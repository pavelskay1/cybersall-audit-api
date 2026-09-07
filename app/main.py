"""FastAPI-сервис для аудита кода через clodex.xyz."""
import json
import asyncio
from pathlib import Path, PurePath
from datetime import datetime, timezone
from fastapi import FastAPI, UploadFile, File, Form, HTTPException, Depends, Header
from fastapi.responses import JSONResponse, HTMLResponse
from .clodex_client import audit_code, MODELS
from .sanitizer import sanitize
from .auth import verify_key, generate_key

app = FastAPI(
    title="Code Audit API",
    description="Аудит кода через AI-пайплайн (clodex.xyz)",
    version="0.2.0",
)

REPORTS_DIR = Path(__file__).parent.parent / "reports"
REPORTS_DIR.mkdir(exist_ok=True)


@app.get("/", response_class=HTMLResponse)
async def index():
    models_html = "".join(
        f'<option value="{k}">{v["label"]}</option>' for k, v in MODELS.items()
    )
    return f"""<!DOCTYPE html>
<html lang="ru">
<head><meta charset="utf-8"><title>Code Audit API</title>
<style>
  body {{ font-family: system-ui; max-width: 800px; margin: 40px auto; padding: 0 20px; }}
  h1 {{ color: #333; }}
  textarea {{ width: 100%; height: 300px; font-family: monospace; font-size: 13px; }}
  select, input[type=text] {{ width: 100%; padding: 8px; margin: 8px 0; }}
  button {{ background: #2563eb; color: white; border: none; padding: 12px 24px;
           border-radius: 6px; cursor: pointer; font-size: 15px; margin-top: 12px; }}
  button:hover {{ background: #1d4ed8; }}
  #result {{ white-space: pre-wrap; background: #f5f5f5; padding: 16px; border-radius: 8px;
            margin-top: 20px; font-size: 13px; max-height: 600px; overflow-y: auto; }}
  .meta {{ color: #666; font-size: 12px; margin-top: 4px; }}
</style>
</head>
<body>
<h1>🔍 Code Audit API</h1>
<p>Требуется API-ключ (X-API-Key заголовок).</p>

<label>API-ключ:</label>
<input type="text" id="apikey" placeholder="Ваш API-ключ">

<label>Модель:</label>
<select id="model">{models_html}</select>

<label>Код:</label>
<textarea id="code" placeholder="Вставьте код сюда..."></textarea>

<button onclick="doAudit()">Аудитировать</button>
<div id="result"></div>

<script>
async function doAudit() {{
  const code = document.getElementById('code').value;
  const model = document.getElementById('model').value;
  const apikey = document.getElementById('apikey').value;
  const result = document.getElementById('result');
  if (!apikey) {{ result.innerHTML = '❌ Введите API-ключ'; return; }}
  result.innerHTML = '⏳ Аудит через ' + model + '...';
  try {{
    const fd = new FormData();
    fd.append('code', code);
    fd.append('model', model);
    const r = await fetch('/api/audit', {{ method: 'POST', headers: {{ 'X-API-Key': apikey }}, body: fd }});
    const data = await r.json();
    if (data.error || data.detail) {{ result.innerHTML = '❌ ' + (data.error || data.detail); }}
    else {{ result.innerHTML = '<div class="meta">Модель: ' + data.model +
      ' | Баланс: ' + (data.balance_remaining||'?') + ' | Токены: ' + (data.prompt_tokens||0) + '/' + (data.completion_tokens||0) +
      '</div><pre>' + data.report + '</pre>'; }}
  }} catch(e) {{ result.innerHTML = '❌ ' + e.message; }}
}}
</script>
</body></html>"""


@app.post("/api/audit")
async def api_audit(
    code: str = Form(...),
    model: str = Form("claude-opus-5"),
    question: str = Form(None),
    client: dict = Depends(verify_key),
):
    if not code.strip():
        raise HTTPException(400, "Код пустой")
    try:
        result = await asyncio.to_thread(audit_code, code, model, question)
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)
    report_name = f"report_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}_{model}.txt"
    report_path = REPORTS_DIR / report_name
    report_path.write_text(result["text"], encoding="utf-8")
    return {
        "report": result["text"],
        "model": model,
        "prompt_tokens": result["usage"].get("prompt_tokens") or result["usage"].get("input_tokens", 0),
        "completion_tokens": result["usage"].get("completion_tokens") or result["usage"].get("output_tokens", 0),
        "balance_remaining": client.get("remaining"),
        "saved_to": str(report_path),
    }


@app.post("/api/audit/file")
async def api_audit_file(
    file: UploadFile = File(...),
    model: str = Form("claude-opus-5"),
    question: str = Form(None),
    client: dict = Depends(verify_key),
):
    import re
    safe_name = re.sub(r'[^A-Za-z0-9._-]', '_', PurePath(file.filename).name)[:100] or "upload"
    content = await file.read()
    if len(content) > 200_000:
        raise HTTPException(413, "Файл слишком большой (макс 200 КБ)")
    code = content.decode("utf-8", errors="replace")
    try:
        result = await asyncio.to_thread(audit_code, code, model, question)
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)
    report_name = f"report_{safe_name}_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.txt"
    report_path = REPORTS_DIR / report_name
    report_path.write_text(result["text"], encoding="utf-8")
    return {
        "report": result["text"],
        "model": model,
        "prompt_tokens": result["usage"].get("prompt_tokens") or result["usage"].get("input_tokens", 0),
        "completion_tokens": result["usage"].get("completion_tokens") or result["usage"].get("output_tokens", 0),
        "balance_remaining": client.get("remaining"),
        "saved_to": str(report_path),
    }


@app.post("/api/audit/ensemble")
async def api_audit_ensemble(
    code: str = Form(...),
    question: str = Form(None),
    client: dict = Depends(verify_key),
):
    from .orchestrator import audit_full
    if not code.strip():
        raise HTTPException(400, "Код пустой")
    try:
        result = await asyncio.to_thread(audit_full, code, question)
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)
    report_name = f"ensemble_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.txt"
    report_path = REPORTS_DIR / report_name
    report_path.write_text(result["report"], encoding="utf-8")
    return {
        "report": result["report"],
        "quality_ok": result["quality_ok"],
        "blocks": result["blocks"],
        "elapsed_sec": result["elapsed_sec"],
        "balance_remaining": client.get("remaining"),
    }


@app.get("/api/models")
async def list_models(client: dict = Depends(verify_key)):
    return {"models": {k: v["label"] for k, v in MODELS.items()}}


@app.post("/api/auth/create")
async def create_key(plan: str = "free"):
    """Создать API-ключ (только для админа)."""
    key = generate_key(plan)
    return {"api_key": key, "plan": plan}


@app.get("/api/auth/balance")
async def balance(client: dict = Depends(verify_key)):
    return {"plan": client["plan"], "remaining": client.get("remaining"), "limit": client.get("limit")}
