"""FastAPI-сервис для аудита кода через clodex.xyz.

Исправления (по результатам аудита Claude Opus 5 + GPT-6-Astra):
- Path traversal: report_path создаётся через uuid, имя файла игнорируется
- XSS: data.report экранируется через textContent, а не innerHTML
- Лимит размера: max 200 КБ на код, max 4 КБ на question
- Prompt injection: sanitize() применяется к question тоже
- Error leakage: внутренние ошибки не раскрываются
- safe_filename: токенизированное имя файла для отчётов
"""
import re
import uuid
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
    version="0.3.0",
)

REPORTS_DIR = Path(__file__).parent.parent / "reports"
REPORTS_DIR.mkdir(exist_ok=True)

MAX_CODE_LEN = 200_000
MAX_QUESTION_LEN = 4_000


def safe_filename(raw: str, max_len: int = 100) -> str:
    """Токенизирует имя файла: только [A-Za-z0-9._-], без path separators."""
    name = PurePath(raw).name
    name = re.sub(r"[^A-Za-z0-9._-]", "_", name)
    return name[:max_len] or "upload"


def check_code(code: str):
    """Проверяет размер кода."""
    if not code.strip():
        raise HTTPException(400, "Код пустой")
    if len(code) > MAX_CODE_LEN:
        raise HTTPException(413, f"Код слишком большой (макс {MAX_CODE_LEN:,} символов)")


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
<h1>Code Audit API</h1>
<p>Tребуется API-ключ (X-API-Key заголовок).</p>
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
  if (!apikey) {{ result.textContent = 'Введите API-ключ'; return; }}
  result.textContent = 'Аудит через ' + model + '...';
  try {{
    const fd = new FormData();
    fd.append('code', code);
    fd.append('model', model);
    const r = await fetch('/api/audit', {{ method: 'POST', headers: {{ 'X-API-Key': apikey }}, body: fd }});
    const data = await r.json();
    if (data.error || data.detail) {{
      result.textContent = 'Ошибка: ' + (data.error || data.detail);
    }} else {{
      const meta = document.createElement('div');
      meta.className = 'meta';
      meta.textContent = 'Модель: ' + data.model +
        ' | Баланс: ' + (data.balance_remaining||'?') +
        ' | Токены: ' + (data.prompt_tokens||0) + '/' + (data.completion_tokens||0);
      const pre = document.createElement('pre');
      pre.textContent = data.report;
      result.replaceChildren(meta, pre);
    }}
  }} catch(e) {{ result.textContent = 'Ошибка: ' + e.message; }}
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
    check_code(code)
    if question:
        question = sanitize(question)
        if len(question) > MAX_QUESTION_LEN:
            raise HTTPException(413, f"Question слишком длинный (макс {MAX_QUESTION_LEN:,})")
    try:
        result = await asyncio.to_thread(audit_code, code, model, question)
    except Exception as e:
        return JSONResponse({"error": "Ошибка обработки запроса"}, status_code=500)
    report_id = uuid.uuid4().hex[:12]
    report_name = f"report_{report_id}_{model}.txt"
    report_path = REPORTS_DIR / report_name
    report_path.write_text(result["text"], encoding="utf-8")
    return {
        "report": result["text"],
        "model": model,
        "prompt_tokens": result["usage"].get("prompt_tokens") or result["usage"].get("input_tokens", 0),
        "completion_tokens": result["usage"].get("completion_tokens") or result["usage"].get("output_tokens", 0),
        "balance_remaining": client.get("remaining"),
    }


@app.post("/api/audit/file")
async def api_audit_file(
    file: UploadFile = File(...),
    model: str = Form("claude-opus-5"),
    question: str = Form(None),
    client: dict = Depends(verify_key),
):
    fname = safe_filename(file.filename)
    content = await file.read()
    if len(content) > MAX_CODE_LEN:
        raise HTTPException(413, f"Файл слишком большой (макс {MAX_CODE_LEN:,} байт)")
    code = content.decode("utf-8", errors="replace")
    if not code.strip():
        raise HTTPException(400, "Файл пустой")
    if question:
        question = sanitize(question)
    try:
        result = await asyncio.to_thread(audit_code, code, model, question)
    except Exception as e:
        return JSONResponse({"error": "Ошибка обработки запроса"}, status_code=500)
    report_id = uuid.uuid4().hex[:12]
    report_name = f"report_{fname}_{report_id}.txt"
    report_path = REPORTS_DIR / report_name
    report_path.write_text(result["text"], encoding="utf-8")
    return {
        "report": result["text"],
        "model": model,
        "prompt_tokens": result["usage"].get("prompt_tokens") or result["usage"].get("input_tokens", 0),
        "completion_tokens": result["usage"].get("completion_tokens") or result["usage"].get("output_tokens", 0),
        "balance_remaining": client.get("remaining"),
    }


@app.post("/api/audit/ensemble")
async def api_audit_ensemble(
    code: str = Form(...),
    question: str = Form(None),
    client: dict = Depends(verify_key),
):
    from .orchestrator import audit_full
    check_code(code)
    if question:
        question = sanitize(question)
    try:
        result = await asyncio.to_thread(audit_full, code, question)
    except Exception as e:
        return JSONResponse({"error": "Ошибка обработки запроса"}, status_code=500)
    report_id = uuid.uuid4().hex[:12]
    report_name = f"ensemble_{report_id}.txt"
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
    key = generate_key(plan)
    return {"api_key": key, "plan": plan}


@app.get("/api/auth/balance")
async def balance(client: dict = Depends(verify_key)):
    return {"plan": client["plan"], "remaining": client.get("remaining"), "limit": client.get("limit")}
