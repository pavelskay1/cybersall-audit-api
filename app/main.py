"""FastAPI-сервис для аудита кода через clodex.xyz.

v0.4: добавлен автоматический чанкинг большого кода + SSE таймер.
"""
import re
import uuid
import json
import asyncio
from pathlib import Path, PurePath
from datetime import datetime, timezone
from fastapi import FastAPI, UploadFile, File, Form, HTTPException, Depends, Header, Request
from fastapi.responses import JSONResponse, HTMLResponse, StreamingResponse
from .clodex_client import audit_code, MODELS
from .sanitizer import sanitize
from .auth import verify_key, generate_key
from .chunker import split_code, estimate_time

app = FastAPI(
    title="Code Audit API",
    description="Аудит кода через AI-пайплайн (clodex.xyz)",
    version="0.4.0",
)

REPORTS_DIR = Path(__file__).parent.parent / "reports"
REPORTS_DIR.mkdir(exist_ok=True)

MAX_CODE_LEN = 500_000  # увеличен до 500 КБ — чанкер разобьёт
MAX_QUESTION_LEN = 4_000


def safe_filename(raw: str, max_len: int = 100) -> str:
    name = PurePath(raw).name
    name = re.sub(r"[^A-Za-z0-9._-]", "_", name)
    return name[:max_len] or "upload"


def check_code(code: str):
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
<head><meta charset="utf-8"><title>CodeAudit AI</title>
<style>
  *{{margin:0;padding:0;box-sizing:border-box}}
  body{{font-family:system-ui,-apple-system,sans-serif;background:#f8fafc;color:#1a1a1a}}
  .container{{max-width:900px;margin:0 auto;padding:0 20px}}
  .hero{{background:linear-gradient(135deg,#1e3a5f,#0d1b2a);color:#fff;padding:60px 0;text-align:center}}
  .hero h1{{font-size:2rem;margin-bottom:15px}}
  .hero p{{font-size:1.1rem;opacity:.9;max-width:600px;margin:0 auto 20px}}
  .badge{{display:inline-block;background:#3b82f6;padding:6px 16px;border-radius:20px;font-size:.9rem}}
  .features{{padding:40px 0}}
  .features h2{{text-align:center;margin-bottom:30px;font-size:1.5rem}}
  .features-grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(250px,1fr));gap:20px}}
  .feature{{background:#fff;padding:25px;border-radius:10px;box-shadow:0 2px 8px rgba(0,0,0,.05)}}
  .feature h3{{color:#1e3a5f;margin-bottom:10px;font-size:1rem}}
  .audit-section{{padding:40px 0;background:#fff}}
  .audit-section h2{{text-align:center;margin-bottom:20px;font-size:1.5rem}}
  .audit-form{{max-width:700px;margin:0 auto}}
  .form-group{{margin-bottom:15px}}
  .form-group label{{display:block;font-weight:600;margin-bottom:5px;color:#374151}}
  .form-group input,.form-group select,.form-group textarea{{width:100%;padding:10px 12px;border:1px solid #d1d5db;border-radius:6px;font-size:14px}}
  .form-group textarea{{height:200px;font-family:'Courier New',monospace;font-size:13px;resize:vertical}}
  .form-row{{display:flex;gap:10px}}
  .form-row .form-group{{flex:1}}
  .btn{{background:#3b82f6;color:#fff;border:none;padding:12px 30px;border-radius:6px;font-size:1rem;cursor:pointer;width:100%}}
  .btn:hover{{background:#2563eb}}
  .btn:disabled{{background:#9ca3af;cursor:not-allowed}}
  #result{{margin-top:20px;padding:20px;background:#f1f5f9;border-radius:8px;white-space:pre-wrap;font-size:13px;font-family:'Courier New',monospace;display:none;max-height:500px;overflow-y:auto}}
  .meta{{color:#666;font-size:12px;margin-bottom:10px;padding-bottom:10px;border-bottom:1px solid #e2e8f0}}
  .hint{{background:#eff6ff;border:1px solid #bfdbfe;padding:12px;border-radius:6px;margin-bottom:15px;font-size:13px;color:#1e40af}}
  .hint code{{background:#dbeafe;padding:2px 6px;border-radius:3px}}
  .progress{{display:none;margin-top:15px;background:#f1f5f9;border-radius:8px;padding:20px;text-align:center}}
  .progress-bar{{height:6px;background:#e2e8f0;border-radius:3px;margin:10px 0;overflow:hidden}}
  .progress-fill{{height:100%;background:#3b82f6;border-radius:3px;transition:width .3s;width:0}}
  .timer{{font-size:1.5rem;font-weight:bold;color:#1e3a5f;margin:10px 0}}
  .timer small{{font-size:.8rem;color:#666;font-weight:normal}}
  .size-info{{font-size:12px;color:#666;margin-top:4px}}
  .size-warn{{color:#b91c1c;font-size:12px;margin-top:4px;display:none}}
  .footer{{background:#0d1b2a;color:#fff;padding:30px 0;text-align:center;font-size:.9rem}}
</style>
</head>
<body>
<section class="hero"><div class="container">
<h1>CodeAudit AI</h1>
<p>Аудит кода через 4 модели AI. Находим баги, уязвимости и логические ошибки.</p>
<span class="badge">Claude + GPT + Kimi + DeepSeek</span>
</div></section>
<section class="features"><div class="container">
<h2>Как это работает</h2>
<div class="features-grid">
<div class="feature"><h3>1. Вставляете код</h3><p>Python, C++, JavaScript. Код автоматически санитизируется.</p></div>
<div class="feature"><h3>2. AI анализирует</h3><p>4 модели проверяют параллельно. Большой код разбивается автоматически.</p></div>
<div class="feature"><h3>3. Получаете отчёт</h3><p>P0 (критические), P1 (важные), P2 (мелочи). С кодом-фиксами.</p></div>
</div></div></section>
<section class="audit-section"><div class="container">
<h2>Попробуйте бесплатно</h2>
<div class="hint"><strong>API-ключ:</strong> <code>n_C0T_V14g6YwF6WHI5AnrCvJgUd4XA_TPhno_Q6ILU</code> <small>(30 запросов/день)</small></div>
<div class="audit-form">
<div class="form-group"><label>API-ключ</label><input type="text" id="apikey" value="n_C0T_V14g6YwF6WHI5AnrCvJgUd4XA_TPhno_Q6ILU"></div>
<div class="form-row">
<div class="form-group"><label>Модель</label><select id="model">
<option value="glm-5.2">GLM-5.2 (быстро)</option>
<option value="claude-opus-5">Claude Opus 5</option>
<option value="gpt-6-astra">GPT-6-Astra</option>
<option value="deepseek-v4-pro">DeepSeek V4 Pro</option>
<option value="kimi-k3">Kimi K3</option>
</select></div>
<div class="form-group"><label>Режим</label><select id="mode">
<option value="single">Одна модель</option>
<option value="ensemble">Кросс-валидация (4 модели)</option>
</select></div>
</div>
<div class="form-group">
<label>Код для аудита</label>
<textarea id="code" placeholder="Вставьте код сюда...">def divide(a, b):
    return a / b

def read_file(path):
    f = open(path)
    data = f.read()
    return data</textarea>
<div class="size-info" id="sizeInfo"></div>
<div class="size-warn" id="sizeWarn">Код автоматически разобьётся на части.</div>
</div>
<button class="btn" onclick="doAudit()" id="auditBtn">Аудитировать</button>
<div class="progress" id="progress">
<div class="timer" id="timer">~15 сек <small>ожидается</small></div>
<div class="progress-bar"><div class="progress-fill" id="progressFill"></div></div>
<div id="progressText" style="font-size:13px;color:#666"></div>
</div>
<div id="result"></div>
</div></div></section>
<section class="footer"><div class="container"><p>CodeAudit AI v0.4</p></div></section>
<script>
const MAX_CODE=500000;
const codeEl=document.getElementById('code');
const sizeInfo=document.getElementById('sizeInfo');
const sizeWarn=document.getElementById('sizeWarn');
function updateSize(){{const l=codeEl.value.length;sizeInfo.textContent=l.toLocaleString()+' символов';sizeWarn.style.display=l>MAX_CODE?'block':'none'}}
codeEl.addEventListener('input',updateSize);updateSize();

async function doAudit(){{
  const code=codeEl.value;
  const model=document.getElementById('model').value;
  const mode=document.getElementById('mode').value;
  const apikey=document.getElementById('apikey').value;
  const result=document.getElementById('result');
  const btn=document.getElementById('auditBtn');
  const progress=document.getElementById('progress');
  const timer=document.getElementById('timer');
  const progressFill=document.getElementById('progressFill');
  const progressText=document.getElementById('progressText');

  if(!apikey){{result.style.display='block';result.textContent='Введите API-ключ';return}}
  if(!code.trim()){{result.style.display='block';result.textContent='Вставьте код';return}}

  btn.disabled=true;btn.textContent='Аудит...';
  result.style.display='none';
  progress.style.display='block';

  const blocks=Math.ceil(code.length/15000);
  const estSingle=blocks*15;
  const estEnsemble=blocks*60;
  const est=mode==='ensemble'?estEnsemble:estSingle;

  let elapsed=0;
  const timerInterval=setInterval(()=>{{
    elapsed++;
    const remain=Math.max(0,est-elapsed);
    const pct=Math.min(100,Math.round((elapsed/est)*100));
    progressFill.style.width=pct+'%';
    timer.textContent='~'+remain+' сек';
    if(blocks>1)progressText.textContent='Блок '+Math.min(blocks,Math.ceil(elapsed/15))+'/'+blocks;
  }},1000);

  const url=mode==='ensemble'?'/api/audit/ensemble':'/api/audit';
  const fd=new FormData();fd.append('code',code);
  if(mode==='single')fd.append('model',model);

  try{{
    const r=await fetch(url,{{method:'POST',headers:{{'X-API-Key':apikey}},body:fd}});
    const data=await r.json();
    clearInterval(timerInterval);progressFill.style.width='100%';
    timer.textContent='Готово! ('+elapsed+' сек)';

    if(data.error||data.detail){{
      result.style.display='block';result.textContent='Ошибка: '+(data.error||data.detail);
    }}else{{
      let metaText='';
      if(mode==='ensemble'){{
        metaText='Блоков: '+(data.blocks||'?')+' | Время: '+(data.elapsed_sec||'?')+' сек | Баланс: '+(data.balance_remaining||'?');
      }}else{{
        metaText='Модель: '+data.model+' | Баланс: '+(data.balance_remaining||'?')+' | Токены: '+(data.prompt_tokens||0)+'/' +(data.completion_tokens||0);
      }}
      const meta=document.createElement('div');meta.className='meta';meta.textContent=metaText;
      const pre=document.createElement('pre');pre.style.whiteSpace='pre-wrap';pre.style.fontFamily="'Courier New',monospace";pre.style.fontSize='13px';pre.textContent=data.report;
      result.style.display='block';result.replaceChildren(meta,pre);
    }}
  }}catch(e){{
    clearInterval(timerInterval);result.style.display='block';result.textContent='Ошибка: '+e.message;
  }}finally{{btn.disabled=false;btn.textContent='Аудитировать'}}
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
            raise HTTPException(413, "Question слишком длинный")
    
    # Разбиваем большой код на части
    blocks = split_code(code)
    if len(blocks) == 1:
        # Обычный запрос
        try:
            result = await asyncio.to_thread(audit_code, code, model, question)
        except Exception as e:
            return JSONResponse({"error": "Ошибка обработки"}, status_code=500)
        report_id = uuid.uuid4().hex[:12]
        report_path = REPORTS_DIR / f"report_{report_id}_{model}.txt"
        report_path.write_text(result["text"], encoding="utf-8")
        return {
            "report": result["text"],
            "model": model,
            "prompt_tokens": result["usage"].get("prompt_tokens") or result["usage"].get("input_tokens", 0),
            "completion_tokens": result["usage"].get("completion_tokens") or result["usage"].get("output_tokens", 0),
            "balance_remaining": client.get("remaining"),
            "blocks": 1,
        }
    
    # Большие запросы — обработка по блокам
    all_reports = []
    for i, block in enumerate(blocks):
        try:
            result = await asyncio.to_thread(audit_code, block["code"], model, question)
            all_reports.append(f"## Блок {i+1}/{len(blocks)}: {block['name']}\n\n{result['text']}")
        except Exception as e:
            all_reports.append(f"## Блок {i+1}/{len(blocks)}: {block['name']}\n\nОшибка: {e}")
    
    final_report = "\n\n---\n\n".join(all_reports)
    report_id = uuid.uuid4().hex[:12]
    report_path = REPORTS_DIR / f"report_{report_id}_{model}.txt"
    report_path.write_text(final_report, encoding="utf-8")
    return {
        "report": final_report,
        "model": model,
        "prompt_tokens": 0,
        "completion_tokens": 0,
        "balance_remaining": client.get("remaining"),
        "blocks": len(blocks),
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
    
    blocks = split_code(code)
    if len(blocks) == 1:
        try:
            result = await asyncio.to_thread(audit_code, code, model, question)
        except Exception as e:
            return JSONResponse({"error": "Ошибка обработки"}, status_code=500)
        report_id = uuid.uuid4().hex[:12]
        report_path = REPORTS_DIR / f"report_{fname}_{report_id}.txt"
        report_path.write_text(result["text"], encoding="utf-8")
        return {
            "report": result["text"],
            "model": model,
            "prompt_tokens": result["usage"].get("prompt_tokens") or result["usage"].get("input_tokens", 0),
            "completion_tokens": result["usage"].get("completion_tokens") or result["usage"].get("output_tokens", 0),
            "balance_remaining": client.get("remaining"),
            "blocks": 1,
        }
    
    all_reports = []
    for i, block in enumerate(blocks):
        try:
            result = await asyncio.to_thread(audit_code, block["code"], model, question)
            all_reports.append(f"## Блок {i+1}/{len(blocks)}: {block['name']}\n\n{result['text']}")
        except Exception as e:
            all_reports.append(f"## Блок {i+1}/{len(blocks)}: {block['name']}\n\nОшибка: {e}")
    
    final_report = "\n\n---\n\n".join(all_reports)
    report_id = uuid.uuid4().hex[:12]
    report_path = REPORTS_DIR / f"report_{fname}_{report_id}.txt"
    report_path.write_text(final_report, encoding="utf-8")
    return {
        "report": final_report,
        "model": model,
        "prompt_tokens": 0,
        "completion_tokens": 0,
        "balance_remaining": client.get("remaining"),
        "blocks": len(blocks),
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
        return JSONResponse({"error": "Ошибка обработки"}, status_code=500)
    report_id = uuid.uuid4().hex[:12]
    report_path = REPORTS_DIR / f"ensemble_{report_id}.txt"
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
