"""FastAPI-сервис для аудита кода через clodex.xyz.

v0.4: добавлен автоматический чанкинг большого кода + SSE таймер.
"""
import re
import html as html_mod
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
from .sandbox import static_analyze, ban_client
from .converter import convert_python_to_cpp
from .email_sender import send_report
from .pdf_report import generate_audit_report
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


def check_code(code: str, client_key: str = None):
    """Валидация входного кода для аудита.

    Код аудита НЕ исполняется на сервере: он санитизируется и уходит в LLM.
    Запрещённые паттерны (import os, eval и т.п.) — это обычный материал для аудита,
    поэтому статический анализ и бан здесь НЕ применяются.
    Бан и sandbox-изоляция остаются только при реальном исполнении кода
    (см. sandbox.run_in_sandbox).
    """
    if not code.strip():
        raise HTTPException(400, "Код пустой")
    if len(code) > MAX_CODE_LEN:
        raise HTTPException(413, f"Код слишком большой (макс {MAX_CODE_LEN:,} символов)")


@app.get("/")
async def index():
    """Редирект на лендинг (nginx)."""
    from fastapi.responses import RedirectResponse
    return RedirectResponse(url="/landing/index.html", status_code=302)


@app.post("/api/audit")
async def api_audit(
    code: str = Form(...),
    model: str = Form("claude-opus-5"),
    question: str = Form(None),
    client: dict = Depends(verify_key),
):
    check_code(code, client.get("key"))
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
    check_code(code, client.get("key"))
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



@app.post("/api/convert")
async def api_convert(
    code: str = Form(...),
    question: str = Form(None),
    client: dict = Depends(verify_key),
):
    check_code(code, client.get("key"))
    if question:
        question = sanitize(question)
    try:
        result = await asyncio.to_thread(convert_python_to_cpp, code, question)
    except Exception as e:
        return JSONResponse({"error": "Ошибка конвертации"}, status_code=500)
    report_id = uuid.uuid4().hex[:12]
    report_path = REPORTS_DIR / f"convert_{report_id}.cpp"
    report_path.write_text(result["cpp"], encoding="utf-8")
    return {
        "cpp": result["cpp"],
        "stages": result["stages"],
        "elapsed": result["elapsed"],
        "balance_remaining": client.get("remaining"),
    }


@app.post("/api/audit/email")
async def api_audit_email(
    code: str = Form(...),
    email: str = Form(...),
    model: str = Form("ensemble"),
    question: str = Form(None),
    client: dict = Depends(verify_key),
):
    check_code(code, client.get("key"))
    if question:
        question = sanitize(question)

    if model == "ensemble":
        from .orchestrator import audit_full
        try:
            result = await asyncio.to_thread(audit_full, code, question)
            report = result["report"]
            elapsed = result["elapsed_sec"]
            blocks = result["blocks"]
        except Exception as e:
            return JSONResponse({"error": "Ошибка обработки"}, status_code=500)
    else:
        try:
            result = await asyncio.to_thread(audit_code, code, model, question)
            report = result["text"]
            elapsed = 0
            blocks = 1
        except Exception as e:
            return JSONResponse({"error": "Ошибка обработки"}, status_code=500)

    # Генерация PDF
    try:
        pdf_bytes = generate_audit_report(report, model, elapsed, blocks)
    except Exception as e:
        pdf_bytes = None

    # Отправка email
    subject = f"[Cybersall AI] Отчёт аудита кода — {datetime.now(timezone.utc).strftime('%d.%m.%Y')}"
    body = f"<h2>Cybersall AI Agent — Отчёт аудита</h2><p>Режим: {model} | Время: {elapsed}с | Блоков: {blocks}</p><hr><pre>{html_mod.escape(report[:5000])}</pre>"
    sent = send_report(email, subject, body, pdf_bytes, "cybersall_audit_report.pdf")

    return {
        "sent": sent,
        "email": email,
        "report_preview": report[:500] + "..." if len(report) > 500 else report,
        "elapsed": elapsed,
        "blocks": blocks,
        "balance_remaining": client.get("remaining"),
    }


@app.post("/api/convert/email")
async def api_convert_email(
    code: str = Form(...),
    email: str = Form(...),
    question: str = Form(None),
    client: dict = Depends(verify_key),
):
    check_code(code, client.get("key"))
    if question:
        question = sanitize(question)

    try:
        result = await asyncio.to_thread(convert_python_to_cpp, code, question)
    except Exception as e:
        return JSONResponse({"error": "Ошибка конвертации"}, status_code=500)

    # Генерация PDF с C++ кодом
    try:
        pdf_bytes = generate_audit_report(result["cpp"], "python→c++", result["elapsed"], 1)
    except Exception:
        pdf_bytes = None

    subject = f"[Cybersall AI] Python → C++ конвертация — {datetime.now(timezone.utc).strftime('%d.%m.%Y')}"
    body = f"<h2>Cybersall AI Agent — Конвертация Python → C++</h2><p>Время: {result['elapsed']}с</p><hr><pre>{html_mod.escape(result['cpp'][:5000])}</pre>"
    sent = send_report(email, subject, body, pdf_bytes, "cybersall_convert_report.pdf")

    return {
        "sent": sent,
        "email": email,
        "cpp_preview": result["cpp"][:500],
        "elapsed": result["elapsed"],
        "stages": result["stages"],
        "balance_remaining": client.get("remaining"),
    }

@app.post("/api/auth/create")
async def create_key(plan: str = "free"):
    key = generate_key(plan)
    return {"api_key": key, "plan": plan}


@app.get("/api/auth/balance")
async def balance(client: dict = Depends(verify_key)):
    return {"plan": client["plan"], "remaining": client.get("remaining"), "limit": client.get("limit")}