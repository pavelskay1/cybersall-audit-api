"""FastAPI-сервис для аудита кода через AI-пайплайн.

v0.5: unified splitter (orchestrator.split_into_blocks), PDF download, report metadata.
"""
import re
import html as html_mod
import uuid
import json
import asyncio
from pathlib import Path, PurePath
from datetime import datetime, timezone
from fastapi import FastAPI, UploadFile, File, Form, HTTPException, Depends, Header, Request
from fastapi.responses import JSONResponse, HTMLResponse, StreamingResponse, FileResponse
from .clodex_client import audit_code, MODELS
from .sanitizer import sanitize
from .auth import verify_key, generate_key, check_create_allowed
from .sandbox import static_analyze, ban_client
from .converter import convert_python_to_cpp
from .email_sender import send_report
from .pdf_report import generate_audit_report
from .orchestrator import split_into_blocks, estimate_audit_minutes

app = FastAPI(
    title="Cybersall AI Agent",
    description="AI-аудит кода через ансамбль LLM",
    version="0.5.0",
)

REPORTS_DIR = Path(__file__).parent.parent / "reports"
REPORTS_DIR.mkdir(exist_ok=True)

MAX_CODE_LEN = 500_000
MAX_QUESTION_LEN = 4_000

# Максимум одновременных ансамблевых аудитов (каждый = 4-7 мин LLM)
ENSEMBLE_SEMAPHORE = asyncio.Semaphore(2)
ENSEMBLE_IP_LIMITS = {}  # ip -> {"date": str, "count": int}
ENSEMBLE_PER_IP_PER_DAY = 5


def safe_filename(raw: str, max_len: int = 100) -> str:
    name = PurePath(raw).name
    name = re.sub(r"[^A-Za-z0-9._-]", "_", name)
    return name[:max_len] or "upload"


def check_code(code: str, client_key: str = None):
    """Валидация входного кода для аудита."""
    if not code.strip():
        raise HTTPException(400, "Код пустой")
    if len(code) > MAX_CODE_LEN:
        raise HTTPException(413, f"Код слишком большой (макс {MAX_CODE_LEN:,} символов)")


def save_report(report_id: str, report_text: str, model: str, elapsed: float = 0,
                blocks: int = 1, question: str = None, report_type: str = "audit"):
    """Сохраняет отчёт + метаданные в JSON для PDF/email."""
    meta = {
        "report_id": report_id,
        "type": report_type,
        "model": model,
        "elapsed": elapsed,
        "blocks": blocks,
        "question": question,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "report_len": len(report_text),
    }
    (REPORTS_DIR / f"{report_id}_meta.json").write_text(json.dumps(meta, ensure_ascii=False))
    (REPORTS_DIR / f"{report_id}_report.txt").write_text(report_text, encoding="utf-8")
    return meta


@app.get("/")
async def index():
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

    blocks = await asyncio.to_thread(split_into_blocks, code)

    if len(blocks) == 1:
        try:
            result = await asyncio.to_thread(audit_code, code, model, question)
        except Exception as e:
            return JSONResponse({"error": "Ошибка обработки"}, status_code=500)
        report_id = uuid.uuid4().hex[:12]
        save_report(report_id, result["text"], model, question=question)
        return {
            "report": result["text"],
            "report_id": report_id,
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
    save_report(report_id, final_report, model, question=question)
    return {
        "report": final_report,
        "report_id": report_id,
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

    blocks = await asyncio.to_thread(split_into_blocks, code)

    if len(blocks) == 1:
        try:
            result = await asyncio.to_thread(audit_code, code, model, question)
        except Exception as e:
            return JSONResponse({"error": "Ошибка обработки"}, status_code=500)
        report_id = uuid.uuid4().hex[:12]
        save_report(report_id, result["text"], model, question=question)
        return {
            "report": result["text"],
            "report_id": report_id,
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
    save_report(report_id, final_report, model, question=question)
    return {
        "report": final_report,
        "report_id": report_id,
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
    request: Request = None,
    client: dict = Depends(verify_key),
):
    from .orchestrator import audit_full
    check_code(code, client.get("key"))
    if question:
        question = sanitize(question)
    # Per-IP лимит на ансамбль (5/сутки) — защита от халявщиков и abuse
    if request and request.client:
        client_ip = request.headers.get("x-real-ip") or request.client.host
    else:
        client_ip = "?"
    today = datetime.now(timezone.utc).date().isoformat()
    entry = ENSEMBLE_IP_LIMITS.setdefault(client_ip, {})
    if entry.get("date") != today:
        entry.clear()
        entry["date"] = today
        entry["count"] = 0
    if entry["count"] >= ENSEMBLE_PER_IP_PER_DAY:
        raise HTTPException(429, f"Слишком много ансамблевых аудитов с этого IP (макс {ENSEMBLE_PER_IP_PER_DAY}/сутки)")
    entry["count"] += 1

    async with ENSEMBLE_SEMAPHORE:
        try:
            result = await asyncio.to_thread(audit_full, code, question)
        except Exception as e:
            return JSONResponse({"error": "Ошибка обработки"}, status_code=500)
    report_id = uuid.uuid4().hex[:12]
    save_report(report_id, result["report"], "ensemble",
                elapsed=result["elapsed_sec"], blocks=result["blocks"], question=question)
    return {
        "report": result["report"],
        "report_id": report_id,
        "quality_ok": result["quality_ok"],
        "blocks": result["blocks"],
        "elapsed_sec": result["elapsed_sec"],
        "balance_remaining": client.get("remaining"),
    }


@app.get("/api/report/{report_id}/pdf")
async def download_pdf(report_id: str, client: dict = Depends(verify_key)):
    """Скачать PDF-отчёт по report_id."""
    report_path = REPORTS_DIR / f"{report_id}_report.txt"
    meta_path = REPORTS_DIR / f"{report_id}_meta.json"
    if not report_path.exists():
        raise HTTPException(404, "Отчёт не найден")
    report_text = report_path.read_text(encoding="utf-8")
    meta = json.loads(meta_path.read_text()) if meta_path.exists() else {}
    pdf_bytes = generate_audit_report(
        report_text,
        model=meta.get("model", "unknown"),
        elapsed=meta.get("elapsed", 0),
        blocks=meta.get("blocks", 1),
    )
    return StreamingResponse(
        iter([pdf_bytes]),
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="cybersall_report_{report_id}.pdf"'},
    )


@app.get("/api/report/{report_id}/meta")
async def report_meta(report_id: str, client: dict = Depends(verify_key)):
    """Получить метаданные отчёта."""
    meta_path = REPORTS_DIR / f"{report_id}_meta.json"
    if not meta_path.exists():
        raise HTTPException(404, "Отчёт не найден")
    return json.loads(meta_path.read_text())


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
    save_report(report_id, result["cpp"], "python->cpp", elapsed=result["elapsed"],
                question=question, report_type="convert")
    return {
        "cpp": result["cpp"],
        "report_id": report_id,
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

    report_id = uuid.uuid4().hex[:12]
    save_report(report_id, report, model, elapsed=elapsed, blocks=blocks, question=question)

    try:
        pdf_bytes = generate_audit_report(report, model, elapsed, blocks)
    except Exception as e:
        pdf_bytes = None

    subject = f"[Cybersall AI] Отчёт аудита — {datetime.now(timezone.utc).strftime('%d.%m.%Y')}"
    body = f"<h2>Cybersall AI Agent — Отчёт аудита</h2><p>Режим: {model} | Время: {elapsed}с | Блоков: {blocks}</p><hr><pre>{html_mod.escape(report[:5000])}</pre>"
    sent = send_report(email, subject, body, pdf_bytes, "cybersall_audit_report.pdf")

    return {
        "sent": sent,
        "report_id": report_id,
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

    report_id = uuid.uuid4().hex[:12]
    save_report(report_id, result["cpp"], "python->cpp", elapsed=result["elapsed"],
                question=question, report_type="convert")

    try:
        pdf_bytes = generate_audit_report(result["cpp"], "python->c++", result["elapsed"], 1)
    except Exception:
        pdf_bytes = None

    subject = f"[Cybersall AI] Python -> C++ — {datetime.now(timezone.utc).strftime('%d.%m.%Y')}"
    body = f"<h2>Cybersall AI Agent — Конвертация Python -> C++</h2><p>Время: {result['elapsed']}с</p><hr><pre>{html_mod.escape(result['cpp'][:5000])}</pre>"
    sent = send_report(email, subject, body, pdf_bytes, "cybersall_convert_report.pdf")

    return {
        "sent": sent,
        "report_id": report_id,
        "email": email,
        "cpp_preview": result["cpp"][:500],
        "elapsed": result["elapsed"],
        "stages": result["stages"],
        "balance_remaining": client.get("remaining"),
    }


@app.post("/api/auth/create")
async def create_key(plan: str = "free", x_admin_key: str | None = Header(None), request: Request = None):
    """Создание ключа: free — с лимитом на IP; pro/enterprise — только с X-Admin-Key."""
    if request and request.client:
        client_ip = request.headers.get("x-real-ip") or request.client.host
    else:
        client_ip = "?"
    check_create_allowed(plan, client_ip, x_admin_key)
    key = generate_key(plan)
    return {"api_key": key, "plan": plan}


@app.get("/api/auth/balance")
async def balance(client: dict = Depends(verify_key)):
    return {"plan": client["plan"], "remaining": client.get("remaining"), "limit": client.get("limit")}
