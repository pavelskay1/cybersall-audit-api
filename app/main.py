"""FastAPI-сервис для аудита кода через clodex.xyz.

v0.4: добавлен автоматический чанкинг большого кода + SSE таймер.
"""
import re
import hmac
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
from .auth import verify_key, generate_key, check_create_allowed, resolve_partner, get_partner_share
from .sandbox import static_analyze, ban_client, run_in_sandbox
from .harden import harden_question, tripwire_hits
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

EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")


def safe_filename(raw: str, max_len: int = 100) -> str:
    name = PurePath(raw).name
    name = re.sub(r"[^A-Za-z0-9._-]", "_", name)
    name = name.lstrip(".")  # не допускаем dot-файлы и ".."
    return name[:max_len] or "upload"


def _validate_model(model: str, allow_ensemble: bool = False) -> str:
    """Модель — клиентский параметр и попадает в имя файла отчёта.

    Разрешаем только ключи MODELS (и 'ensemble' там, где он поддерживается),
    чтобы исключить path traversal через '../../' в имени файла.
    """
    if allow_ensemble and model == "ensemble":
        return model
    if model not in MODELS:
        raise HTTPException(400, "Недопустимая модель")
    return model


def _validate_email(email: str) -> str:
    email = (email or "").strip()
    if not EMAIL_RE.match(email):
        raise HTTPException(400, "Некорректный email")
    return email


def _write_text(path: Path, content: str) -> None:
    """Синхронная запись — вызывать через asyncio.to_thread."""
    path.write_text(content, encoding="utf-8")


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


def clean_question(question: str) -> str:
    """Санитизация секретов + экранирование промт-инъекции + лимит длины."""
    if not question:
        return question
    q = harden_question(sanitize(question))
    if len(q) > MAX_QUESTION_LEN:
        raise HTTPException(413, "Question слишком длинный")
    return q


# --- Поведенческий бан при промт-инъекции (2026-09-23) ---
INJ_ATTEMPT_LIMIT = 3           # до бана: N срабатываний трипваира с одного ключа
_inj_attempts: dict = {}        # hash ключа -> число подтверждённых попыток


def count_injection_attempt(client_key: str) -> bool:
    """Регистрирует инъекционную попытку; возвращает True, если пора банить."""
    if not client_key:
        return False
    import hashlib
    kh = hashlib.sha256(client_key.encode()).hexdigest()
    n = _inj_attempts.get(kh, 0) + 1
    if n >= INJ_ATTEMPT_LIMIT:
        _inj_attempts[kh] = 0
        ban_client(client_key, "Множественные попытки промт-инъекции")
        return True
    _inj_attempts[kh] = n
    print(f"[SECURITY] Inj-попытка #{n}/{INJ_ATTEMPT_LIMIT} (key {kh[:8]}...)")
    return False


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
    model = _validate_model(model)
    question = clean_question(question)

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
        await asyncio.to_thread(_write_text, report_path, result["text"])
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
        except Exception:
            all_reports.append(f"## Блок {i+1}/{len(blocks)}: {block['name']}\n\nОшибка обработки блока")

    final_report = "\n\n---\n\n".join(all_reports)
    report_id = uuid.uuid4().hex[:12]
    report_path = REPORTS_DIR / f"report_{report_id}_{model}.txt"
    await asyncio.to_thread(_write_text, report_path, final_report)
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
    model = _validate_model(model)
    content = await file.read()
    if len(content) > MAX_CODE_LEN:
        raise HTTPException(413, f"Файл слишком большой (макс {MAX_CODE_LEN:,} байт)")
    code = content.decode("utf-8", errors="replace")
    if not code.strip():
        raise HTTPException(400, "Файл пустой")
    if question:
        question = clean_question(question)

    blocks = split_code(code)
    if len(blocks) == 1:
        try:
            result = await asyncio.to_thread(audit_code, code, model, question)
        except Exception as e:
            return JSONResponse({"error": "Ошибка обработки"}, status_code=500)
        report_id = uuid.uuid4().hex[:12]
        report_path = REPORTS_DIR / f"report_{fname}_{report_id}.txt"
        await asyncio.to_thread(_write_text, report_path, result["text"])
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
        except Exception:
            all_reports.append(f"## Блок {i+1}/{len(blocks)}: {block['name']}\n\nОшибка обработки блока")

    final_report = "\n\n---\n\n".join(all_reports)
    report_id = uuid.uuid4().hex[:12]
    report_path = REPORTS_DIR / f"report_{fname}_{report_id}.txt"
    await asyncio.to_thread(_write_text, report_path, final_report)
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
    question = clean_question(question)
    try:
        result = await asyncio.to_thread(audit_full, code, question)
    except Exception as e:
        return JSONResponse({"error": "Ошибка обработки"}, status_code=500)

    # Трипваир инъекции: если дирижёр saw, что модель исполняет инструкции из кода
    issues = str(result.get("issues") or "")
    if tripwire_hits(issues):
        if count_injection_attempt(client.get("key")):
            raise HTTPException(403, "Ключ заблокирован за инъекционные попытки")

    report_id = uuid.uuid4().hex[:12]
    report_path = REPORTS_DIR / f"ensemble_{report_id}.txt"
    await asyncio.to_thread(_write_text, report_path, result.get("report") or "")
    if result.get("template_code"):
        # .txt, а не .py: файл приходит от LLM и не должен быть исполняемым
        tmpl_path = REPORTS_DIR / f"ensemble_{report_id}.template.txt"
        await asyncio.to_thread(_write_text, tmpl_path, result["template_code"])
    return {
        "report": result.get("report") or "",
        "template_code": result.get("template_code") or "",
        "quality_ok": result.get("quality_ok", False),
        "blocks": result.get("blocks", 1),
        "elapsed_sec": result.get("elapsed_sec", 0),
        "balance_remaining": client.get("remaining"),
    }


@app.post("/api/run")
async def api_run(
    code: str = Form(...),
    client: dict = Depends(verify_key),
):
    """Исполняет код в Docker-песочнице (gVisor runsc, без сети, read-only).

    Изоляция: statический анализ -> Docker (--network=none, honeypot-декой) ->
    динамический анализ -> поведенческий бан. Аудит при этом НЕ исполняется.
    """
    check_code(code, client.get("key"))
    if len(code) > 50_000:
        raise HTTPException(
            status_code=413,
            detail="Код слишком большой для песочницы (макс 50 000)",
        )

    result = await asyncio.to_thread(run_in_sandbox, code, client.get("key"))
    return {**result, "balance_remaining": client.get("remaining")}


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
        question = clean_question(question)
    try:
        result = await asyncio.to_thread(convert_python_to_cpp, code, question)
    except Exception as e:
        return JSONResponse({"error": "Ошибка конвертации"}, status_code=500)
    report_id = uuid.uuid4().hex[:12]
    report_path = REPORTS_DIR / f"convert_{report_id}.cpp"
    await asyncio.to_thread(_write_text, report_path, result["cpp"])
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
    model = _validate_model(model, allow_ensemble=True)
    email = _validate_email(email)
    if question:
        question = clean_question(question)

    if model == "ensemble":
        from .orchestrator import audit_full
        try:
            result = await asyncio.to_thread(audit_full, code, question)
            report = result.get("report") or ""
            elapsed = result.get("elapsed_sec", 0)
            blocks = result.get("blocks", 1)
        except Exception as e:
            return JSONResponse({"error": "Ошибка обработки"}, status_code=500)

        # Трипваир инъекции — тот же контроль, что и в /api/audit/ensemble
        issues = str(result.get("issues") or "")
        if tripwire_hits(issues):
            if count_injection_attempt(client.get("key")):
                raise HTTPException(403, "Ключ заблокирован за инъекционные попытки")
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
    email = _validate_email(email)
    if question:
        question = clean_question(question)

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
async def create_key(plan: str = "free", ref: str | None = Form(None), x_admin_key: str | None = Header(None), request: Request = None):
    """Создание ключа: free — с лимитом на IP; pro/enterprise — только с X-Admin-Key. ref — код партнера."""
    # ВНИМАНИЕ: x-real-ip доверен только если nginx его принудительно перезаписывает.
    # Без этого клиент может подменить заголовок и обойти лимит создания free-ключей.
    if request and request.client:
        client_ip = request.headers.get("x-real-ip") or request.client.host
    else:
        client_ip = "?"
    check_create_allowed(plan, client_ip, x_admin_key)
    partner = resolve_partner(ref)
    key = generate_key(plan, partner)
    out = {"api_key": key, "plan": plan}
    if partner:
        out["partner"] = partner
    return out


PARTNER_COST_PER_1M_USD = 0.15  # расходы LLM за 1M токенов (clodex), сервер до 11/2026 бесплатный


async def _require_admin(x_admin_key: str | None) -> None:
    from .auth import ADMIN_KEY_FILE
    if not x_admin_key:
        raise HTTPException(403, "Требуется X-Admin-Key")
    if not ADMIN_KEY_FILE.exists():
        raise HTTPException(500, "Админ-ключ не настроен на сервере")
    stored = await asyncio.to_thread(lambda: ADMIN_KEY_FILE.read_text().strip())
    # compare_digest — constant-time сравнение, защита от тайминг-атаки
    if not stored or not hmac.compare_digest(x_admin_key, stored):
        raise HTTPException(403, "Неверный админ-ключ")


@app.get("/api/partner/stats")
async def partner_stats(partner: str, x_admin_key: str | None = Header(None)):
    """Статистика партнера: ключи, запросы, выручка, расходы LLM+газ, чистая, доля 50% в USD и CYB."""
    await _require_admin(x_admin_key)
    from .auth import _load, _load_partners, PLANS
    code = (partner or "").strip().lower()
    partners = _load_partners()
    cfg = partners.get(code)
    if not isinstance(cfg, dict) or not cfg.get("active", False):
        raise HTTPException(404, "Партнер не найден или неактивен")
    keys = _load().get("keys", {})
    owned = {h: v for h, v in keys.items() if v.get("partner") == code}
    plan_counts: dict = {}
    requests_total = 0
    revenue_usd = 0.0
    for v in owned.values():
        plan = v.get("plan", "free")
        plan_counts[plan] = plan_counts.get(plan, 0) + 1
        try:
            requests_total += int(v.get("today_count", 0) or 0)
        except (TypeError, ValueError):
            pass
        price = float(PLANS.get(plan, {}).get("price", 0) or 0)
        revenue_usd += price
    hashes = {h[:8] for h in owned}
    llm_tokens = 0
    try:
        log_file = REPORTS_DIR.parent / "logs" / "audit_runs.jsonl"
        if log_file.exists():
            lines = await asyncio.to_thread(
                lambda: log_file.read_text(encoding="utf-8").splitlines()[-20000:]
            )
            for line in lines:
                try:
                    rec = json.loads(line)
                except ValueError:
                    continue
                # В логе полный key_hash — сравниваем по 8-символьному префиксу
                rec_hash = str(rec.get("key_hash", "") or "")
                if rec_hash[:8] in hashes or rec.get("partner") == code:
                    try:
                        llm_tokens += int(rec.get("prompt_tokens", 0) or 0) + int(rec.get("completion_tokens", 0) or 0)
                    except (TypeError, ValueError):
                        continue
    except OSError:
        pass
    llm_cost_usd = round(llm_tokens / 1_000_000 * PARTNER_COST_PER_1M_USD, 4)
    gas_cost_usd = 0.0  # газ учитывается вручную при выплате через treasury (цепочка Avalanche)
    net_usd = round(revenue_usd - llm_cost_usd - gas_cost_usd, 2)
    share = get_partner_share(code)
    payout_usd = round(max(net_usd, 0.0) * share, 2)
    return {
        "partner": code,
        "share": share,
        "payout_asset": cfg.get("payout_asset", "CYB"),
        "keys": len(owned),
        "plans": plan_counts,
        "requests_total": requests_total,
        "revenue_usd": round(revenue_usd, 2),
        "llm_tokens": llm_tokens,
        "llm_cost_usd": llm_cost_usd,
        "gas_cost_usd": gas_cost_usd,
        "net_usd": net_usd,
        "payout_usd": payout_usd,
        "note": "requests_total=today_count (сбрасывается ежедневно); месячный объем — по audit_runs.jsonl",
    }


@app.get("/api/auth/balance")
async def balance(client: dict = Depends(verify_key)):
    return {"plan": client["plan"], "remaining": client.get("remaining"), "limit": client.get("limit")}