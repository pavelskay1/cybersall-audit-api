"""Аутентификация клиентов через API-ключ.
Ключи хранятся в хешированном виде в secret/api_keys.json.
"""
import hashlib
import json
import secrets
import time
import datetime
from pathlib import Path
from fastapi import Header, HTTPException

SECRET_DIR = Path(__file__).parent.parent / "secret"
KEYS_FILE = SECRET_DIR / "api_keys.json"
ADMIN_KEY_FILE = SECRET_DIR / "admin_key.txt"
LIMITS_FILE = SECRET_DIR / "create_limits.json"
FREE_CREATE_PER_IP_PER_DAY = 5  # бесплатных ключей с одного IP в сутки

PLANS = {
    "free": {"per_day": 3, "price": 0},
    "pro": {"per_day": 30, "price": 49},
    "enterprise": {"per_day": 200, "price": 499},
}


def _load():
    if KEYS_FILE.exists():
        return json.loads(KEYS_FILE.read_text())
    return {"keys": {}}


def _save(data):
    KEYS_FILE.parent.mkdir(parents=True, exist_ok=True)
    KEYS_FILE.write_text(json.dumps(data, indent=2, ensure_ascii=False))
    import os
    os.chmod(KEYS_FILE, 0o600)


def _load_limits():
    if LIMITS_FILE.exists():
        return json.loads(LIMITS_FILE.read_text())
    return {}


def _save_limits(data):
    LIMITS_FILE.parent.mkdir(parents=True, exist_ok=True)
    LIMITS_FILE.write_text(json.dumps(data, indent=2, ensure_ascii=False))
    import os
    os.chmod(LIMITS_FILE, 0o600)


def _hash(key: str) -> str:
    return hashlib.sha256(key.encode()).hexdigest()


def check_create_allowed(plan: str, client_ip: str, admin_key: str | None = None) -> None:
    """Защита /api/auth/create: платные планы только с админ-ключом, free — лимит на IP."""
    if plan != "free":
        if not admin_key:
            raise HTTPException(403, "Платные планы доступны только через админ-ключ")
        if not ADMIN_KEY_FILE.exists():
            raise HTTPException(500, "Админ-ключ не настроен на сервере")
        stored = ADMIN_KEY_FILE.read_text().strip()
        if not stored or admin_key != stored:
            raise HTTPException(403, "Неверный админ-ключ")
        return
    limits = _load_limits()
    today = datetime.date.today().isoformat()
    day = limits.setdefault(client_ip, {}).setdefault(today, 0)
    if day >= FREE_CREATE_PER_IP_PER_DAY:
        raise HTTPException(429, "Слишком много бесплатных ключей с этого IP (макс 5/сутки). Попробуйте завтра.")
    limits[client_ip][today] = day + 1
    _save_limits(limits)


def generate_key(plan: str = "free") -> str:
    if plan not in PLANS:
        raise ValueError(f"Неизвестный план: {plan}. Доступны: {list(PLANS)}")
    raw = secrets.token_urlsafe(32)
    data = _load()
    now = int(time.time())
    data["keys"][_hash(raw)] = {
        "plan": plan, "created_at": now, "last_used": None,
        "today_count": 0, "today_date": None, "banned": False,
    }
    _save(data)
    return raw


def verify_key(api_key: str = Header(..., alias="X-API-Key")) -> dict:
    if not api_key:
        raise HTTPException(401, "Требуется X-API-Key заголовок")
    data = _load()
    client = data["keys"].get(_hash(api_key))
    if client is None:
        raise HTTPException(401, "Неверный API-ключ")
    # Проверка бана
    if client.get("banned"):
        raise HTTPException(403, "Ваш ключ заблокирован за нарушение правил безопасности")

    today = datetime.date.today().isoformat()
    if client.get("today_date") != today:
        client["today_count"] = 0
        client["today_date"] = today

    limit = PLANS[client["plan"]]["per_day"]
    if client["today_count"] >= limit:
        raise HTTPException(429, f"Дневной лимит исчерпан ({limit} запросов). Обновите план.")

    client["today_count"] += 1
    client["last_used"] = int(time.time())
    _save(data)
    return {
        "plan": client["plan"],
        "remaining": limit - client["today_count"],
        "limit": limit,
        "key": api_key,
    }


def get_balance(api_key: str = Header(..., alias="X-API-Key")) -> dict:
    data = _load()
    client = data["keys"].get(_hash(api_key))
    if client is None:
        raise HTTPException(401, "Неверный API-ключ")
    if client.get("banned"):
        raise HTTPException(403, "Ваш ключ заблокирован")
    today = datetime.date.today().isoformat()
    if client.get("today_date") != today:
        client["today_count"] = 0
        client["today_date"] = today
    limit = PLANS[client["plan"]]["per_day"]
    return {
        "plan": client["plan"],
        "used_today": client["today_count"],
        "limit": limit,
        "remaining": limit - client["today_count"],
    }
