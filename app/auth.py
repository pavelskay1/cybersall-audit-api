"""Аутентификация клиентов через API-ключ.
Ключи хранятся в хешированном виде в secret/api_keys.json.
"""
import hashlib
import json
import secrets
import time
from pathlib import Path
from fastapi import Header, HTTPException

SECRET_DIR = Path(__file__).parent.parent / "secret"
KEYS_FILE = SECRET_DIR / "api_keys.json"

# Планы и лимиты запросов в день
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
    # секретный файл — 600
    import os
    os.chmod(KEYS_FILE, 0o600)


def _hash(key: str) -> str:
    return hashlib.sha256(key.encode()).hexdigest()


def generate_key(plan: str = "free") -> str:
    """Создаёт новый API-ключ с указанным планом."""
    if plan not in PLANS:
        raise ValueError(f"Неизвестный план: {plan}. Доступны: {list(PLANS)}")
    raw = secrets.token_urlsafe(32)
    data = _load()
    now = int(time.time())
    data["keys"][_hash(raw)] = {"plan": plan, "created_at": now, "last_used": None, "today_count": 0, "today_date": None}
    _save(data)
    return raw


def verify_key(api_key: str = Header(..., alias="X-API-Key")) -> dict:
    """Проверяет API-ключ. Возвращает данные клиента. 401 при неверном ключе."""
    if not api_key:
        raise HTTPException(401, "Требуется X-API-Key заголовок")
    data = _load()
    client = data["keys"].get(_hash(api_key))
    if client is None:
        raise HTTPException(401, "Неверный API-ключ")

    # Сброс счётчика на новый день
    import datetime
    today = datetime.date.today().isoformat()
    if client.get("today_date") != today:
        client["today_count"] = 0
        client["today_date"] = today

    limit = PLANS[client["plan"]]["per_day"]
    if client["today_count"] >= limit:
        raise HTTPException(429, f"Дневной лимит исчерпан ({limit} запросов). Обновите план.")

    # Списываем запрос
    client["today_count"] += 1
    client["last_used"] = int(time.time())
    _save(data)
    return {"plan": client["plan"], "remaining": limit - client["today_count"], "limit": limit}


def get_balance(api_key: str = Header(..., alias="X-API-Key")) -> dict:
    """Возвращает остаток запросов для клиента."""
    data = _load()
    client = data["keys"].get(_hash(api_key))
    if client is None:
        raise HTTPException(401, "Неверный API-ключ")
    import datetime
    today = datetime.date.today().isoformat()
    if client.get("today_date") != today:
        client["today_count"] = 0
        client["today_date"] = today
    limit = PLANS[client["plan"]]["per_day"]
    return {"plan": client["plan"], "used_today": client["today_count"], "limit": limit, "remaining": limit - client["today_count"]}
