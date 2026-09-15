"""Тесты аутентификации — генерация ключей, хеширование, rate limit."""
import sys
import json
import hashlib
import secrets
import tempfile
import os
from pathlib import Path
from datetime import datetime

sys.path.insert(0, "/opt/audit-api")


def test_hash_deterministic():
    """SHA-256 хеш детерминирован."""
    key = "test_key_12345"
    h1 = hashlib.sha256(key.encode()).hexdigest()
    h2 = hashlib.sha256(key.encode()).hexdigest()
    assert h1 == h2
    assert len(h1) == 64


def test_hash_unique():
    """Разные ключи дают разные хеши."""
    h1 = hashlib.sha256("key1".encode()).hexdigest()
    h2 = hashlib.sha256("key2".encode()).hexdigest()
    assert h1 != h2


def test_generate_key_format():
    """Ключ — URL-safe base64 строка."""
    key = secrets.token_urlsafe(32)
    assert len(key) >= 40
    assert "+" not in key  # urlsafe не содержит +


def test_plans_defined():
    """Планы аутентификации определены корректно."""
    from app.auth import PLANS
    assert "free" in PLANS
    assert "pro" in PLANS
    assert "enterprise" in PLANS
    assert PLANS["free"]["per_day"] < PLANS["pro"]["per_day"]
    assert PLANS["pro"]["per_day"] < PLANS["enterprise"]["per_day"]


def test_key_storage_cycle():
    """Полный цикл: создание → сохранение → чтение → проверка хеша."""
    from app.auth import _hash, generate_key, _load, KEYS_FILE

    # Создаём ключ
    key = generate_key("free")
    assert len(key) > 0

    # Проверяем что хеш записан
    data = _load()
    h = _hash(key)
    assert h in data["keys"]
    assert data["keys"][h]["plan"] == "free"
    assert data["keys"][h]["banned"] == False


def test_rate_limit_file():
    """Файл лимитов создаётся и читается."""
    from app.auth import _load_limits, _save_limits

    limits = _load_limits()
    assert isinstance(limits, dict)

    # Записываем тестовый лимит
    limits["test_ip"] = {"2026-09-15": 3}
    _save_limits(limits)

    # Читаем обратно
    loaded = _load_limits()
    assert loaded["test_ip"]["2026-09-15"] == 3

    # Очищаем
    del loaded["test_ip"]
    _save_limits(loaded)


if __name__ == "__main__":
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    passed = 0
    failed = 0
    for t in tests:
        try:
            t()
            print(f"  PASS: {t.__name__}")
            passed += 1
        except AssertionError as e:
            print(f"  FAIL: {t.__name__} — {e}")
            failed += 1
        except Exception as e:
            print(f"  ERROR: {t.__name__} — {e}")
            failed += 1
    print(f"\n{passed} passed, {failed} failed")
    sys.exit(1 if failed else 0)
