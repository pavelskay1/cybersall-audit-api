"""Honeytokens и decoy-данные для обнаружения escape из sandbox.

Внешний контейнер sandbox-host содержит фейковые секреты.
Если злоумышленник выходит за пределы внутреннего контейнера —
находит эти данные, которые при использовании триггерят детект.
"""
import hashlib
import json
import secrets
from pathlib import Path
from datetime import datetime, timezone

HONEYPOT_DIR = Path("/opt/audit-api/honeypot")
LOG_DIR = Path("/opt/audit-api/logs")


def init_honeypot():
    """Создаёт фейковые секреты для sandbox-окружения."""
    HONEYPOT_DIR.mkdir(parents=True, exist_ok=True)
    HONEYPOT_DIR.chmod(0o755)

    fake_data = {
        ".clodex_key": f"sk-honeypot-{secrets.token_hex(32)}",
        "api_keys.json": json.dumps({
            "keys": {
                hashlib.sha256(b"honeypot-decoy").hexdigest(): {
                    "plan": "enterprise",
                    "created_at": int(datetime.now(timezone.utc).timestamp()),
                    "honeypot": True,
                }
            }
        }),
        "admin_key.txt": f"honeypot-admin-{secrets.token_urlsafe(32)}",
        "mail.txt": "honeypot-password-xxxxx",
        ".env": (
            "CLODEX_API_KEY=sk-honeypot-decoy\n"
            "DATABASE_URL=postgresql://honeypot:honeypot@localhost:5432/fake\n"
            "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYHONEYPOT\n"
            "REDIS_URL=redis://honeypot:6379/0\n"
        ),
        "treasury.json": json.dumps({
            "cyb_proxy": "0x000000000000000000000000000000000000DEAD",
            "byok_wallet": "0x000000000000000000000000000000000000DEAD",
            "honeypot": True,
        }),
    }

    for fname, content in fake_data.items():
        path = HONEYPOT_DIR / fname
        path.write_text(content, encoding="utf-8")

    return HONEYPOT_DIR


def check_honeypot_access(output: str, client_key: str = None) -> str:
    """Проверяет, пытался ли код получить доступ к honeypot-данным."""
    indicators = [
        "honeypot",
        "sk-honeypot-",
        "honeypot-admin-",
        "0x000000000000000000000000000000000000DEAD",
        "wJalrXUtnFEMI",
    ]
    for indicator in indicators:
        if indicator in output:
            _log_honeypot_trigger(indicator, client_key)
            return f"Honeypot access attempt: found '{indicator}' in output"
    return ""


def _log_honeypot_trigger(indicator: str, client_key: str = None):
    """Логирует срабатывание honeypot."""
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    log_entry = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "event": "honeypot_triggered",
        "indicator": indicator,
        "key": client_key[:8] + "..." if client_key else "unknown",
        "severity": "CRITICAL",
    }
    with open(LOG_DIR / "security_honeypot.jsonl", "a") as f:
        f.write(json.dumps(log_entry, ensure_ascii=False) + "\n")
    print(f"[HONEYPOT] TRIGGERED: {indicator}")


def get_honeypot_mount() -> list[str]:
    """Возвращает Docker volume-опции для монтирования honeypot."""
    init_honeypot()
    return ["-v", f"{HONEYPOT_DIR}:/app/secrets:ro"]
