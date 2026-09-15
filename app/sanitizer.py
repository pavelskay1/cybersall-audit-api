"""Санитайзер секретов перед отправкой во внешние LLM.

Порядок паттернов ВАЖЕН:
- сначала специфичные (ssh, крипто-адреса, приватные ключи) — чтобы короткие
  общего вида (email, телефон) не перехватывали их первыми
- потом общие (email, телефон)
- потом значения (sk-..., AKIA..., Bearer)
"""
import re

# Без сортировки — порядок фиксированный, специфичные сначала
SANITIZE_PATTERNS = [
    # PEM-блоки целиком (multi-line) — до всего
    (r"(?i)-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----[\s\S]*?-----END \1PRIVATE KEY-----", "[PEM_PRIVATE_KEY_REDACTED]"),
    # Приватные ключи (заголовок, если end-тег не найден)
    (r"(?i)(BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY)[\- ]*", "[PRIVATE_KEY_REDACTED]"),
    # SSH-адреса (до email, чтобы не перехватил email-паттерн)
    (r"ssh\s+\S+@\S+", "ssh [REDACTED_USER]@[REDACTED_HOST]"),
    # Крипто-адреса EVM (до телефона)
    (r"0x[a-fA-F0-9]{40}", "[CRYPTO_ADDRESS_REDACTED]"),
    # AWS-ключи
    (r"AKIA[0-9A-Z]{16}", "[REDACTED_AWS_KEY]"),
    # OpenAI-style ключи
    (r"sk-[a-zA-Z0-9]{20,}", "[REDACTED_KEY]"),
    # Bearer-токены
    (r"Bearer\s+[a-zA-Z0-9_\-.]{20,}", "Bearer [REDACTED_TOKEN]"),
    # Selectel
    (r"(SELECTEL_AI_KEY|SELECTEL_URL|selectel_key|selectel_url)\s*=\s*[\"\'`]?[^\s\"\'`]+", r"\1=[REDACTED]"),
    # API-ключи в переменных: api_key=xxx, token=xxx
    (r"(?i)(api[_-]?key|token|secret|password|passphrase|access_key|private_key|auth_token)\s*[=:]\s*[\"\'`]?[^\s\"\'`]+", r"\1=[REDACTED]"),
    # API-ключи в JSON: {"api_key": "xxx"} или {'api_key': 'xxx'}
    (r'(?i)["\'](api[_-]?key|token|secret|password|passphrase|access_key|private_key)["\']\s*:\s*["\'][^"\']+["\']', r'"\1": "[REDACTED]"'),
    # Email (после ssh)
    (r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", "[EMAIL_REDACTED]"),
    # Телефоны (после крипто-адресов)
    (r"(?<!\d)\+?\d{10,12}(?!\d)", "[PHONE_REDACTED]"),
]


def sanitize(text: str) -> str:
    for pat, repl in SANITIZE_PATTERNS:
        text = re.sub(pat, repl, text, flags=re.IGNORECASE)
    return text
