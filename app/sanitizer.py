"""Санитайзер секретов перед отправкой во внешние LLM.

Исправления (по результатам аудита Claude Opus 5 + GPT-6-Astra):
- Добавлен паттерн для JSON-ключей (api_key в кавычках)
- Добавлен паттерн для AWS-ключей
- Добавлен паттерн для строковых секретов в кавычках
- Добавлена защита от каскадной перезаписи
"""
import re

SANITIZE_PATTERNS = [
    # API-ключи в переменных: api_key=xxx, token=xxx
    (r"(?i)(api[_-]?key|token|secret|password|passphrase|access_key|private_key|auth_token)\s*[=:]\s*[\"\'`]?[^\s\"\'`]+", r"\1=[REDACTED]"),
    # API-ключи в JSON: "api_key": "xxx" или 'api_key': 'xxx'
    (r'(?i)["\']?(api[_-]?key|token|secret|password|passphrase|access_key|private_key)["\']?\s*:\s*["\'][^"\']+["\']', r'"\1": "[REDACTED]"'),
    # OpenAI-style ключи
    (r"sk-[a-zA-Z0-9]{20,}", "[REDACTED_KEY]"),
    # AWS-ключи
    (r"AKIA[0-9A-Z]{16}", "[REDACTED_AWS_KEY]"),
    # Bearer-токены
    (r"Bearer\s+[a-zA-Z0-9_\-.]{20,}", "Bearer [REDACTED_TOKEN]"),
    # Selectel
    (r"(SELECTEL_AI_KEY|SELECTEL_URL|selectel_key|selectel_url)\s*=\s*[\"\'`]?[^\s\"\'`]+", r"\1=[REDACTED]"),
    # SSH
    (r"ssh\s+\S+@\S+", "ssh [REDACTED_USER]@[REDACTED_HOST]"),
    # Email
    (r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", "[EMAIL_REDACTED]"),
    # Телефоны
    (r"(?<!\d)\+?\d{10,12}(?!\d)", "[PHONE_REDACTED]"),
    # Приватные ключи
    (r"(?i)(BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY)", "[PRIVATE_KEY_REDACTED]"),
    # USDT/крипто-адреса (EVM)
    (r"0x[a-fA-F0-9]{40}", "[CRYPTO_ADDRESS_REDACTED]"),
]

# Сначала заменяем较长ные паттерны, чтобы короткие не перезаписывали
SANITIZE_PATTERNS.sort(key=lambda x: -len(x[0]))

def sanitize(text: str) -> str:
    for pat, repl in SANITIZE_PATTERNS:
        text = re.sub(pat, repl, text, flags=re.IGNORECASE)
    return text
