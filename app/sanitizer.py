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
    # PEM-блоки целиком (multi-line) — до всего.
    # Независимые незахватывающие группы предотвращают баг обратной ссылки \1 в Python re
    (r"(?i)-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----", "[PEM_PRIVATE_KEY_REDACTED]"),
    # Оборванный PEM без закрывающего тега — маскируем до конца текста во избежание утечки
    (r"(?i)-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----[\s\S]*", "[PEM_PRIVATE_KEY_REDACTED]"),
    # Приватные ключи (fallback для одиночных заголовков)
    (r"(?i)(BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY)[\- ]*", "[PRIVATE_KEY_REDACTED]"),
    # SSH-адреса (до email, чтобы не перехватил email-паттерн).
    # Хост ограничиваем разделителями — иначе жадный \S+ съест кавычку/скобку/запятую
    # строкового литерала и сломает синтаксис код-аудита (else SyntaxError).
    (r"ssh\s+[^\s\"',;()\[\]]+@[^\s\"',;()\[\]]+", "ssh [REDACTED_USER]@[REDACTED_HOST]"),
    # Крипто-адреса EVM (до телефона)
    (r"0x[a-fA-F0-9]{40}", "[CRYPTO_ADDRESS_REDACTED]"),
    # AWS-ключи
    (r"AKIA[0-9A-Z]{16}", "[REDACTED_AWS_KEY]"),
    # OpenAI-style ключи (включая sk-proj-... и дефисы/подчёркивания)
    (r"sk-[a-zA-Z0-9_\-]{20,}", "[REDACTED_KEY]"),
    # Bearer-токены (включая Base64/JWT символы)
    (r"Bearer\s+[a-zA-Z0-9_\-\.~+/]+=*", "Bearer [REDACTED_TOKEN]"),
    # Selectel: строковые литералы (включая f/r префиксы) и безопасные голые значения
    (r'(?i)\b(SELECTEL_AI_KEY|SELECTEL_URL|selectel_key|selectel_url)\s*=\s*[fFrRbBuU]{0,2}"(?:[^"\\]|\\.)*"', r"\1=[REDACTED]"),
    (r"(?i)\b(SELECTEL_AI_KEY|SELECTEL_URL|selectel_key|selectel_url)\s*=\s*[fFrRbBuU]{0,2}'(?:[^'\\]|\\.)*'", r"\1=[REDACTED]"),
    (r"(?i)\b(SELECTEL_AI_KEY|SELECTEL_URL|selectel_key|selectel_url)\s*=\s*(?![\[{]?REDACTED)(?!\s*os\.environ)[A-Za-z0-9_\-.]+(?![\w.(\[])", r"\1=[REDACTED]"),
    # API-ключи в переменных: api_key=[REDACTED] token=[REDACTED]
    # Поддержка составных префиксов (fr, rf, etc.) и экранированных кавычек
    (r'(?i)((?:api[_-]?key|token|secret|password|passphrase|access_key|private_key|auth_token)\s*[=:]\s*)([fFrRbBuU]{0,2}"(?:[^"\\]|\\.)*")', r"\1[REDACTED]"),
    (r"(?i)((?:api[_-]?key|token|secret|password|passphrase|access_key|private_key|auth_token)\s*[=:]\s*)([fFrRbBuU]{0,2}'(?:[^'\\]|\\.)*')", r"\1[REDACTED]"),
    # Голые значения: маскируем только «токеноподобные» — содержат точку/дефис (JWT,
    # url-стиль) или цифры целиком. Плейн-идентификаторы (переменные вида
    # api_key = api_key, VERY_LONG_CONSTANT, ABC123Def) НЕ маскируем: иначе
    # LLM-аудит принимает результат за NameError и получаем ложный quality_ok=False.
    # Совместимо с Python < 3.11 (без атомарных групп)
    (r"(?i)((?:api[_-]?key|token|secret|password|passphrase|access_key|private_key|auth_token)\s*[=:]\s*)(?!\s*os\.environ)(?![\[{]?REDACTED)(?!\s*(?:str|int|float|bool|bytes|list|dict|tuple|set|Optional|Union|None|Any|Self)\b)(?:[A-Za-z0-9_\-.]*[-.][A-Za-z0-9_\-.]*|\d+)(?![\w.(\[])", r"\1[REDACTED]"),
    # API-ключи в JSON (включая auth_token и корректную изоляцию кавычек)
    (r'(?i)["\'](api[_-]?key|token|secret|password|passphrase|access_key|private_key|auth_token)["\']\s*:\s*(["\'])(?:\\.|(?!\2)[^\\])*\2', r'"\1": "[REDACTED]"'),
    # Email (после ssh)
    (r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", "[EMAIL_REDACTED]"),
    # Телефоны (после крипто-адресов)
    (r"(?<!\d)\+?\d{10,12}(?!\d)", "[PHONE_REDACTED]"),
]


def sanitize(text: str) -> str:
    for pat, repl in SANITIZE_PATTERNS:
        text = re.sub(pat, repl, text, flags=re.IGNORECASE)
    return text