"""Санитайзер секретов перед отправкой во внешние LLM."""
import re

SANITIZE_PATTERNS = [
    (r"(?i)(api[_-]?key|token|secret|password|passphrase|access_key|private_key)\s*[=:]\s*[\"\'`]?[^\s\"\'`]+", r"\1=[REDACTED]"),
    (r"sk-[a-zA-Z0-9]{20,}", "[REDACTED_KEY]"),
    (r"Bearer\s+[a-zA-Z0-9_\-.]{20,}", "Bearer [REDACTED_TOKEN]"),
    (r"(SELECTEL_AI_KEY|SELECTEL_URL|selectel_key|selectel_url)\s*=\s*[\"\'`]?[^\s\"\'`]+", r"\1=[REDACTED]"),
    (r"ssh\s+\S+@\S+", "ssh [REDACTED_USER]@[REDACTED_HOST]"),
    (r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", "[EMAIL_REDACTED]"),
    (r"(?<!\d)\+?\d{10,12}(?!\d)", "[PHONE_REDACTED]"),
    (r"(?i)(BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY)", "[PRIVATE_KEY_REDACTED]"),
]

def sanitize(text: str) -> str:
    for pat, repl in SANITIZE_PATTERNS:
        text = re.sub(pat, repl, text, flags=re.IGNORECASE)
    return text
