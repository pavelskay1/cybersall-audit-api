"""Клиент для clodex.xyz — поддержка OpenAI и Anthropic форматов."""
import os, json
import httpx
from pathlib import Path
from datetime import datetime, timezone
from .sanitizer import sanitize

CLODEX_URL = "https://clodex.xyz/v1/chat/completions"
CLODEX_ANTHROPIC_URL = "https://clodex.xyz/v1/messages"
LOG_DIR = Path(__file__).parent.parent / "logs"

MODELS = {
    "glm-5.2": {"provider": "openai", "name": "glm-5.2", "label": "GLM-5.2 (Zhipu)"},
    "gpt-6-astra": {"provider": "openai", "name": "gpt-6-astra", "label": "GPT-6-Astra"},
    "gpt-5.5": {"provider": "openai", "name": "gpt-5.5", "label": "GPT-5.5"},
    "deepseek-v4-pro": {"provider": "openai", "name": "deepseek-v4-pro", "label": "DeepSeek V4 Pro"},
    "claude-opus-5": {"provider": "anthropic", "name": "claude-opus-5", "label": "Claude Opus 5"},
    "gemini-3.8-flash": {"provider": "openai", "name": "gemini-3.8-flash", "label": "Gemini 3.8 Flash"},
    "grok-4.6": {"provider": "openai", "name": "grok-4.6", "label": "Grok 4.6"},
    "kimi-k3": {"provider": "openai", "name": "kimi-k3", "label": "Kimi K3"},
    "qwen3.8-max": {"provider": "openai", "name": "qwen3.8-max", "label": "Qwen 3.8 Max"},
}

def load_key() -> str:
    env_key = os.environ.get("CLODEX_API_KEY")
    if env_key:
        return env_key.strip()
    key_path = os.environ.get("CLODEX_KEY_PATH", str(Path(__file__).parent.parent / "secret" / ".clodex_key"))
    try:
        return Path(key_path).read_text().strip()
    except FileNotFoundError:
        raise RuntimeError(f"Ключ не найден. Запишите в {key_path} или задайте CLODEX_API_KEY")


def call_openai(model: str, prompt: str, max_tokens: int = 8000, temperature: float = 0.2) -> dict:
    key = load_key()
    payload = {
        "model": model,
        "messages": [{"role": "user", "content": prompt}],
        "max_tokens": max_tokens,
        "temperature": temperature,
    }
    headers = {"Authorization": f"Bearer {key}", "Content-Type": "application/json"}
    with httpx.Client(timeout=300) as client:
        r = client.post(CLODEX_URL, json=payload, headers=headers)
        r.raise_for_status()
    data = r.json()
    content = data["choices"][0]["message"]["content"]
    usage = data.get("usage", {})
    return {"text": content, "usage": usage, "model": model}


def call_anthropic(model: str, prompt: str, max_tokens: int = 8000) -> dict:
    key = load_key()
    headers = {
        "x-api-key": key,
        "anthropic-version": "2023-06-01",
        "content-type": "application/json",
    }
    data = {
        "model": model,
        "max_tokens": max_tokens,
        "messages": [{"role": "user", "content": prompt}],
    }
    with httpx.Client(timeout=300) as client:
        r = client.post(CLODEX_ANTHROPIC_URL, json=data, headers=headers)
        r.raise_for_status()
    result = r.json()
    content = result.get("content", [{}])[0].get("text", "")
    usage = result.get("usage", {})
    return {"text": content, "usage": usage, "model": model}


def audit_code(code: str, model_key: str, question: str = None) -> dict:
    if model_key not in MODELS:
        raise ValueError(f"Неизвестная модель: {model_key}. Доступные: {list(MODELS.keys())}")
    
    model_info = MODELS[model_key]
    sanitized_code = sanitize(code)
    
    if question is None:
        question = "Проанализируй код. Найди баги, уязвимости, логические ошибки. Приоритеты P0/P1/P2. Рекомендации на русском."
    
    prompt = f"## Код на аудит\n```\n{sanitized_code}\n```\n\n## Задание\n{question}"
    
    if model_info["provider"] == "anthropic":
        result = call_anthropic(model_info["name"], prompt)
    else:
        result = call_openai(model_info["name"], prompt)
    
    log_audit(model_key, question, result["usage"])
    return result


def log_audit(model: str, question: str, usage: dict):
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    log_file = LOG_DIR / "audit_runs.jsonl"
    record = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "model": model,
        "question": question[:100],
        "prompt_tokens": usage.get("prompt_tokens") or usage.get("input_tokens"),
        "completion_tokens": usage.get("completion_tokens") or usage.get("output_tokens"),
    }
    with open(log_file, "a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")
