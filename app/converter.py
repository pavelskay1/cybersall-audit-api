"""Модуль конвертации Python → C++.

Использует пайплайн: Claude (перевод) → GPT (птимизация) → DeepSeek (проверка).
"""
import time
from .clodex_client import call_openai, call_anthropic, log_audit
from .sanitizer import sanitize

CONVERT_CHAIN = [
    {"model": "claude-opus-5", "role": "translator"},
    {"model": "gpt-6-astra", "role": "optimizer", "fallback": "deepseek-v4-flash"},
    {"model": "kimi-k3", "role": "reviewer"},
]

TRANSLATE_PROMPT = """Ты — expert C++ инженер с 15-летним опытом. Переведи этот Python код в production-ready C++.

Требования:
1. Используй C++20 (std::ranges, std::format, structured bindings)
2. Zero-allocation где возможно (stack-allocated, reserve заранее)
3. RAII для всех ресурсов
4. Strong typing (никаких void*, reinterpret_cast без нужды)
5. Обработка ошибок через std::expected (C++23) или std::optional
6. NOLINT только если realmente нужен
7. Include necessary headers
8. Добавь namespace (название из имени файла или Utils)
9. Никаких raw pointers — только smart pointers или value types
10. Предпочтительнее std::array/std::span над std::vector если размер известен

Python код:
```python
{code}
```

Дополнительный контекст: {question}

Верни ТОЛЬКО C++ код без объяснений. Строго в ```cpp блоке."""

OPTIMIZE_PROMPT = """Ты — C++ performance engineer. Оптимизируй этот C++ код для HFT/low-latency:

1. Убай все heap-аллокации (new/malloc → stack/reserve)
2. Замени std::string на string_view где безопасно
3. Убай копирования — используй move semantics
4. Branch prediction hints (__builtin_expect)
5. Cache-friendly data layouts (SoA vs AoS)
6. Никаких исключений в hot path — use std::optional/error codes
7. Компилируйся с -O3 -march=native

Код:
```cpp
{code}
```

Верни оптимизированный C++ код без объяснений."""

REVIEW_PROMPT = """Ты — C++ QA инженер. Проверь этот код на:

1. Memory safety (buffer overflow, use-after-free, dangling refs)
2. Thread safety (race conditions, deadlocks)
3. Undefined behavior
4. Logic errors (сравни с оригинальным поведением Python)
5. компилируемость (все ли headers, все ли типы)

Код:
```cpp
{code}
```

Если нашёл ошибки — исправь и верни финальный код.
Если ошибок нет — верни тот же код.
Только C++ код, без объяснений."""


def convert_python_to_cpp(code: str, question: str = None) -> dict:
    """Конвертирует Python → C++ через пайплайн из 3 моделей."""
    start = time.time()
    code = sanitize(code)
    ctx = question or "Оптимизировать для производительности"

    current_code = code
    stages_log = []

    # Stage 1: Claude — перевод
    print("[converter] Stage 1: Claude — перевод Python → C++")
    prompt = TRANSLATE_PROMPT.format(code=current_code, question=ctx)
    try:
        r = call_anthropic("claude-opus-5", prompt, max_tokens=12000)
        current_code = _extract_code(r["text"], "cpp")
        log_audit("claude-opus-5", "convert:translate", r.get("usage", {}))
        stages_log.append({"stage": "translate", "model": "claude-opus-5", "ok": True})
    except Exception as e:
        print(f"[converter] Claude failed: {e}, fallback to DeepSeek")
        try:
            r = call_openai("deepseek-v4-flash", prompt, max_tokens=12000)
            current_code = _extract_code(r["text"], "cpp")
            log_audit("deepseek-v4-flash", "convert:translate", r.get("usage", {}))
            stages_log.append({"stage": "translate", "model": "deepseek-v4-flash", "ok": True})
        except Exception as e2:
            stages_log.append({"stage": "translate", "model": "none", "ok": False, "error": str(e2)})
            return {"cpp": "", "error": f"Перевод не удался: {e2}", "stages": stages_log, "elapsed": 0}

    # Stage 2: GPT — оптимизация
    print("[converter] Stage 2: GPT — оптимизация")
    model_key = "gpt-6-astra"
    try:
        r = call_openai(model_key, OPTIMIZE_PROMPT.format(code=current_code), max_tokens=12000)
        current_code = _extract_code(r["text"], "cpp")
        log_audit(model_key, "convert:optimize", r.get("usage", {}))
        stages_log.append({"stage": "optimize", "model": model_key, "ok": True})
    except Exception as e:
        print(f"[converter] GPT failed: {e}, fallback to DeepSeek")
        model_key = "deepseek-v4-flash"
        try:
            r = call_openai(model_key, OPTIMIZE_PROMPT.format(code=current_code), max_tokens=12000)
            current_code = _extract_code(r["text"], "cpp")
            log_audit(model_key, "convert:optimize", r.get("usage", {}))
            stages_log.append({"stage": "optimize", "model": model_key, "ok": True})
        except Exception as e2:
            stages_log.append({"stage": "optimize", "model": "none", "ok": False, "error": str(e2)})

    # Stage 3: Kimi — ревью
    print("[converter] Stage 3: Kimi — ревью")
    try:
        r = call_openai("kimi-k3", REVIEW_PROMPT.format(code=current_code), max_tokens=12000)
        reviewed = _extract_code(r["text"], "cpp")
        if reviewed and len(reviewed) > len(current_code) * 0.5:
            current_code = reviewed
        log_audit("kimi-k3", "convert:review", r.get("usage", {}))
        stages_log.append({"stage": "review", "model": "kimi-k3", "ok": True})
    except Exception as e:
        print(f"[converter] Kimi review failed: {e}")
        stages_log.append({"stage": "review", "model": "none", "ok": False, "error": str(e)})

    elapsed = round(time.time() - start, 1)
    return {
        "cpp": current_code,
        "stages": stages_log,
        "elapsed": elapsed,
    }


def _extract_code(text: str, lang: str) -> str:
    """Извлекает код из markdown-блока."""
    if f"```{lang}" in text:
        parts = text.split(f"```{lang}")
        if len(parts) > 1:
            code = parts[1].split("```")[0]
            return code.strip()
    if "```" in text:
        parts = text.split("```")
        if len(parts) >= 3:
            return parts[1].strip()
    return text.strip()
