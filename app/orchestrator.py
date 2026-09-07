"""Оркестратор ансамбля LLM для аудита кода.

Цепочка: Claude (первичный) → GPT-6-Astra (глубина) → Kimi K3 (додумывание)
Дирижёр: DeepSeek V4 Flash (разбиение, сбор, контроль качества, доработка)
Fallback: если GPT падает — её роль берёт DeepSeek.
"""
import json
import time
from pathlib import Path
from .clodex_client import call_openai, call_anthropic, load_key, MODELS, log_audit
from .sanitizer import sanitize

CHAIN = [
    {"role": "primary", "model": "claude-opus-5"},
    {"role": "deep", "model": "gpt-6-astra", "fallback": "deepseek-v4-flash"},
    {"role": "final", "model": "kimi-k3"},
]
ORCHESTRATOR = "deepseek-v4-flash"
QUALITY_CHECKER = "claude-opus-5"

MAX_BLOCK_CHARS = 4000  # лимит кода на блок для одной модели
MAX_TOKENS = 8000


def split_into_blocks(code: str, model: str = ORCHESTRATOR) -> list[dict]:
    """DeepSeek разбивает код на логические блоки с контекстом."""
    prompt = f"""Разбей следующий код на логические блоки для параллельного аудита.
Каждый блок: {MAX_BLOCK_CHARS} символов максимум. Для каждого блока добавь контекст:
- что это (функция/класс/модуль)
- откуда вызывается (если видно)
- фокус аудита (какие проблемы искать)

Верни ТОЛЬКО JSON:
[
  {{"name": "...", "code": "...", "context": "...", "focus": "..."}}
]

Код:
```python
{code[:50000]}
```"""
    r = call_openai(model if model in MODELS else ORCHESTRATOR, prompt, max_tokens=3000)
    text = r["text"].strip()
    if text.startswith("```"):
        text = text.split("\n", 1)[1].rsplit("```", 1)[0]
    try:
        blocks = json.loads(text)
        if not isinstance(blocks, list) or len(blocks) == 0:
            raise ValueError("Empty blocks")
        return blocks
    except Exception as e:
        print(f"[orchestrator] Не удалось разбить на блоки: {e}, беру код целиком")
        return [{"name": "whole_code", "code": code[:MAX_BLOCK_CHARS], "context": "весь код", "focus": "полный аудит"}]


def run_stage(block: dict, stage: dict, previous_results: list[dict]) -> dict:
    """Прогоняет один блок через одну модель цепочки. GPT fallback → DeepSeek."""
    model_key = stage["model"]
    code = block.get("code", "")
    context = block.get("context", "")
    focus = block.get("focus", "найди реальные баги P0/P1/P2")
    name = block.get("name", "block")

    history = ""
    if previous_results:
        history = "\n\n### Находки предыдущих моделей по этому блоку:\n"
        for prev in previous_results:
            history += f"\n--- {prev['model']} ---\n{prev['text'][:1500]}\n"

    prompt = f"""Ты — security-инженер. Аудитируешь блок кода из проекта.

Блок: {name}
Контекст: {context}
Фокус: {focus}

Код:
```python
{code}
```

{history}

Дай отчёт: реальные проблемы с приоритетами P0/P1/P2, код-фикс. Не выдумывай —
проверяй каждую находку на реальность. Язык: русский."""

    attempt = 0
    errors = []
    while attempt < 2:
        try:
            if model_key.startswith(("claude", "anthropic")):
                r = call_anthropic(model_key, prompt, max_tokens=MAX_TOKENS)
            else:
                r = call_openai(model_key, prompt, max_tokens=MAX_TOKENS)
            text = r["text"]
            if not text or len(text) < 20:
                raise ValueError("Пустой ответ")
            log_audit(model_key, f"block={name}", r.get("usage", {}))
            return {"model": model_key, "block": name, "text": text, "usage": r.get("usage", {})}
        except Exception as e:
            errors.append(str(e))
            attempt += 1
            print(f"[orchestrator] {model_key} попытка {attempt} ошибка: {e}")
            if model_key == "gpt-6-astra" and stage.get("fallback"):
                print(f"[orchestrator] GPT не ответил, fallback → {stage['fallback']}")
                model_key = stage["fallback"]
            time.sleep(5)

    return {"model": model_key, "block": name, "text": "", "error": "; ".join(errors)}


def quality_check(results: list[dict], model: str = ORCHESTRATOR) -> tuple[bool, str, str]:
    """DeepSeek проверяет качество ответов. Если плохо — возвращает вопросы для доработки."""
    combined = "\n\n".join(
        f"--- {r.get('model', '?')} (блок {r.get('block', '?')}) ---\n{r.get('text', '')[:2000]}"
        for r in results if r.get("text")
    )

    prompt = f"""Ты — дирижёр аудита. Проанализируй ответы трёх моделей.

{combined}

Оцени:
1. Полноту (все ли реальные проблемы найдены?)
2. Достоверность (нет ли явных галлюцинаций?)
3. Структуру (понятно ли, что исправлять?)

Верни JSON:
{{"quality": "high|medium|low", "issues": ["...", "..."], "questions": ["вопросы для доработки"]}}
Только JSON."""
    r = call_openai(model, prompt, max_tokens=2000)
    text = r["text"].strip()
    if text.startswith("```"):
        text = text.split("\n", 1)[1].rsplit("```", 1)[0]
    try:
        verdict = json.loads(text)
        q = verdict.get("quality", "low")
        all_ok = q == "high"
        questions = "\n".join(verdict.get("questions", []))
        issues = "\n".join(verdict.get("issues", []))
        return all_ok, questions, issues
    except Exception as e:
        print(f"[orchestrator] Не удалось распарсить вердикт: {e}")
        return False, "Проверь ответы подробнее", text


def audit_full(code: str, question: str = None) -> dict:
    """Полный прогон оркестра: Claude → GPT → Kimi → DeepSeek-контроль."""
    start = time.time()
    code = sanitize(code)
    if question:
        code = f"Вопрос пользователя: {question}\n\n{code}"

    # 1. Дирижёр разбивает на блоки
    blocks = split_into_blocks(code)
    print(f"[orchestrator] Разбито на {len(blocks)} блоков")

    all_results = []
    chain = [
        {"role": "primary", "model": "claude-opus-5"},
        {"role": "deep", "model": "gpt-6-astra", "fallback": "deepseek-v4-flash"},
        {"role": "final", "model": "kimi-k3"},
    ]

    for i, block in enumerate(blocks):
        print(f"[orchestrator] Блок {i+1}/{len(blocks)}: {block.get('name', '?')}")
        previous = [r for r in all_results if r.get("block") == block.get("name")]
        for stage in chain:
            res = run_stage(block, stage, previous)
            all_results.append(res)
            previous.append(res)

    # 2. Дирижёр собирает и оценивает качество
    print("[orchestrator] Контроль качества...")
    ok, questions, issues = quality_check(all_results)

    final_text = "\n\n".join(
        f"--- {r.get('model', '?')} (блок {r.get('block', '?')}) ---\n{r.get('text', r.get('error', 'нет ответа'))[:4000]}"
        for r in all_results if r.get("text") or r.get("error")
    )

    if not ok:
        # Доработка: дирижёр отправляет вопросы в Kimi
        print("[orchestrator] Доработка (DeepSeek вопросы → Kimi)")
        rework_prompt = f"""{final_text[:12000]}

Вопросы дирижёра для доработки:
{questions}

Дай финальные правки: что нужно исправить в выводах?"""
        try:
            r = call_openai("kimi-k3", rework_prompt, max_tokens=MAX_TOKENS)
            if r["text"]:
                final_text += f"\n\n--- ДОРАБОТКА (kimi-k3) ---\n{r['text']}"
        except Exception as e:
            print(f"[orchestrator] Доработка не удалась: {e}")
            final_text += f"\n\n--- ВОПРОСЫ ДИРИЖЁРА ---\n{questions}\n\n{issues}"

    elapsed = time.time() - start
    return {
        "report": final_text,
        "quality_ok": ok,
        "questions": questions,
        "issues": issues,
        "blocks": len(blocks),
        "elapsed_sec": round(elapsed, 1),
    }
