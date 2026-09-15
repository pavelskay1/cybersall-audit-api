"""Оркестратор ансамбля LLM для аудита кода.

Цепочка: Claude (первичный) -> GPT-6-Astra (глубина) -> Kimi K3 (додумывание)
Дирижёр: DeepSeek V4 Flash (разбиение, сбор, контроль качества, финальный вердикт)
Fallback: если GPT падает — её роль берёт DeepSeek.
"""
import json
import math
import re
import time
from pathlib import Path
from .clodex_client import call_openai, call_anthropic, load_key, MODELS, log_audit
from .sanitizer import sanitize

CHAIN = [
    {"role": "primary", "model": "claude-opus-5", "fallback": "kimi-k3"},
    {"role": "deep", "model": "glm-5.2", "fallback": "gpt-6-astra"},
    {"role": "final", "model": "kimi-k3", "fallback": "glm-5.2"},
]
ORCHESTRATOR = "deepseek-v4.1-flash"
ORCHESTRATOR_FALLBACK = "glm-5.2"
QUALITY_CHECKER = "claude-opus-5"

MAX_BLOCK_CHARS = 16000
MAX_TOKENS = 16000
MAX_BLOCKS = 16      # больше блоков = взрыв времени и токенов
MIN_BLOCK_CHARS = 8000  # ниже этого размера блок считается 'слишком мелким'

# Метрики по замерам (2026-09-12, Avalanche-контракт, 3 блока)
AVG_STAGE_SEC = {"claude-opus-5": 41, "gpt-6-astra": 140, "kimi-k3": 56}
SPLIT_AVG_SEC = 32
QUALITY_AVG_SEC = 36
REWORK_AVG_SEC = 47


def estimate_audit_minutes(code_len: int) -> int:
    """Честная оценка времени аудита для лендинга/таймера."""
    blocks = max(1, math.ceil(code_len / MAX_BLOCK_CHARS))
    per_block = sum(AVG_STAGE_SEC.values())
    total_sec = SPLIT_AVG_SEC + blocks * per_block + QUALITY_AVG_SEC + REWORK_AVG_SEC
    return max(2, round(total_sec / 60))


def _file_index(code: str) -> str:
    """Краткий индекс файла: сигнатуры функций, чтобы блоки знали о соседях."""
    sigs = re.findall(r"^\s*(?:def\s+\w+|function\s+\w+|constructor|receive|fallback)\s*[^\n{;]*", code, re.M)
    if not sigs:
        return ""
    clean = [s.strip() for s in sigs]
    out = "Полный файл содержит следующие функции (в соседних блоках):\n" + "\n".join("- " + s for s in clean)
    return out


def _merge_small_blocks(blocks: list) -> list:
    """Склеивает слишком мелкие блоки в соседние, пока не наберётся разумный размер."""
    merged = []
    carry = None
    for b in blocks:
        code = b.get("code", "")
        if not code:
            continue
        if carry is None:
            carry = dict(b)
            continue
        small = len(code) < MIN_BLOCK_CHARS or len(carry["code"]) < MIN_BLOCK_CHARS
        if small and len(carry["code"]) + len(code) <= MAX_BLOCK_CHARS:
            carry["code"] += "\n\n" + code
            carry["name"] = (carry.get("name") or "block") + "+" + (b.get("name") or "block")
            carry["focus"] = "полный аудит объединённого блока"
            carry["context"] = ((carry.get("context") or "") + "\n" + (b.get("context") or "")).strip()
            continue
        merged.append(carry)
        carry = dict(b)
    if carry is not None:
        merged.append(carry)
    return merged or blocks


def _fallback_blocks(code: str, file_index: str) -> list:
    """Простая нарезка по символам, если LLM-сплиттер не справился или раздробил слишком мелко."""
    blocks, start, i = [], 0, 0
    n = len(code)
    while start < n:
        end = min(start + MAX_BLOCK_CHARS, n)
        blocks.append({"name": f"block_{i+1}", "code": code[start:end],
                      "context": file_index, "focus": "полный аудит сегмента"})
        start = end
        i += 1
    return blocks


def split_into_blocks(code: str, model: str = ORCHESTRATOR) -> list:
    file_index = _file_index(code)
    # Маленький файл аудируем целиком: LLM-сплиттер не нужен, это быстрее и точнее
    if len(code) <= MAX_BLOCK_CHARS:
        return [{"name": "whole_code", "code": code,
                 "context": file_index, "focus": "полный аудит файла"}]
    prompt = (
        "Разбей следующий код на логические блоки для параллельного аудита.\n"
        "Целевой размер блока: ~" + str(MAX_BLOCK_CHARS) + " символов. Минимум: " + str(MIN_BLOCK_CHARS) + " символов (кроме последнего). Максимум: " + str(MAX_BLOCKS) + " блоков.\n"
        "Не дроби код слишком мелко — по функции или небольшому модулю, а не по строкам.\n"
        "Для каждого блока добавь контекст: что это, откуда вызывается, фокус аудита.\n"
        "Верни ТОЛЬКО JSON:\n"
        '[{"name": "...", "code": "...", "context": "...", "focus": "..."}]\n\n'
        "Код:\n```python\n" + code[:50000] + "\n```"
    )
    for splitter_model in [model, "glm-5.2", "claude-opus-5", "kimi-k3"]:
        try:
            if splitter_model.startswith(("claude", "anthropic")):
                r = call_anthropic(splitter_model, prompt, max_tokens=4000)
            else:
                r = call_openai(splitter_model, prompt, max_tokens=10000)
            text = r["text"].strip()
            if text.startswith("```"):
                text = text.split("\n", 1)[1].rsplit("```", 1)[0]
            blocks = json.loads(text)
            if not isinstance(blocks, list) or len(blocks) == 0:
                raise ValueError("Empty blocks")
            # Склеить мелкие блоки и ограничить число блоков (страховка от дробилки)
            blocks = _merge_small_blocks(blocks)
            if len(blocks) > MAX_BLOCKS:
                print(f"[orchestrator] Сплиттер дал {len(blocks)} блоков — режу по символам")
                blocks = _fallback_blocks(code, file_index)
            # Вписать индекс файла в контекст каждого блока
            for b in blocks:
                ctx = b.get("context", "")
                b["context"] = (file_index + "\n\n" + ctx).strip() if file_index else ctx
            
            # Проверка покрытия: если потеряно >10% кода — fallback
            total_in = sum(len(b.get("code", "")) for b in blocks)
            if total_in < len(code) * 0.9:
                print(f"[orchestrator] Покрытие {total_in}/{len(code)} ({100*total_in//len(code)}%) — fallback")
                blocks = _fallback_blocks(code, file_index)
            
            return blocks
        except Exception as e:
            print(f"[orchestrator] split через {splitter_model} не удался: {e}")
            continue
    print("[orchestrator] Все модели для сплита недоступны, беру код целиком")
    return [{"name": "whole_code", "code": code[:MAX_BLOCK_CHARS],
             "context": file_index, "focus": "полный аудит"}]


def run_stage(block: dict, stage: dict, previous_results: list) -> dict:
    model_key = stage["model"]
    code = block.get("code", "")
    context = block.get("context", "")
    focus = block.get("focus", "найди реальные баги P0/P1/P2")
    name = block.get("name", "block")

    if name == "whole_code":
        scope_intro = (
            "Ты — security-инженер. Аудитируешь файл целиком (он небольшой, "
            "передан полностью).\n\n"
        )
    else:
        scope_intro = (
            "Ты — security-инженер. Аудитируешь БЛОК из большого файла проекта.\n\n"
            "ВАЖНО: ты видишь не весь файл, а фрагмент. Не утверждай, что функции "
            "'отсутствуют', если их нет в этом блоке — сначала сверься со списком "
            "функций полного файла в контексте.\n\n"
        )

    history = ""
    if previous_results:
        history = "\n\n### Находки предыдущих моделей по этому блоку:\n"
        for prev in previous_results:
            history += "\n--- " + prev.get("model", "?") + " ---\n" + prev.get("text", "")[:1500] + "\n"

    prompt = (
        scope_intro +
        "Блок: " + name + "\n"
        "Контекст: \n" + context + "\n\n"
        "Фокус: " + focus + "\n\n"
        "Код блока:\n```python\n" + code + "\n```\n\n"
        + history + "\n\n"
        "Формат ответа:\n"
        "1. Реальные проблемы этого блока с приоритетами P0/P1/P2 (только то, что "
        "подтверждается кодом блока или списком функций).\n"
        "2. Для каждой проблемы — почему она реальна, код-фикс.\n"
        "3. Если проблема касается всего файла, а не блока — пометь [ФАЙЛ] и "
        "опиши кратко.\n"
        "Не выдумывай. Язык: русский."
    )

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
            log_audit(model_key, "block=" + name, r.get("usage", {}))
            return {"model": model_key, "block": name, "text": text, "usage": r.get("usage", {}), "elapsed": r.get("elapsed", 0)}
        except Exception as e:
            errors.append(str(e))
            attempt += 1
            print(f"[orchestrator] {model_key} попытка {attempt} ошибка: {e}")
            if model_key == "gpt-6-astra" and stage.get("fallback"):
                print(f"[orchestrator] GPT не ответил, fallback -> {stage['fallback']}")
                model_key = stage["fallback"]
            time.sleep(5)

    return {"model": model_key, "block": name, "text": "", "error": "; ".join(errors)}


def quality_check(results: list, model: str = ORCHESTRATOR):
    parts = []
    block_names = set()
    for r in results:
        if r.get("text"):
            m = r.get("model", "?")
            b = r.get("block", "?")
            block_names.add(b)
            t = r.get("text", "")[:2000]
            parts.append("--- " + m + " (блок " + b + ") ---\n" + t)
    combined = "\n\n".join(parts)
    if not combined.strip():
        print("[orchestrator] quality_check: нет текстовых результатов для проверки")
        return False, "Нет результатов для проверки", ""

    if len(block_names) <= 1:
        scope_desc = "файл небольшой, каждая модель видела его целиком."
    else:
        scope_desc = "файл разбит на блоки, каждая модель видела ТОЛЬКО свой блок кода."

    prompt = (
        "Ты — дирижёр аудита. " + scope_desc + "\n\n"
        + combined + "\n\n"
        "Учитывая это, оцени:\n"
        "1. Полноту — покрыты ли все блоки?\n"
        "2. Достоверность — есть ли ложные утверждения 'функция отсутствует', "
        "когда она есть в соседнем блоке?\n"
        "3. Структуру — согласованы ли приоритеты между моделями?\n\n"
        "Верни JSON: {\"quality\": \"high|medium|low\", \"issues\": [\"...\"], "
        "\"questions\": [\"вопросы для доработки\"]}\nТолько JSON."
    )

    for checker_model in [model, "glm-5.2", "claude-opus-5", "kimi-k3"]:
        try:
            if checker_model.startswith(("claude", "anthropic")):
                r = call_anthropic(checker_model, prompt, max_tokens=4000)
            else:
                r = call_openai(checker_model, prompt, max_tokens=4000)
            text = r["text"].strip()
            if text.startswith("```"):
                text = text.split("\n", 1)[1].rsplit("```", 1)[0]
            verdict = json.loads(text)
            q = verdict.get("quality", "low")
            all_ok = q == "high"
            questions = "\n".join(verdict.get("questions", []))
            issues = "\n".join(verdict.get("issues", []))
            return all_ok, questions, issues
        except Exception as e:
            print(f"[orchestrator] quality_check через {checker_model} не удался: {e}")
            continue

    print("[orchestrator] quality_check: все модели недоступны, пропускаю проверку")
    return True, "", ""


def final_verdict(results: list, code_len: int, model: str = ORCHESTRATOR) -> str:
    """Финальный анализ дирижёра: дедупликация, учёт разбивки, единый вердикт."""
    parts = []
    seen_blocks = set()
    for r in results:
        if r.get("text") or r.get("error"):
            m = r.get("model", "?")
            b = r.get("block", "?")
            seen_blocks.add(b)
            t = r.get("text", r.get("error", ""))[:6000]
            parts.append("--- " + m + " (блок " + b + ") ---\n" + t)
    combined = "\n\n".join(parts[:30])
    if not combined.strip():
        return ""
    blocks = max(1, len(seen_blocks))
    if blocks == 1:
        split_desc = "файл небольшой и был передан моделям целиком (1 блок)."
        split_problem = ""
    else:
        split_desc = (
            "файл был разбит на " + str(blocks) + " логических блоков, каждый блок "
            "аудировали 3 модели (Claude Opus 5, GPT-6-Astra, Kimi K3) по отдельности."
        )
        split_problem = (
            "\n\nПРОБЛЕМА РАЗБИВКИ: модели видели только свои блоки. Часть утверждений "
            "может быть ложной ('функция отсутствует', хотя она в другом блоке), "
            "часть находок дублируется между моделями."
        )
    prompt = (
        "Ты — главный дирижёр аудита кода. " + split_desc + split_problem + "\n\n"
        "Твоя задача — дать КЛИЕНТУ точный итоговый отчёт:\n"
        "1. Удали дубликаты (одна проблема, найденная 2-3 моделями = 1 пункт).\n"
        "2. Отсекай ложные срабатывания, противоречащие коду (сверяй со списком функций).\n"
        "3. Сгруппируй по приоритетам P0 (критические) / P1 (серьёзные) / P2 (низкие).\n"
        "4. Для каждой реальной проблемы: описание, почему это риск, рекомендация.\n"
        "5. В конце — краткий вывод: аудит пройден / требует доработки.\n\n"
        "Ответы моделей:\n" + combined + "\n\n"
        "Итоговый отчёт на русском, чётко и без воды."
    )
    for verdict_model in [model, "glm-5.2", "claude-opus-5", "kimi-k3"]:
        try:
            if verdict_model.startswith(("claude", "anthropic")):
                r = call_anthropic(verdict_model, prompt, max_tokens=MAX_TOKENS)
            else:
                r = call_openai(verdict_model, prompt, max_tokens=MAX_TOKENS)
            text = r["text"]
            if not text or len(text) < 20:
                raise ValueError("Пустой ответ")
            log_audit(verdict_model, "final_verdict", r.get("usage", {}), elapsed=r.get("elapsed", 0))
            return text
        except Exception as e:
            print(f"[orchestrator] final_verdict через {verdict_model} не удался: {e}")
            continue
    return ""


def audit_full(code: str, question: str = None) -> dict:
    start = time.time()
    code = sanitize(code)
    if question:
        code = "Вопрос пользователя: " + question + "\n\n" + code

    blocks = split_into_blocks(code)
    print(f"[orchestrator] Разбито на {len(blocks)} блоков")

    all_results = []
    chain = [
        {"role": "primary", "model": "claude-opus-5"},
        {"role": "deep", "model": "gpt-6-astra", "fallback": "deepseek-v4.1-flash"},
        {"role": "final", "model": "kimi-k3"},
    ]

    for i, block in enumerate(blocks):
        bname = block.get("name", "?")
        print(f"[orchestrator] Блок {i+1}/{len(blocks)}: {bname}")
        previous = [r for r in all_results if r.get("block") == bname]
        for stage in chain:
            res = run_stage(block, stage, previous)
            all_results.append(res)
            previous.append(res)

    print("[orchestrator] Контроль качества...")
    try:
        ok, questions, issues = quality_check(all_results)
    except Exception as e:
        print(f"[orchestrator] quality_check упал: {e}")
        ok, questions, issues = True, "", str(e)

    parts = []
    for r in all_results:
        if r.get("text") or r.get("error"):
            m = r.get("model", "?")
            b = r.get("block", "?")
            t = r.get("text", r.get("error", "нет ответа"))[:4000]
            parts.append("--- " + m + " (блок " + b + ") ---\n" + t)
    final_text = "\n\n".join(parts)

    if not ok and questions:
        print("[orchestrator] Доработка (вопросы -> Kimi)")
        rework_prompt = final_text[:12000] + "\n\nВопросы дирижёра для доработки:\n" + questions + "\n\nДай финальные правки: что нужно исправить в выводах?"
        try:
            r = call_openai("kimi-k3", rework_prompt, max_tokens=MAX_TOKENS)
            if r["text"]:
                final_text += "\n\n--- ДОРАБОТКА (kimi-k3) ---\n" + r["text"]
        except Exception as e:
            print(f"[orchestrator] Доработка не удалась: {e}")
            final_text += "\n\n--- ВОПРОСЫ ДИРИЖЁРА ---\n" + questions + "\n\n" + issues

    # Финальный вердикт дирижёра (дедупликация + учёт разбивки)
    print("[orchestrator] Финальный вердикт (DeepSeek)...")
    verdict = final_verdict(all_results, len(code))
    if not verdict:
        print("[orchestrator] Финальный вердикт через fallback conductor...")
        verdict = final_verdict(all_results, len(code), model=ORCHESTRATOR_FALLBACK)
    if verdict:
        final_text = verdict + "\n\n===== СЫРЫЕ ОТВЕТЫ МОДЕЛЕЙ =====\n\n" + final_text

    elapsed = time.time() - start
    return {
        "report": final_text,
        "quality_ok": ok,
        "questions": questions,
        "issues": issues,
        "blocks": len(blocks),
        "elapsed_sec": round(elapsed, 1),
        "estimate_min": estimate_audit_minutes(len(code)),
    }
