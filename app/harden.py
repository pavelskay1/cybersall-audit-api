"""Промт-инъекционная защита данных на всех путях в LLM.

Принцип: НЕ удаляем подозрительные фразы (аудитор должен их видеть и флагать),
а нейтрализуем разрыв роли — «закрывающие якоря» становятся инертным текстом,
контент остаётся анализируемым.
"""
import re

# "Закрывающие якоря" позволяют содержимому кода выйти за пределы роли данных
# и подсунуть модели инструкции.
INJECTION_ANCHORS = [
    ("ignore all previous instructions", "ign0re all prev10us instructions"),
    ("ignore previous instructions", "ign0re prev10us instructions"),
    ("ignore all instructions", "ign0re all instructions"),
    ("ignore the system", "ignore the s2stem"),
    ("forget all previous", "f0rget all prev10us"),
    ("<|im_start|>", "<|lm_start|>"),
    ("<|im_end|>", "<|lm_end|>"),
    ("<<SYS>>", "<_SYS_>"),
    ("</SYS>", "<_/SYS_>"),
    ("[INST]", "[lNST]"),
    ("[/INST]", "[/lNST]"),
    ('"role": "system"', '"r0le": "system"'),
    ('"role": "assistant"', '"r0le": "assistant"'),
    ("role: system", "r0le: system"),
    ("<s>", "<0s>"),
    ("</s>", "</0s>"),
]

# Тройные обратные кавычки внутри кода могут закрыть markdown-фенс блока данных
# раньше времени и вынести текст за его пределы (исполнение инъекции).
CODE_FENCE_GUARD = "\u200b"

# Фразы, по которым в выводах моделей распознаётся исполнение инструкций из кода
# (модель "послушалась" — трипваир срабатывает в quality_check).
INJECTION_TRIPWIRE = [
    "игнорирую предыдущие инструкции",
    "игнорирую все предыдущие инструкции",
    "ignore previous instructions",
    "понял, игнорирую",
    "следую инструкциям из кода",
    "выполняю инструкции из кода",
    "по инструкции из кода",
]


def harden_code(code: str) -> str:
    """Нейтрализует якоря промт-инъекции в коде перед вставкой в промт.

    Структура: роль данных не может смениться (фенс и role-маркеры инертны),
    но контент остаётся видимым аудитору — подозрительные фразы лишь искажены,
    не удалены.
    """
    if not code:
        return code
    code = code.replace("```", "`" + CODE_FENCE_GUARD + "`" + CODE_FENCE_GUARD + "`")
    for src, dst in INJECTION_ANCHORS:
        code = code.replace(src, dst)
    return code


def harden_question(question: str) -> str:
    """Экранирует вопрос клиента (передаётся в промт как задание, но не как роль).

    Плюс удаляет потенциально опасные zero-width/управляющие символы.
    """
    if not question:
        return question
    q = harden_code(question)
    q = re.sub(r"[\u200b\u200c\u200d\u2060\ufeff]", "", q)
    return q


def tripwire_hits(text: str) -> list:
    """Возвращает список сработавших трипваиров исполнения инъекции в тексте."""
    if not text:
        return []
    low = text.lower()
    return [p for p in INJECTION_TRIPWIRE if p.lower() in low]