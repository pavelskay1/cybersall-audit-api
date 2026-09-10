"""Модуль разбиения кода на логические блоки для аудита.

Автоматически разбивает код по:
- Функциям (def)
- Классам (class)
- Модулям (import blocks)
- Строкам (если нет структуры)

Каждый блок ≤ MAX_BLOCK_SIZE символов.
"""
import re
from pathlib import Path

MAX_BLOCK_SIZE = 15000  # символов на блок
MIN_BLOCK_SIZE = 200    # не создавать блоки меньше этого

# Паттерны для разбиения
FUNC_PATTERN = re.compile(r"^(def\s+\w+|class\s+\w+)", re.MULTILINE)
IMPORT_PATTERN = re.compile(r"^(import\s|from\s)", re.MULTILINE)


def split_code(code: str) -> list[dict]:
    """Разбивает код на логические блоки.
    Возвращает список: [{"name": "...", "code": "...", "line_start": N}, ...]"""
    
    if len(code) <= MAX_BLOCK_SIZE:
        return [{"name": "full_code", "code": code, "line_start": 1}]
    
    lines = code.split("\n")
    blocks = []
    current_block = []
    current_start = 1
    current_name = "header"
    
    for i, line in enumerate(lines):
        current_block.append(line)
        current_text = "\n".join(current_block)
        
        # Проверяем границу блока
        if len(current_text) > MAX_BLOCK_SIZE:
            # Ищем последний def/class в блоке для разреза
            split_point = find_split_point(current_block)
            
            if split_point > 0:
                # Разрезаем
                good_lines = current_block[:split_point]
                remaining_lines = current_block[split_point:]
                
                if good_lines:
                    block_text = "\n".join(good_lines)
                    block_name = extract_name(good_lines) or f"block_{len(blocks)+1}"
                    blocks.append({"name": block_name, "code": block_text, "line_start": current_start})
                
                current_block = remaining_lines
                current_start = current_start + split_point
            else:
                # Не нашли хорошую точку разреза — режем принудительно
                block_text = "\n".join(current_block[:len(current_block)//2])
                blocks.append({"name": f"block_{len(blocks)+1}", "code": block_text, "line_start": current_start})
                current_block = current_block[len(current_block)//2:]
                current_start = current_start + len(current_block)//2
    
    # Последний блок
    if current_block:
        block_text = "\n".join(current_block)
        if len(block_text) > MIN_BLOCK_SIZE:
            block_name = extract_name(current_block) or f"block_{len(blocks)+1}"
            blocks.append({"name": block_name, "code": block_text, "line_start": current_start})
    
    return blocks if blocks else [{"name": "full_code", "code": code[:MAX_BLOCK_SIZE], "line_start": 1}]


def find_split_point(lines: list[str]) -> int:
    """Ищет последний def/class перед превышением лимита."""
    last_good = -1
    for i, line in enumerate(lines):
        stripped = line.strip()
        if stripped.startswith("def ") or stripped.startswith("class "):
            last_good = i
    return last_good if last_good > 0 else -1


def extract_name(lines: list[str]) -> str:
    """Извлекает имя функции/класса из строк."""
    for line in lines:
        m = re.match(r"^(def|class)\s+(\w+)", line.strip())
        if m:
            return m.group(2)
    return ""


def estimate_time(blocks: list[dict]) -> int:
    """Оценивает время обработки в секундах."""
    # ~15 сек на блок для одной модели
    # ~60 сек на блок для кросс-валидации
    return len(blocks) * 15
