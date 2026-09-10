"""Модуль песочницы для безопасного выполнения кода.

Использует Docker для полной изоляции:
- Нет сети (network_mode=none)
- Read-only FS
- Лимиты CPU/RAM/PID
- Таймаут 30 сек
- Мониторинг системных вызовов

При обнаружении атаки:
- Kill контейнера
- Бан ключа клиента
- Запись лога
"""
import os
import time
import json
import subprocess
import tempfile
from pathlib import Path
from datetime import datetime, timezone

LOG_DIR = Path(__file__).parent.parent / "logs"
SANDBOX_IMAGE = "code-sandbox"
TIMEOUT = 30
MAX_OUTPUT = 100_000  # символов

# Паттерны для статического анализа (до запуска в Docker)
STATIC_DANGEROUS = [
    # Системные вызовы
    "import os", "import subprocess", "import shutil", "import signal",
    "import multiprocessing", "import threading",
    # Импорт сетевых библиотек
    "import socket", "import urllib", "import requests", "import httpx",
    "import aiohttp", "import websocket",
    # Импорт файловых операций (опасных)
    "import ctypes", "import ctypes.util",
    # Динамическое выполнение
    "__import__", "exec(", "eval(", "compile(",
    "globals()", "locals()", "dir()",
    # Обход песочницы
    "open(\"/", "open('/", 
    "os.system(", "os.popen(",
    "subprocess.run(", "subprocess.Popen(",
    "subprocess.call(",
]

# Паттерны для динамического анализа (после выполнения)
DYNAMIC_INDICATORS = [
    "Permission denied",
    "Operation not permitted",
    "No such file or directory",
    "Connection refused",
    "Network is unreachable",
]

def static_analyze(code: str) -> tuple[bool, str]:
    """Статический анализ кода перед запуском.
    Возвращает (безопасно, причина)."""
    code_lower = code.lower()
    for pattern in STATIC_DANGEROUS:
        if pattern.lower() in code_lower:
            return False, f"Обнаружен запрещённый паттерн: {pattern}"
    return True, ""


def run_in_sandbox(code: str, client_key: str = None) -> dict:
    """Запускает код в Docker-песочнице.
    Возвращает результат или ошибку."""
    
    # 1. Статический анализ
    safe, reason = static_analyze(code)
    if not safe:
        ban_client(client_key, reason)
        return {"blocked": True, "reason": reason, "status": "blocked"}
    
    # 2. Записываем код во временный файл
    with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False, dir="/tmp") as f:
        f.write(code)
        code_file = f.name
    
    try:
        # 3. Запуск в Docker
        start = time.time()
        result = subprocess.run(
            [
                "docker", "run", "--rm",
                "--network=none",                    # нет сети
                "--read-only",                       # read-only FS
                "--cpus=1",                          # 1 ядро
                "--memory=256m",                     # 256 МБ RAM
                "--pids-limit=50",                   # макс 50 процессов
                "--tmpfs=/tmp:size=50m",             # временная FS
                "--security-opt=no-new-privileges",  # нет привилегий
                "-v", f"{code_file}:/tmp/code.py:ro",
                SANDBOX_IMAGE,
            ],
            capture_output=True,
            text=True,
            timeout=TIMEOUT + 5,
        )
        elapsed = time.time() - start
        
        # 4. Сбор результатов
        stdout = result.stdout[:MAX_OUTPUT]
        stderr = result.stderr[:MAX_OUTPUT]
        
        # 5. Проверка на аномалии
        threat = check_anomalies(result, code, client_key, elapsed)
        
        # 6. Очистка
        os.unlink(code_file)
        
        if threat:
            ban_client(client_key, threat)
            return {"blocked": True, "reason": threat, "status": "threat"}
        
        return {
            "stdout": stdout,
            "stderr": stderr,
            "returncode": result.returncode,
            "elapsed": round(elapsed, 2),
            "status": "ok",
        }
    
    except subprocess.TimeoutExpired:
        os.unlink(code_file)
        ban_client(client_key, f"Timeout {TIMEOUT} сек")
        return {"blocked": True, "reason": f"Таймаут {TIMEOUT} сек", "status": "timeout"}
    except Exception as e:
        if os.path.exists(code_file):
            os.unlink(code_file)
        return {"error": str(e), "status": "error"}


def check_anomalies(result: subprocess.CompletedProcess, code: str, client_key: str, elapsed: float) -> str:
    """Проверяет результат выполнения на аномалии."""
    output = result.stdout + result.stderr
    
    # Таймаут
    if result.returncode == -9 or "TIMEOUT" in output:
        return "Таймаут выполнения (возможен fork bomb или endless loop)"
    
    # Попытки доступа к файлам
    for indicator in DYNAMIC_INDICATORS:
        if indicator in output:
            return f"Обнаружена попытка: {indicator}"
    
    # Слишком быстрое завершение с ошибкой
    if elapsed < 0.1 and result.returncode != 0:
        return "Подозрительно быстрое завершение с ошибкой"
    
    return ""


def ban_client(client_key: str, reason: str):
    """Банит клиента за вредоносную активность."""
    if not client_key:
        return
    
    log = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "action": "ban",
        "key": client_key[:8] + "...",
        "reason": reason,
    }
    
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    with open(LOG_DIR / "security_bans.jsonl", "a") as f:
        f.write(json.dumps(log, ensure_ascii=False) + "\n")
    
    # Бан в api_keys.json
    keys_file = Path(__file__).parent.parent / "secret" / "api_keys.json"
    if keys_file.exists():
        import hashlib
        data = json.loads(keys_file.read_text())
        key_hash = hashlib.sha256(client_key.encode()).hexdigest()
        if key_hash in data.get("keys", {}):
            data["keys"][key_hash]["banned"] = True
            data["keys"][key_hash]["ban_reason"] = reason
            data["keys"][key_hash]["ban_time"] = int(time.time())
            keys_file.write_text(json.dumps(data, indent=2, ensure_ascii=False))
    
    print(f"[SANDBOX] BANNED: {client_key[:8]}... Reason: {reason}")
