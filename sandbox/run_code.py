"""Безопасный запуск кода в изолированной среде."""
import sys
import os
import signal
import time

TIMEOUT = 30  # секунд

def timeout_handler(signum, frame):
    print("TIMEOUT: Код выполнялся слишком долго", file=sys.stderr)
    sys.exit(1)

signal.signal(signal.SIGALRM, timeout_handler)
signal.alarm(TIMEOUT)

code_file = sys.argv[1] if len(sys.argv) > 1 else "/tmp/code.py"

try:
    with open(code_file, "r") as f:
        code = f.read()
    
    # Запрещённые паттерны
    dangerous = [
        "import os", "import subprocess", "import shutil",
        "__import__", "exec(", "eval(", "compile(",
        "open(", "os.", "sys.", "subprocess.",
        "socket.", "urllib.", "requests.", "httpx.",
        "import socket", "import urllib", "import requests", "import httpx",
    ]
    
    for pattern in dangerous:
        if pattern in code:
            print(f"BLOCKED: Обнаружен запрещённый паттерн: {pattern}", file=sys.stderr)
            sys.exit(2)
    
    # Запуск кода
    exec(code, {"__builtins__": __builtins__})
    
except Exception as e:
    print(f"ERROR: {type(e).__name__}: {e}", file=sys.stderr)
    sys.exit(1)
