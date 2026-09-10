FROM python:3.12-slim

# Удаляем ненужные пакеты
RUN apt-get update && apt-get install -y --no-install-recommends     strace     lsof     && rm -rf /var/lib/apt/lists/*

# Создаём непривилегированного пользователя
RUN useradd -m -s /bin/bash sandbox

# Копируем скрипт запуска
COPY run_code.py /run_code.py

# Устанавливаем права
RUN chmod 755 /run_code.py

# Работаем от имени sandbox
USER sandbox

# Рабочая директория
WORKDIR /tmp

# Запуск
CMD ["python3", "/run_code.py"]
