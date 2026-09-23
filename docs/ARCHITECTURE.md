# Архитектура cybersall: взаимодействие блоков и синхронизация с LLM

Документ описывает, как устроена система cybersall (FastAPI-сервис на S2,
`/opt/audit-api`), как её блоки взаимодействуют между собой и как синхронизируются
с внешними LLM через clodex.xyz. Включает email/SMTP-подсистему доставки отчётов.

---

## 1. Общая схема потока

```
Клиент (HTTP/HTTPS, X-API-Key)
   │
   ▼
┌────────────────────────── main.py (FastAPI, 10 эндпоинтов) ──────────────────────────┐
│  /api/audit          /api/audit/file    /api/audit/ensemble    /api/audit/email      │
│  /api/run (Docker-песочница)            /api/convert           /api/convert/email    │
│  /api/models         /api/auth/create   /api/partner/stats     /api/auth/balance     │
└──────┬──────────────────────┬──────────────────────┬───────────────────┬─────────────┘
       │ auth (ключ/лимиты)   │ orchestrator          │ converter         │ email_sender
       ▼                      ▼                      ▼                   ▼
┌───────────────┐   ┌────────────────────────┐   ┌────────────────┐  ┌──────────────────┐
│  secret/      │   │  split_into_blocks     │   │ Claude→GPT→Kimi │  │ SMTP mail.ru     │
│  api_keys.json│   │  → run_stage (xN)      │   │ конверсия Py→C++│  │ (SSL 465),       │
│  partners.json│   │  → quality_check       │   │ (с fallback)    │  │ PDF-вложение     │
│  limits/...   │   │  → rework / final_verdict│                    │  │ secret/mail.txt  │
└───────────────┘   └──────────┬─────────────┘   └────────────────┘  └──────────────────┘
                               │ clodex_client (call_openai / call_anthropic)
                               ▼
                 ┌───────────────────────────────┐
                 │  clodex.xyz/v1/chat/completions │  ← OpenAI-формат
                 │  clodex.xyz/v1/messages         │  ← Anthropic-формат
                 └───────────────────────────────┘
                     (CLODEX_API_KEY из secret/.clodex_key)
```

Все пути, по которым код/ответы попадают в промпты LLM, проходят через
**два обязательных фильтра**: `sanitizer.sanitize()` (утечка секретов) и
`harden.harden_code()` (промт-инъекции).

---

## 2. Блоки системы и их обязанности

| Модуль | Роль | Что делает |
|---|---|---|
| `main.py` | HTTP-шлюз | Принимает запросы, проверяет ключ/лимиты (auth), дозирует I/O через `asyncio.to_thread`, пишет отчёты и шаблоны в `reports/` |
| `auth.py` | Безопасность доступа | SHA-256-хэши ключей в `secret/api_keys.json`, планы free/pro/enterprise (3/30/200 запросов в день), лимит создания free-ключей 5/IP/сутки, партнёры и выплаты (50/50, `partners.json`) |
| `orchestrator.py` | Ядро аудита | Разбивает код на блоки, гоняет 3 стадии ансамбля, контролирует качество, собирает финальный вердикт и шаблон исправленного кода |
| `chunker.py` | Разбиение кода | Символьный сплит на логические блоки (def/class/import), ≤15 КБ на блок; для больших файлов оркестратор задействует LLM-сплиттер |
| `sanitizer.py` | Анти-утечка | Маскирует PEM-ключи, ssh, крипто-адреса, AWS/OpenAI/Bearer-токены, api_key/secret/token/password, email, телефоны ДО отправки в LLM |
| `harden.py` | Промт-инъекции | Нейтрализует «закрывающие якоря» (`ignore previous`, `[INST]`, `<|im_start|>`, `role:"system"`), guard на тройные backticks, трипваир исполнения инъекций |
| `clodex_client.py` | Транспорт в LLM | Единый клиент OpenAI/Anthropic форматов, логирование запросов в `logs/audit_runs.jsonl`, обработка пустых ответов reasoning-моделей |
| `converter.py` | Python→C++ | Цепочка Claude (перевод) → GPT-6-Astra (оптимизация) → Kimi K3 (ревью), тот же `clodex_client` |
| `email_sender.py` | Доставка отчётов | Отправка HTML+PDF через SMTP mail.ru (SSL 465), пароль из `secret/mail.txt` |
| `pdf_report.py` | Рендеринг | Генерация PDF-отчёта (fpdf, DejaVu) для email-доставки |
| `sandbox.py` | Исполнение | `/api/run`: стат-анализ → Docker (gVisor, --network=none, honeypot-директория) → динамический анализ → бан |

---

## 3. Синхронизация между блоками: конвейер аудита (`audit_full`)

`audit_full(code, question)` в `orchestrator.py:429` — главный сценарий. Стадии идут
**строго последовательно** (передача находок по цепочке), блоки внутри стадии —
**параллельно** (ThreadPoolExecutor, `STAGE_WORKERS=4`).

### Этапы и их модели

| Стадия | Роль | Основная модель | Fallback | max_tokens |
|---|---|---|---|---|
| Split | Разбиение на блоки | deepseek-v4.1-flash (дирижёр) | v4-pro → claude-opus-5 → kimi-k3 → символьная нарезка `_fallback_blocks` | 10000 |
| 1. primary | Первичный аудит | claude-opus-5 | kimi-k3 | 16000 |
| 2. deep | Глубина/межпроцедурный анализ | gpt-6-astra | deepseek-v4.1-flash | 16000 |
| 3. final | Кросс-проверка/додумывание | kimi-k3 | deepseek-v4-pro | 16000 |
| Quality check | Оценка качества аудита | deepseek-v4.1-flash | v4-pro → claude-opus-5 → kimi-k3 | 4000→12000 |
| Rework | Доработка по вопросам дирижёра | kimi-k3 | — | 16000 |
| Final verdict | Дедупликация + шаблон кода | deepseek-v4.1-flash | deepseek-v4-pro | 16000→32000 |

### Какие данные передаются между стадиями

- **Block → run_stage**: `name`, `code` (санитизирован + harden), `context`
  (индекс функций файла + контекст сплиттера), `focus`.
- **Этап N-1 → Этап N**: `previous_results` — находки ПРЕДЫДУЩИХ моделей по
  **тому же блоку**. Ключевой момент синхронизации: результаты **фильтруются**
  (`P1-4`) — в историю не попадают пустые `error`-ответы, и каждый блок получает
  только свою историю (`r.get("block") == bname and r.get("text")`), экранированную
  `harden_code` (P1-2), чтобы отравленный вывод этапа N не мог инжектить инструкции
  в промпт этапа N+1.
- **Все результаты → quality_check**: объединённый текст ответов (до 2000 символов
  на ответ) + `source_code` (до `MAX_TEMPLATE_SOURCE=50000` с маркером усечения).
  Дирижёр сверяет полноту/достоверность/консистентность, а **не** наличие багов.
- **Quality → main**: `quality_ok` (bool), `questions` (для rework), `issues`
  (включая `INJECTION-TRIPWIRE` — если модель «послушалась» код, трипваир
  срабатывает в `main.py` → `count_injection_attempt` → 403 + бан ключа).
- **Плохое качество → rework**: если `quality_ok=False` и есть `questions`,
  итог дорабатывает kimi-k3 (вход — `final_text[:12000]` + вопросы, оба через
  `harden_code`), результат присоединяется к отчёту.
- **⇒ Final verdict**: дедупликация, отсев ложных срабатываний, группировка
  P0/P1/P2, требование «СПИСОК СЛЕДОВАНИЯ» (каждая рекомендация обязана попасть
  в шаблон), генерация секции «ШАБЛОН ИСПРАВЛЕННОГО КОДА» (точечно правленный
  оригинал, не переписывание) на основе `source_code`.
- **Verdict → extract_template** (`orchestrator.py:402`): программное извлечение
  шаблона из отчёта (по секции; fallback — последний ```` ``` ````-блок ≥
  `MIN_TEMPLATE_LEN=1000`; ZWSP очищается).
- **audit_full → main.py**: `report`, `quality_ok`, `questions`, `issues`, `blocks`,
  `elapsed_sec`, `estimate_min`, `template_code`. main.py сохраняет отчёт в
  `reports/ensemble_<id>.txt`, шаблон — в `reports/ensemble_<id>.template.txt`
  (расширение **не** `.py` — файл приходит от LLM и не должен быть исполняемым).

### Программа-максимум времени (estimate)

`estimate_audit_minutes` (`:42`) честно учитывает параллелизм: 3 последовательных
этапа, каждый длится `per_block × ceil(blocks/STAGE_WORKERS)` секунд, плюс
split/quality/rework. Используется на лендинге/таймере.

---

## 4. Синхронизация с LLM (clodex_client)

- **Один ключ** на все модели: `CLODEX_API_KEY` в env или `secret/.clodex_key`.
- **Два протокола**: OpenAI (`/v1/chat/completions`) для большинства,
  Anthropic (`/v1/messages`) для `claude-*` (включая `call_anthropic`).
- **Реестр моделей** `MODELS` (`:19`): glm-5.2, gpt-6-astra, gpt-5.5,
  deepseek-v4-pro/flash/v4.1-flash, claude-opus-5, gemini-3.8-flash, grok-4.6,
  kimi-k3, qwen3.8-max.
- **Перед отправкой**: `sanitize(code)` + `harden_code(code)` + `harden_question(q)`.
  В логи `audit_runs.jsonl` попадает только санитизированный question.
- **Пустые ответы**: reasoning-модели (deepseek-v4.1-flash) могут вернуть пустой
  `content` — клиент падает с ошибкой «Пустой ответ», а `run_stage`/`quality_check`/
  `final_verdict` сами ретраят с увеличенным `max_tokens`, затем уходят на fallback.
- **Логирование**: каждая успешная модель пишет в `logs/audit_runs.jsonl`
  (ts, model, question-stage, prompt/completion tokens, elapsed) — на эти данные
  опирается `/api/partner/stats` (p2-фикс: сравнение `key_hash[:8]`).

---

## 5. Инъекции и трипваир (гард всей синхронизации)

1. `harden_code` — якоря инъекций становятся инертными (`ign0re prev10us`),
   тройные backticks в коде заменяются на ZWSP-версию (не могут закрыть фенс).
2. `quality_check` / `final_verdict` получают ответы моделей как **данные**,
   а история между стадиями экранируется.
3. `INJECTION_TRIPWIRE` (harden.py): если модель написала «игнорирую предыдущие
   инструкции» / «выполняю инструкции из кода» — quality_check возвращает False
   с маркером `INJECTION-TRIPWIRE`, main.py блокирует ключ (403) при повторении.

---

## 6. Почта / SMTP (email_sender.py)

- **SMTP**: `smtp.mail.ru:465` (SSL), отправитель `luxset@mail.ru`, получатель по
  умолчанию `309303@mail.ru`. Пароль — `secret/mail.txt` (не в репозитории).
- **Куда интегрирована**: эндпоинты `/api/audit/email` и `/api/convert/email`
  в `main.py:324` и `:383`.
- **Поток**: аудит/конвертация → генерация HTML-тела (`html_mod.escape` первых
  5000 символов) → `pdf_report.generate_audit_report` (PDF-вложение)
  → `send_report(email, subject, body_html, pdf_bytes, filename)` →
  `MIMEMultipart` + base64 PDF → `SMTP_SSL` + login + `send_message`.
- **Ошибки**: SMTP-исключения ловятся, возвращается `sent=False` (HTTP-ответ
  200 с флагом), пароль из файла не логируется.
- **Фиксы аудита (main.py)**: email-адрес валидируется `_validate_email`
  (regex до отправки — защита от инъекции в SMTP-заголовки); tripwire-контроль
  в `/api/audit/email` теперь такой же, как в `/api/audit/ensemble`
  (раньше пропускался — P1-1).

---

## 7. Секреты и файловая структура (не в git)

```
/opt/audit-api/
├── app/            # код (main, orchestrator, sanitizer, harden, clodex_client, ...)
├── secret/         # HЕ в git: api_keys.json, partners.json, admin_key.txt,
│                   #   mail.txt (SMTP-пароль), .clodex_key, create_limits.json
├── reports/        # ensemble_<id>.txt и ensemble_<id>.template.txt (отчёты+шаблоны)
└── logs/           # audit_runs.jsonl, security_bans.jsonl, cleanup.log
```

Все артефакты в `secret/` исключены из git; `template_code` пишется с расширением
`.template.txt`, чтобы файл от LLM никогда не стал исполняемым `.py`.

---

## 8. Ключевые параметры синхронизации (app/orchestrator.py)

| Параметр | Значение | Смысл |
|---|---|---|
| `MAX_BLOCK_CHARS` | 16000 | Макс. размер блока для аудита |
| `MAX_TOKENS` | 16000 | Max выходной лимит на один вызов модели |
| `MAX_BLOCKS` | 16 | Страховка от «дробилки» сплиттера |
| `MIN_BLOCK_CHARS` | 8000 | Ниже этого блок склеивается с соседним |
| `MAX_TEMPLATE_SOURCE` | 50000 | Единый cap на исходник для quality/verdict |
| `MIN_TEMPLATE_LEN` | 1000 | Мин. длина шаблона для fallback-экстракции |
| `STAGE_WORKERS` | 4 | Параллельных воркеров внутри этапа |
| `AVG_STAGE_SEC` | claude 41с / gpt 140с / kimi 56с | Метрики для оценки времени |