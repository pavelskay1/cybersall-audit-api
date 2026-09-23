# HANDOFF — Cybersall AI Agent (audit-api)

**Обновлено:** 23.09.2026 (релиз: полный LLM-аудит всех модулей + деплой) | **Сервер:** 195.19.202.106 | **Папка:** /opt/audit-api

## Статус

- FastAPI (uvicorn, 127.0.0.1:8000, systemd `audit-api`), nginx: лендинг + прокси
- Docker sandbox: изоляция вредоносного кода
- Оркестратор v2.2: Claude Opus 5 → GPT-6-Astra (fallback DeepSeek V4.1 Flash) → Kimi K3, дирижёр DeepSeek V4.1 Flash (1M ctx)
  - `split_into_blocks()`: fast-path — код ≤16000 символов аудируется одним блоком без LLM-сплиттера (было: 4 блока на 30 строк → 11 мин; стало 1 блок → ~3.5 мин)
  - Страховка сплиттера: `_merge_small_blocks()` склеивает блоки <8000 символов, лимит MAX_BLOCKS=16, иначе `_fallback_blocks()` режет по символам
  - `_file_index()`: блоки получают список функций полного файла (борьба с ложными «функция отсутствует»)
  - `final_verdict()`: DeepSeek дедуплицирует, отсекает ложные, группирует P0/P1/P2; для 1 блока промпт без «проблемы разбивки»
  - `estimate_audit_minutes()`: честная оценка ≈4–5 мин первый блок + ~3 мин каждый следующий (факт 13.09: 1 блок 215с, 4 блока 648с)
- **Релиз 23.09.2026** (после LLM-аудита всех модулей через /api/audit/ensemble):
  - `orchestrator.py`: универсальный fallback для всех стадий (claude-opus-5→kimi-k3, gpt-6-astra→deepseek-v4.1-flash, kimi-k3→deepseek-v4-pro), fail-closed quality_check (P0-3), `_fallback_blocks` при отказе сплиттеров (P0-1), harden_code на history/rework_prompt (P1-2), фильтр пустых previous (P1-4), защита fut.result() (P1-5), единый cap MAX_TEMPLATE_SOURCE=50000 (P1-1), extract_template с ZWSP/мин-длиной (P1-3), параллелизм STAGE_WORKERS=4, честный estimate (P2-1/P2-3); `template_code` выдаётся в ответ и сохраняется в reports/ensemble_*.template.txt
  - `sanitizer.py`: фикс утечки PKCS#8 PEM (обратная ссылка \1 → незахватывающие группы), маскировка оборванных PEM, ssh-паттерн не ест кавычки/скобки строковых литералов, голые значения не маскируют переменные-идентификаторы (api_key = api_key больше не ломается в NameError)
  - `main.py`: фиксы P0-1 (HTTPException 413 без headers-аргумента), P0-2 (path traversal через model → `_validate_model`), P1-1 (tripwire-контроль в /api/audit/email), P1-2 (partner stats key_hash[:8]), P1-3 (admin-ключ через hmac.compare_digest), P2-1..P2-7 (asyncio.to_thread, email-валидация `_validate_email`, `template_code` → .template.txt, .get() вместо [], lstrip точек, int() в try)
  - Синхронизировано с продом: все 10 модулей app/ совпадают MD5 1:1; добавлены отсутствовавшие в git `harden.py`, `web3.py`, `honeypot.py`
  - Документация: `docs/ARCHITECTURE.md` (взаимодействие/синхронизация блоков системы и LLM, включая SMTP §6), `docs/CYBERSALL-NOTES-2026-09-23.md`, отчёты аудитов в `docs/`
  - Таг в репозитории: `deploy-20260923_172342`

## Казначейство (mm CLI MetaMask)

- Кошелёк BYOK: `0x4080C22B98E3EDE6Fcd31a3381e79D04d6CAAE84`
- Секреты: `secret/byok_private.txt`, `secret/byok_mnemonic.txt` (chmod 600), `secret/treasury.json`
- Avalanche C-Chain (43114), USDC: `0xB97EF9Ef8734C71904D8002F8b6Bc66Dd9c48a6E`
- Баланс: ~0.590 AVAX + 0.372 USDC (~$4.77). Свап 0.05 AVAX→USDC прошёл
- ВАЖНО: в BYOK-режиме повторные свапы без email-2FA; смена policy требует 2FA (mm под BYOK policy не даёт)

## Команды казначейства

    cd /opt/audit-api
    /opt/audit-api/venv/bin/python3 treasury_cli.py status|balance
    /opt/audit-api/venv/bin/python3 treasury_cli.py quote USDC CYB 10
    /opt/audit-api/venv/bin/python3 treasury_cli.py execute <quote_id>
    /opt/audit-api/venv/bin/python3 treasury_cli.py send 0xADDR 1.5 CYB

## Контракт CYB (v2, ЗАДЕПЛОЕН)

- Proxy (mainnet 43114): `0x9cC9BB843A6B112dec511d53805bf9883DF387e1`
- Implementation: `0xCDfE625b836ba80dB5172f794b27778265550ac2`
- Treasury/owner: BYOK `0x4080C22B98E3EDE6Fcd31a3381e79D04d6CAAE84`, initial supply 1M CYB на казначействе
- Адрес записан в `secret/treasury.json` (cyb_proxy), локально `cybersall-token/` 18/18 тестов; репо GitHub `pavelskay1/cybersall-token`
- v2: transfer fee 1.5% → казначейство; OTP→получатель+сумма; cap 10M; mintToTreasury; useForService вместо burn; receive() revert; anti-whale удалён; rescueTokens/rescueAvax; nonReentrant
- Аудит v3 (наша система, 5 блоков): P0-1 useForService — централизованный owner (осознанный дизайн MVP), P0-2 — ложноположительная (fee не взимается: `to==treasury` exempt)

## Безопасность

- Токены/ключи в чат НЕ выводить, только пути (chmod 600)
- `.gitignore` исключает `secret/`, `logs/`, `reports/`, `*.bak*`
- Дыра /api/auth/create ЗАКРЫТА: free — лимит 5 ключей/сутки/IP; pro/enterprise — только с X-Admin-Key из `secret/admin_key.txt` (chmod 600)
- Первый сервер (195.19.12.98, /opt/tinvest-system, /opt/crypto-system) — НЕ трогать, только смотреть

## TODO

- [x] Деплой контракта CYB на Avalanche C-Chain (proxy 0x9cC9BB843A6B112dec511d53805bf9883DF387e1)
- [x] Адрес контракта в `secret/treasury.json`
- [ ] Перезапустить аудит контракта через новый оркестратор v2.2 (точность)
- [ ] Пересобрать смоук-тест на большом файле (>16000 символов) — проверить лимиты блоков
- [x] Push на GitHub (ветка `cybersall-audit-api`) — релиз 23.09.2026
- [ ] HTTPS-домен для продакшена
- [x] Закрыть/ограничить `/api/auth/create` (free + лимит 5/сутки/IP; pro/enterprise только через X-Admin-Key)
