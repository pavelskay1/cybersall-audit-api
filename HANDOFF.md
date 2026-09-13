# HANDOFF — Cybersall AI Agent (audit-api)

**Обновлено:** 13.09.2026 | **Сервер:** 195.19.202.106 | **Папка:** /opt/audit-api

## Статус

- FastAPI (uvicorn, 127.0.0.1:8000, systemd `audit-api`), nginx: лендинг + прокси
- Docker sandbox: изоляция вредоносного кода
- Оркестратор v2.2: Claude Opus 5 → GPT-6-Astra (fallback DeepSeek V4.1 Flash) → Kimi K3, дирижёр DeepSeek V4.1 Flash (1M ctx)
  - `split_into_blocks()`: fast-path — код ≤16000 символов аудируется одним блоком без LLM-сплиттера (было: 4 блока на 30 строк → 11 мин; стало 1 блок → ~3.5 мин)
  - Страховка сплиттера: `_merge_small_blocks()` склеивает блоки <8000 символов, лимит MAX_BLOCKS=16, иначе `_fallback_blocks()` режет по символам
  - `_file_index()`: блоки получают список функций полного файла (борьба с ложными «функция отсутствует»)
  - `final_verdict()`: DeepSeek дедуплицирует, отсекает ложные, группирует P0/P1/P2; для 1 блока промпт без «проблемы разбивки»
  - `estimate_audit_minutes()`: честная оценка ≈4–5 мин первый блок + ~3 мин каждый следующий (факт 13.09: 1 блок 215с, 4 блока 648с)

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
- [ ] Push на GitHub (ветка `cybersall-audit-api`)
- [ ] HTTPS-домен для продакшена
- [x] Закрыть/ограничить `/api/auth/create` (free + лимит 5/сутки/IP; pro/enterprise только через X-Admin-Key)
