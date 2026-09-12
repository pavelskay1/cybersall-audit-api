# HANDOFF — Cybersall AI Agent (audit-api)

**Обновлено:** 12.09.2026 | **Сервер:** 195.19.202.106 | **Папка:** /opt/audit-api

## Статус

- FastAPI (uvicorn, 127.0.0.1:8000, systemd `audit-api`), nginx: лендинг + прокси
- Docker sandbox: изоляция вредоносного кода
- Оркестратор v2: Claude Opus 5 → GPT-6-Astra (fallback DeepSeek V4 Flash) → Kimi K3, дирижёр DeepSeek V4 Flash
  - `_file_index()`: блоки получают список функций полного файла (борьба с ложными «функция отсутствует»)
  - `final_verdict()`: DeepSeek дедуплицирует, отсекает ложные, группирует P0/P1/P2 с учётом разбивки
  - `estimate_audit_minutes()`: честная оценка ≈6 мин/блок + ~4 мин за каждый следующий

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

## Контракт CYB (v2, готов к деплою)

- Локально: `cybersall-token/` (hardhat), 18/18 тестов
- Изменения v2: transfer fee 1.5% → казначейство; OTP привязан к получателю+сумме; cap MAX_TOTAL_SUPPLY (10M); mintToTreasury («минт как пополнение»); useForService вместо burn; receive() revert; anti-whale удалён; rescueTokens/rescueAvax; свой nonReentrant (OZ 5.6 guard несовместим с прокси)
- Деплой: `TREASURY=<адрес> npx hardhat run scripts/deploy.js --network avalanche`
- Газ на деплой: ~0.59 AVAX на кошельке достаточно (~1-2$)

## Безопасность

- Токены/ключи в чат НЕ выводить, только пути (chmod 600)
- `.gitignore` исключает `secret/`, `logs/`, `reports/`, `*.bak*`
- Первый сервер (195.19.12.98, /opt/tinvest-system, /opt/crypto-system) — НЕ трогать, только смотреть

## TODO

- [ ] Перезапустить аудит контракта через новый оркестратор (точность)
- [ ] Деплой контракта CYB на Avalanche C-Chain
- [ ] Подставить адрес контракта в `secret/treasury.json`
- [ ] Push на GitHub (ветка `cybersall-audit-api`)
- [ ] HTTPS-домен для продакшена
