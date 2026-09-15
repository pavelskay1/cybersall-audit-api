# Интеграция Cybersall AI Agent с GitHub Actions

Автоматический AI-аудит кода при каждом пуше и pull request.

## Как подключить (2 шага)

### Шаг 1: Получить API-ключ

- Бесплатный: `POST /api/auth/create?plan=free` — 3 аудита/день
- Pro: `POST /api/auth/create?plan=pro` — 30 аудитов/день ($49/мес)
- Enterprise: `POST /api/auth/create?plan=enterprise` — 200 аудитов/день ($499/мес)

### Шаг 2: Добавить два файла

1. **`.github/workflows/cybersall-audit.yml`** — из `ci/cybersall-audit.yml` этого репозитория

2. **Секрет в GitHub**: Settings → Secrets and variables → Actions → New repository secret
   - Name: `CYBERSALL_API_KEY`
   - Value: ваш API-ключ

## Что происходит

```
Push / Pull Request
      │
      ▼
GitHub Actions (ubuntu-latest)
      │
      ├─ Проверка изменённых файлов (py, js, ts, cpp, c, sol, rs, go, java)
      │
      ├─ Кодирование файлов в base64
      │
      ├─ POST /api/audit (прямое соединение, без посредников)
      │
      ├─ Результат → PR comment:
      │     🟢 критических проблем не найдено
      │     🔴 найдены P0/P1 → блокировка merge
      │
      └─ Отчёт с описанием проблем и рекомендациями
```

## Конфигурация

| Параметр | По умолчанию | Описание |
|----------|-------------|----------|
| Модель | `claude-opus-5` | Изменить на `ensemble` для полного ансамбля |
| Расширения | `py, js, ts, cpp, c, sol, rs, go, java` | Отредактировать в workflow |
| Max файл | 500KB | Файлы больше пропускаются |
| Max файлов | 20 | Первые 20 изменённых файлов |

## Безопасность

- Код передаётся напрямую GitHub Runner → наш сервер (base64)
- Никаких посредников (Zapier и т.п.)
- Код не хранится на нашем сервере (удаление после 7 дней)
- API-ключ хранится в GitHub Secrets (шифруется)
- Все запросы санитизируются (секреты удаляются до анализа)

## Планы

| План | Запросов/день | Цена | Для кого |
|------|--------------|------|----------|
| **Lite** | 3 | Вход от 1 запроса | Одиночные разработчики |
| **Pro** | 30 | от $49 | Команды до 10 чел |
| **Enterprise** | 200 | $499 | Компании, on-premise |

## Поддержка

- Telegram/email: cybersall@proton.me (placeholder)
- Отчёты о найденных проблемах: считаем по каждому PR
