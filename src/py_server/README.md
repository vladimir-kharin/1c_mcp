# MCP-прокси сервер для 1С

## Что это

Прокси-сервер между MCP-клиентами (Claude Desktop, Cursor) и 1С:Предприятие. Транслирует MCP-протокол в JSON-RPC вызовы к HTTP-сервису 1С.

**Возможности:**
- Два режима подключения клиентов: stdio (для нативных клиентов) и HTTP (для веб)
- Проксирование всех MCP-примитивов: Tools, Resources, Prompts
- Опциональная OAuth2 авторизация с per-user креденшилами
- Асинхронная архитектура для множественных подключений

## Быстрый старт

### Требования

- **Python 3.13** (рекомендуется) или 3.11+
- 1С:Предприятие 8.3.20+ с опубликованным HTTP-сервисом

### Установка

```bash
# Создание виртуального окружения
python -m venv venv

# Активация
venv\Scripts\activate  # Windows
source venv/bin/activate  # Linux/Mac

# Установка зависимостей
pip install -r requirements.txt
```

### Выбор режима работы

#### Stdio режим

Для локальных MCP-клиентов (Claude Desktop, Cursor).

Настройки указываются в конфигурации клиента через переменные окружения.

**Минимальная конфигурация клиента:**
```json
{
  "mcpServers": {
    "1c-server": {
      "command": "python",
      "args": ["-m", "src.py_server"],
      "env": {
        "MCP_ONEC_URL": "http://localhost/base",
        "MCP_ONEC_USERNAME": "admin",
        "MCP_ONEC_PASSWORD": "password"
      }
    }
  }
}
```

Примеры конфигураций для разных клиентов: [`../../mcp_client_settings/`](../../mcp_client_settings/)

#### HTTP режим

Для веб-приложений и множественных клиентов.

Настройки указываются в файле `.env` в корне проекта или через переменные окружения:

```bash
# Скопируйте пример
copy src\py_server\env.example .env  # Windows
cp src/py_server/env.example .env    # Linux/Mac
```

**Минимальный .env:**
```ini
MCP_ONEC_URL=http://localhost/base
MCP_ONEC_USERNAME=admin
MCP_ONEC_PASSWORD=password
```

**Запуск:**
```bash
python -m src.py_server http --port 8000
```

### Docker

Запуск в контейнере для изоляции и упрощения развертывания.

**Быстрый старт:**
```bash
# 1. Скопировать конфигурацию
cp .env.docker.example .env

# 2. Отредактировать .env (обязательно: MCP_ONEC_URL, MCP_ONEC_USERNAME, MCP_ONEC_PASSWORD)

# 3. Запустить через docker-compose
docker-compose up -d

# Проверка
curl http://localhost:8000/health
```

**Или напрямую через Docker:**
```bash
# Сборка образа
docker build -t 1c-mcp-proxy .

# Запуск с переменными окружения
docker run -d \
  -p 8000:8000 \
  -e MCP_ONEC_URL=http://host.docker.internal/base \
  -e MCP_ONEC_USERNAME=admin \
  -e MCP_ONEC_PASSWORD=password \
  --name mcp-proxy \
  1c-mcp-proxy
```

**Важно про сеть:**
- Если 1С на **том же хосте**: используйте `host.docker.internal` (Mac/Windows) или IP хоста `172.17.0.1` (Linux) вместо `localhost`
- Если 1С на **другом сервере**: указывайте его реальный адрес как обычно

**Логи:**
```bash
docker-compose logs -f
```

**Остановка:**
```bash
docker-compose down
```

## Режимы работы

### Stdio режим

- Общение через stdin/stdout
- Используется локальными MCP-клиентами
- Логи идут в stderr
- OAuth2 не поддерживается (при `MCP_AUTH_MODE=oauth2` запуск завершится ошибкой)

### HTTP режим

**Endpoints:**
- `/mcp/` - Streamable HTTP транспорт (основной)
- `/sse` - SSE транспорт (устаревший, но поддерживается)
- `/health` - проверка состояния
- `/info` - информация о сервере
- `/` - список endpoints

**Проверка работы:**
```bash
curl http://localhost:8000/health
```

## Режимы авторизации

### Без OAuth2 (по умолчанию)

```bash
MCP_AUTH_MODE=none  # по умолчанию
```

**Поведение:**
- Все обращения к 1С выполняются от одного пользователя
- Креденшилы задаются в конфигурации: `MCP_ONEC_USERNAME` и `MCP_ONEC_PASSWORD`
- Используется Basic Auth для всех запросов к 1С

### С OAuth2

```bash
MCP_AUTH_MODE=oauth2
MCP_PUBLIC_URL=http://your-server:8000
```

**Поведение:**
- OAuth2 доступен только в HTTP режиме (в stdio запуск завершится ошибкой)
- Каждый клиент авторизуется своими креденшилами 1С
- Креденшилы передаются через OAuth2 flow
- `MCP_ONEC_USERNAME` и `MCP_ONEC_PASSWORD` не используются (если заданы, будут проигнорированы)

**Поддерживаемые OAuth2 flows:**
- **Authorization Code + PKCE** - авторизация через HTML-форму
- **Refresh Token** - обновление с ротацией
- **Token Revocation (RFC 7009)** - отзыв токенов при логауте
- **Dynamic Client Registration** - автоматическая регистрация клиентов

**Дополнительные endpoints (для OAuth2):**
- `/.well-known/oauth-protected-resource` - Protected Resource Metadata
- `/.well-known/oauth-authorization-server` - Authorization Server Metadata
- `/register` - регистрация клиентов
- `/authorize` - HTML форма авторизации
- `/token` - получение/обновление токенов

Детали OAuth2: см. раздел "Примеры использования" и `agents.md`

## Конфигурация

Все настройки задаются через переменные окружения с префиксом `MCP_` или через CLI аргументы.

### Подключение к 1С

| Переменная | Описание | По умолчанию | Обязательная |
|------------|----------|--------------|--------------|
| `MCP_ONEC_URL` | URL базы 1С | - | ✅ При `TRANSPORT=http` |
| `MCP_ONEC_USERNAME` | Имя пользователя | - | ✅ При `TRANSPORT=http` и `AUTH_MODE=none` |
| `MCP_ONEC_PASSWORD` | Пароль | - | ✅ При `TRANSPORT=http` и `AUTH_MODE=none` |
| `MCP_ONEC_SERVICE_ROOT` | Корень HTTP-сервиса | `mcp` | ❌ |
| `MCP_ONEC_UNLOCK_CODE` | Код разрешения при блокировке начала сеансов, передаётся как `?uc=` (аналог ключа запуска `/UC`) | - | ❌ |

### Транспорт до 1С

| Переменная | Описание | По умолчанию | Обязательная |
|------------|----------|--------------|--------------|
| `MCP_TRANSPORT` | Транспорт до 1С: `http`, `file` или `httppoll` | `http` | ❌ |
| `MCP_HTTP_TIMEOUT` | Таймаут ожидания ответа 1С при `TRANSPORT=http`, сек | `120` | ❌ |
| `MCP_FILE_EXCHANGE_DIR` | Папка обмена (подпапки `in/` и `out/`): путь или `ftp://user:pass@host/путь` | - | ✅ При `TRANSPORT=file` |
| `MCP_FILE_POLL_INTERVAL` | Период проверки ответа, сек | `0.2` (папка) / `1` (FTP) | ❌ |
| `MCP_FILE_TIMEOUT` | Таймаут ожидания ответа 1С, сек | `30` | ❌ |
| `MCP_HTTPPOLL_HOST` | Адрес листенера httppoll | `127.0.0.1` | ❌ |
| `MCP_HTTPPOLL_PORT` | Порт листенера httppoll | `9090` | ❌ |
| `MCP_HTTPPOLL_TIMEOUT` | Таймаут ожидания ответа агента, сек | `60` | ❌ |

### HTTP-сервер

| Переменная | Описание | По умолчанию | Обязательная |
|------------|----------|--------------|--------------|
| `MCP_HOST` | Хост для прослушивания | `127.0.0.1` | ❌ |
| `MCP_PORT` | Порт | `8000` | ❌ |
| `MCP_CORS_ORIGINS` | CORS origins (JSON array) | `["*"]` | ❌ |

### MCP

| Переменная | Описание | По умолчанию | Обязательная |
|------------|----------|--------------|--------------|
| `MCP_SERVER_NAME` | Имя сервера | `1C Configuration Data Tools` | ❌ |
| `MCP_SERVER_VERSION` | Версия | `1.6.0` | ❌ |
| `MCP_LOG_LEVEL` | Уровень логирования | `INFO` | ❌ |

Допустимые уровни: `DEBUG`, `INFO`, `WARNING`, `ERROR`

### OAuth2

| Переменная | Описание | По умолчанию | Обязательная |
|------------|----------|--------------|--------------|
| `MCP_AUTH_MODE` | Режим: `none` или `oauth2` | `none` | ❌ |
| `MCP_PUBLIC_URL` | Публичный URL прокси | (определяется из запроса) | ✅ При `AUTH_MODE=oauth2` для HTTP режима |
| `MCP_OAUTH2_CODE_TTL` | TTL authorization code (сек) | `120` | ❌ |
| `MCP_OAUTH2_ACCESS_TTL` | TTL access token (сек) | `3600` | ❌ |
| `MCP_OAUTH2_REFRESH_TTL` | TTL refresh token (сек) | `1209600` | ❌ |
| `MCP_OAUTH2_ALLOWED_REDIRECT_URIS` | Разрешённые redirect_uri через запятую (`*` на конце — префикс; для localhost порт игнорируется) | (не задано — любые) | ❌ |

### CLI аргументы

Переопределяют переменные окружения:

```bash
python -m src.py_server http \
  --onec-url http://server/base \
  --onec-username admin \
  --onec-password secret \
  --auth-mode oauth2 \
  --public-url http://proxy:8000 \
  --port 8000 \
  --log-level DEBUG
```

Полный список аргументов:
```bash
python -m src.py_server --help
```

## Архитектура

### Общая схема

```
┌─────────────────┐
│   MCP Client    │  (Claude Desktop, Cursor)
│  (stdio/HTTP)   │
└────────┬────────┘
         │ MCP Protocol
         ↓
┌────────────────────┐
│  Python Proxy      │
│  - mcp_server      │  Проксирование MCP → JSON-RPC
│  - http_server     │  HTTP/SSE транспорты + OAuth2
│  - stdio_server    │  Stdio транспорт
│  - onec_client     │  HTTP-клиент для 1С
└────────┬───────────┘
         │ JSON-RPC over HTTP
         │ Basic Auth (username:password)
         ↓
┌────────────────────┐
│  1C HTTP Service   │  /hs/mcp/rpc
│  (расширение)      │
└────────────────────┘
```

### Модули

- **`main.py`** - CLI парсинг и запуск
- **`config.py`** - конфигурация через Pydantic
- **`mcp_server.py`** - ядро MCP-сервера (проксирование)
- **`onec_client.py`** - асинхронный HTTP-клиент для 1С
- **`http_server.py`** - HTTP/SSE транспорт + OAuth2
- **`stdio_server.py`** - stdio транспорт
- **`auth/oauth2.py`** - OAuth2 авторизация (Store + Service)

### Проксирование MCP-примитивов

Все MCP-запросы транслируются в JSON-RPC к 1С:

**Tools (инструменты):**
- `tools/list` → список доступных инструментов
- `tools/call` → вызов инструмента с аргументами

**Resources (ресурсы):**
- `resources/list` → список доступных ресурсов
- `resources/read` → чтение содержимого ресурса

**Prompts (промпты):**
- `prompts/list` → список доступных промптов
- `prompts/get` → получение промпта с параметрами

## Примеры использования

### Проверка подключения к 1С

```bash
# HTTP режим
curl http://localhost:8000/health

# Ожидаемый ответ
{
  "status": "healthy",
  "onec_connection": "ok",
  "auth": {"mode": "none"}
}
```

### Информация о сервере

```bash
curl http://localhost:8000/info
```

### OAuth2: отзыв токена (логаут)

Клиент отзывает токен через `POST /revoke` (RFC 7009) — эндпоинт объявлен в
`/.well-known/oauth-authorization-server`. Access и refresh отзываются парой: достаточно прислать любой из них.

```bash
curl -X POST http://localhost:8000/revoke -d "token=<access_или_refresh>"
# → 200 {}
```

> **Password grant удалён.** Раньше `POST /token` с `grant_type=password` выдавал самодостаточный токен
> `simple_base64(username:password)`. Такой токен невозможно отозвать, он переживает перезапуск прокси
> и хранит логин с паролем в конфиге клиента открытым текстом. Сейчас этот грант отвечает 400
> `unsupported_grant_type`, а токены `simple_*` не принимаются. Используйте `authorization_code` с PKCE.

### OAuth2: Authorization Code + PKCE (стандартный)

```bash
# 1. Discovery
curl http://localhost:8000/.well-known/oauth-authorization-server

# 2. Регистрация клиента
curl -X POST http://localhost:8000/register \
  -H "Content-Type: application/json" \
  -d '{"client_name": "My Client"}'

# 3. Авторизация (в браузере)
# http://localhost:8000/authorize?response_type=code&client_id=mcp-public-client&...

# 4. Обмен кода на токены
curl -X POST http://localhost:8000/token \
  -d "grant_type=authorization_code" \
  -d "code=<authorization_code>" \
  -d "redirect_uri=http://localhost/callback" \
  -d "code_verifier=<code_verifier>"
```

### Логирование

```bash
# DEBUG режим для отладки
python -m src.py_server http --log-level DEBUG

# Логи показывают:
# - Все HTTP запросы к 1С
# - OAuth2 операции (генерация/валидация токенов)
# - MCP операции (tools/resources/prompts)
# - Ошибки подключения
```

## Интеграция с 1С

Прокси ожидает HTTP-сервис в 1С по адресу:
```
{MCP_ONEC_URL}/hs/{MCP_ONEC_SERVICE_ROOT}/
```

Например: `http://localhost/base/hs/mcp/`

> **Важно:** Регистр имени базы в URL должен точно совпадать с именем публикации (например, `base`, а не `Base`). Иначе 1С выполняет редирект, превращающий POST в GET.

### Endpoints 1С

1. **`GET /health`**
   - Проверка доступности сервиса
   - Ответ: `{"status": "ok"}`
   - Используется для валидации креденшилов в OAuth2

2. **`POST /rpc`**
   - JSON-RPC endpoint для всех MCP-операций
   - Content-Type: `application/json`
   - Basic Auth: `username:password`

### Формат JSON-RPC запроса

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "tools/list",
  "params": {}
}
```

### Формат JSON-RPC ответа

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "tools": [
      {
        "name": "get_metadata",
        "description": "Получить метаданные объекта",
        "inputSchema": {...}
      }
    ]
  }
}
```

Подробности реализации 1С-стороны: `../1c_ext/agents.md`

## Экспериментальные транспорты до 1С (без веб-сервера)

Обычный путь доставки запросов до 1С — опубликованный HTTP-сервис (`MCP_TRANSPORT=http`, используется по умолчанию). Когда веб-сервера нет, можно включить один из двух экспериментальных транспортов: `MCP_TRANSPORT=file` или `MCP_TRANSPORT=httppoll`. **Не для промышленной эксплуатации** — только для тестирования и для тех, кто ведёт разработку в 1С с помощью MCP.

**Как это работает.** Прокси выкладывает запросы (в папку или во внутреннюю очередь) и ждёт ответов. Забирает и выполняет их **агент** — форма обработки «Управление MCP-сервером» из расширения, запущенная в открытом сеансе 1С. Интервал опроса задаётся на форме (по умолчанию 3 с для папки/FTP, 1 с для HTTP). Запросы выполняются от имени пользователя этого сеанса, поэтому `MCP_ONEC_URL`, логин и пароль прокси не нужны.

**Запуск агента:** в базе открыть «Управление MCP-сервером» → вкладка «MCP без веб-сервера (тест)» → указать адрес → «Старт». Настройки для `MCP_TRANSPORT=file` по сценариям:

| Сценарий | `MCP_FILE_EXCHANGE_DIR` (прокси) | Адрес на форме агента |
|---|---|---|
| Папка, доступная обоим | `D:\tmp\exch` или `\\server\share\exch` | путь к той же папке |
| Папка у прокси, у 1С — только FTP до неё | `D:\tmp\exch` (локальный путь) | `ftp://пользователь:пароль@хост/путь` |
| FTP на третьей машине, общей папки нет | `ftp://пользователь:пароль@хост/путь` | тот же адрес; хост — как его видит машина 1С |

Для `MCP_TRANSPORT=httppoll` адрес на форме — `http://localhost:9090` (адрес HTTP-листенера прокси, каким его видит машина 1С).

### file — обмен через папку

Прокси пишет файл запроса в `<папка>/in/` и ждёт файл ответа в `<папка>/out/`. В `MCP_FILE_EXCHANGE_DIR` указывается либо локальный/сетевой путь, либо адрес папки на FTP-сервере — `ftp://пользователь:пароль@хост:порт/путь` (без шифрования, FTPS не поддерживается). Учётной записи FTP нужны права на создание каталогов, запись и удаление файлов в `in/` и `out/`.

Блок `env` в конфигурации MCP-клиента (рядом с `command`/`args` запуска прокси, см. «Быстрый старт»):

```json
"env": {
  "MCP_TRANSPORT": "file",
  "MCP_FILE_EXCHANGE_DIR": "D:\\tmp\\mcp_exchange"
}
```

Признак работающей связки: файл запроса `*.json` исчезает из `in/`, ответ появляется в `out/` и тут же забирается прокси; ошибки агент показывает в поле состояния на форме. Необязательные настройки прокси (в скобках — умолчания; к интервалу опроса агента отношения не имеют): `MCP_FILE_TIMEOUT` — сколько ждать ответ 1С (30 с), `MCP_FILE_POLL_INTERVAL` — как часто проверять появление файла ответа (0.2 с для папки, 1 с для FTP).

### httppoll — обратный HTTP

Работает только в stdio-режиме прокси (режим подключения клиентов, см. «Режимы работы»). Прокси поднимает HTTP-листенер (по умолчанию `127.0.0.1:9090`), агент сам обращается к нему за запросами — на машине с 1С входящие порты не нужны. Транспорту достаточно проброса одного TCP-порта (например, туннель NoMachine). На форме агента указывается адрес листенера: `http://localhost:9090`.

```json
"env": {
  "MCP_TRANSPORT": "httppoll",
  "MCP_HTTPPOLL_PORT": "9090"
}
```

Необязательные настройки прокси (в скобках — умолчания): `MCP_HTTPPOLL_HOST` (`127.0.0.1`), `MCP_HTTPPOLL_TIMEOUT` — сколько ждать ответ агента (60 с). Проверка, что листенер жив: `curl http://127.0.0.1:9090/health`.

## Документация

### Для разработчиков

- **`agents.md`** - полная документация архитектуры для AI-агентов
  - Детальное описание всех модулей
  - Протоколы взаимодействия
  - OAuth2 flows
  - Точки расширения
  
### Конфигурация

- **`env.example`** - пример `.env` файла со всеми параметрами

---

**MIT License**

Проект активно развивается. Вопросы и предложения приветствуются через Issues.
