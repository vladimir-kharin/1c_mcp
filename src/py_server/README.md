# MCP-прокси сервер для 1С

Этот модуль реализует MCP (Model Context Protocol) прокси-сервер для взаимодействия с 1С. Прокси позволяет MCP-клиентам подключаться к инструментам, ресурсам и промптам, реализованным в 1С.

## Архитектура

```
MCP Client <-> MCP Proxy (Python) <-> 1C HTTP Service
```

- **MCP Client**: Любой клиент, поддерживающий протокол MCP (Claude Desktop, Cursor, и т.д.)
- **MCP Proxy**: Этот Python-сервер, который преобразует MCP-запросы в HTTP-запросы к 1С
- **1C HTTP Service**: HTTP-сервис в 1С, который обрабатывает запросы и возвращает данные

## Возможности

- ✅ Поддержка протокола MCP 1.9.1+
- ✅ Два режима работы: stdio и HTTP с SSE
- ✅ Проксирование всех типов MCP-примитивов:
  - **Tools** (инструменты) - функции для выполнения действий
  - **Resources** (ресурсы) - данные для контекста
  - **Prompts** (промпты) - шаблоны сообщений
- ✅ Автоматическое переподключение к 1С
- ✅ Подробное логирование
- ✅ Конфигурация через переменные окружения
- ✅ CORS поддержка для веб-клиентов

## Установка

1. Установите зависимости:
```bash
pip install -r requirements.txt
```

2. Конфигурация сервера (в отдельном файле .env для случая запуска в HTTP-режиме с SSE):
```bash
cp env.example .env
```

3. Отредактируйте `.env` файл с вашими настройками 1С:
```bash
MCP_ONEC_URL=http://localhost/your_base_name
MCP_ONEC_USERNAME=your_username
MCP_ONEC_PASSWORD=your_password
```

## Использование

### Режим stdio (для MCP-клиентов)

Для использования с MCP-клиентами типа Claude Desktop:

```bash
python -m src.py_server
```

### Режим HTTP-сервера (для веб-клиентов)

Для использования с веб-приложениями:

```bash
python -m src.py_server http --port 8000
```

HTTP-сервер предоставляет следующие endpoints:
- `GET /` - информация о сервере
- `GET /health` - проверка состояния
- `GET /mcp/sse` - SSE подключение для MCP
- `POST /mcp/messages` - отправка сообщений MCP
- `GET /info` - информация о сервере

### Параметры командной строки

```bash
# Основные команды
python -m src.py_server stdio                    # Stdio режим
python -m src.py_server http                     # HTTP режим

# Дополнительные параметры
python -m src.py_server http --host 0.0.0.0 --port 8080
python -m src.py_server stdio --log-level DEBUG
python -m src.py_server http --env-file custom.env

# Переопределение настроек 1С
python -m src.py_server stdio \
  --onec-url http://server/base \
  --onec-username admin \
  --onec-password secret \
  --onec-service-root custom_mcp
```

## Конфигурация

Все настройки можно задать через переменные окружения с префиксом `MCP_`:

| Переменная | Описание | По умолчанию | Обязательная |
|------------|----------|--------------|--------------|
| `MCP_ONEC_URL` | URL базы 1С | - | ✅ |
| `MCP_ONEC_USERNAME` | Имя пользователя 1С | - | ✅ |
| `MCP_ONEC_PASSWORD` | Пароль пользователя 1С | - | ✅ |
| `MCP_ONEC_SERVICE_ROOT` | Корневой URL HTTP-сервиса | `mcp` | ❌ |
| `MCP_HOST` | Хост HTTP-сервера | `127.0.0.1` | ❌ |
| `MCP_PORT` | Порт HTTP-сервера | `8000` | ❌ |
| `MCP_SERVER_NAME` | Имя MCP-сервера | `1C-MCP-Proxy` | ❌ |
| `MCP_SERVER_VERSION` | Версия MCP-сервера | `1.0.0` | ❌ |
| `MCP_LOG_LEVEL` | Уровень логирования | `INFO` | ❌ |
| `MCP_CORS_ORIGINS` | Разрешенные CORS origins | `["*"]` | ❌ |

## Интеграция с 1С

Прокси ожидает, что в 1С реализован HTTP-сервис и обращается к нему по стандартной схеме 1С:

```
<URL базы 1С>/hs/<корневой URL HTTP-сервиса>/<endpoint>
```

По умолчанию корневой URL HTTP-сервиса - `mcp`, но его можно изменить через параметр `MCP_ONEC_SERVICE_ROOT`.

### POST /hs/{service_root}/rpc
Обрабатывает JSON-RPC запросы для всех MCP-операций:
- `tools/list` - список инструментов
- `tools/call` - вызов инструмента
- `resources/list` - список ресурсов
- `resources/read` - чтение ресурса
- `prompts/list` - список промптов
- `prompts/get` - получение промпта

Пример JSON-RPC запроса:
```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "tools/list",
  "params": {}
}
```

## Отладка

Включите подробное логирование:
```bash
python -m src.py_server --log-level DEBUG
```

Проверьте состояние HTTP-сервера:
```bash
curl http://localhost:8000/health
```

## Требования к 1С

- 1С:Предприятие 8.3.20+
- Расширение MCP-сервер (см. `../1c_ext/`)
- HTTP-сервис должен быть опубликован и доступен

## Лицензия

MIT License