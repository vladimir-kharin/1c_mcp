# MCP-прокси сервер для 1С - Документация для AI-агентов

Этот документ предоставляет полное описание архитектуры и компонентов Python MCP-прокси сервера для генерации кода AI-агентами.

## Оглавление

1. [Общая архитектура](#общая-архитектура)
2. [Структура проекта](#структура-проекта)
3. [Основные модули](#основные-модули)
4. [Подсистема авторизации](#подсистема-авторизации)
5. [Протокол взаимодействия с 1С](#протокол-взаимодействия-с-1с)
6. [Конфигурация](#конфигурация)
7. [Типы данных и модели](#типы-данных-и-модели)
8. [Потоки данных](#потоки-данных)
9. [Обработка ошибок](#обработка-ошибок)
10. [Точки расширения](#точки-расширения)

---

## Общая архитектура

### Назначение проекта

MCP-прокси сервер - это промежуточное звено между MCP-клиентами (Claude Desktop, Cursor и др.) и HTTP-сервисом 1С:Предприятие. Прокси транслирует запросы MCP-протокола в JSON-RPC вызовы к 1С и обратно.

### Архитектурная диаграмма

```
┌─────────────────┐
│   MCP Client    │  (Claude Desktop, Cursor)
│  (stdio/http)   │
└────────┬────────┘
         │ MCP Protocol
         │
┌────────▼────────┐
│  Python Proxy   │  Два транспорта:
│                 │  - stdio (для нативных клиентов)
│  - mcp_server   │  - HTTP+SSE (для веб-клиентов)
│  - http_server  │
│  - stdio_server │
└────────┬────────┘
         │ JSON-RPC over HTTP
         │
┌────────▼────────┐
│  1C HTTP        │  /hs/mcp/rpc
│  Service        │  (реализован в расширении 1С)
└─────────────────┘
```

### Ключевые особенности

1. **Два режима работы**: stdio (для нативных MCP-клиентов) и HTTP с SSE (для веб)
2. **Проксирование MCP-примитивов**: Tools, Resources, Prompts
3. **Опциональная OAuth2 авторизация**: два grant flows (Authorization Code + PKCE и Password)
4. **Per-session креденшилы**: каждая MCP-сессия использует свои учётные данные 1С
5. **Асинхронная архитектура**: все I/O операции неблокирующие

---

## Структура проекта

```
src/py_server/
├── __init__.py                      # Экспорты модуля
├── __main__.py                      # Точка входа (python -m src.py_server)
├── main.py                          # CLI парсинг и запуск
├── config.py                        # Конфигурация через Pydantic
│
├── onec_client.py                   # HTTP-клиент для 1С
├── mcp_server.py                    # MCP-сервер (проксирование)
├── http_server.py                   # HTTP/SSE транспорт + OAuth2
├── stdio_server.py                  # Stdio транспорт
│
├── auth/                            # Подсистема авторизации
│   ├── __init__.py
│   └── oauth2.py                    # OAuth2 Store + Service
│
├── requirements.txt                 # Python зависимости
├── env.example                      # Пример .env конфигурации
│
└── *.md                             # Документация
    ├── README.md                    # Пользовательская документация
    ├── ARCHITECTURE.md              # Обзор архитектуры
    ├── agents.md                    # Этот файл
    └── ...
```

---

## Основные модули

### 1. `main.py` - CLI и точка входа

**Назначение:** Парсинг аргументов командной строки, инициализация конфигурации и запуск соответствующего сервера.

**Основные компоненты:**

- `create_parser() -> argparse.ArgumentParser`
  - Создаёт CLI парсер с двумя режимами: `stdio` и `http`
  - Поддерживает аргументы: `--onec-url`, `--onec-username`, `--onec-password`, `--auth-mode`, `--public-url`, и др.
  - Все аргументы опциональны, если заданы в `.env`

- `setup_logging(level: str)`
  - Настройка логирования в stderr
  - Поддержка уровней: DEBUG, INFO, WARNING, ERROR

- `async main()`
  - Загрузка `.env` файла через `dotenv`
  - Преобразование CLI аргументов в переменные окружения
  - Создание `Config` через `get_config()`
  - Запуск `run_stdio_server()` или `run_http_server()`

**Зависимости:**
- `config.get_config()` - получение конфигурации
- `http_server.run_http_server()` - запуск HTTP режима
- `stdio_server.run_stdio_server()` - запуск stdio режима

**Особенности:**
- Windows-специфичная настройка UTF-8 кодировки
- Graceful shutdown при KeyboardInterrupt

---

### 2. `config.py` - Конфигурация системы

**Назначение:** Единый источник истины для всех настроек приложения с валидацией через Pydantic.

**Класс `Config(BaseSettings)`:**

```python
class Config(BaseSettings):
	# Сервер
	host: str = "127.0.0.1"
	port: int = 8000
	
	# Подключение к 1С (обязательные)
	onec_url: str
	onec_username: str
	onec_password: str
	onec_service_root: str = "mcp"
	
	# MCP
	server_name: str = "1C Configuration Data Tools"
	server_version: str = "1.0.0"
	
	# Логирование
	log_level: str = "INFO"
	
	# Безопасность
	cors_origins: list[str] = ["*"]
	
	# OAuth2
	auth_mode: Literal["none", "oauth2"] = "none"
	public_url: Optional[str] = None
	oauth2_code_ttl: int = 120       # секунды
	oauth2_access_ttl: int = 3600    # секунды
	oauth2_refresh_ttl: int = 1209600  # 14 дней
	
	class Config:
		env_file = ".env"
		env_prefix = "MCP_"
```

**Функция `get_config() -> Config`:**
- Singleton-паттерн для конфигурации
- Автоматическая загрузка из переменных окружения с префиксом `MCP_`

**Зависимости:**
- `pydantic` и `pydantic_settings` для валидации

---

### 3. `onec_client.py` - HTTP-клиент для 1С

**Назначение:** Асинхронный HTTP-клиент для взаимодействия с HTTP-сервисом 1С через JSON-RPC.

**Класс `OneCClient`:**

```python
class OneCClient:
	def __init__(self, base_url: str, username: str, password: str, service_root: str = "mcp"):
		self.base_url = base_url  # http://server/base
		self.service_root = service_root  # "mcp"
		self.auth = httpx.BasicAuth(username, password)
		self.client = httpx.AsyncClient(auth=self.auth, timeout=30.0)
		self.service_base_url = f"{base_url}/hs/{service_root}"
```

**Методы:**

1. `async check_health() -> bool`
   - Проверка доступности 1С через `GET /hs/{service_root}/health`
   - Ожидает JSON: `{"status": "ok"}`
   - Используется для валидации креденшилов в OAuth2

2. `async call_rpc(method: str, params: Optional[Dict]) -> Dict`
   - Универсальный JSON-RPC вызов к `POST /hs/{service_root}/rpc`
   - Формат запроса: `{"jsonrpc": "2.0", "id": 1, "method": "...", "params": {...}}`
   - Обработка JSON-RPC ошибок

3. **MCP Tools:**
   - `async list_tools() -> List[types.Tool]`
   - `async call_tool(name: str, arguments: Dict) -> types.CallToolResult`

4. **MCP Resources:**
   - `async list_resources() -> List[types.Resource]`
   - `async read_resource(uri: str) -> List[ReadResourceContents]`
     - Поддержка text и blob (base64) контента

5. **MCP Prompts:**
   - `async list_prompts() -> List[types.Prompt]`
   - `async get_prompt(name: str, arguments: Optional[Dict]) -> types.GetPromptResult`

6. `async close()`
   - Закрытие httpx.AsyncClient

**Преобразование данных:**
- JSON от 1С → MCP типы (из библиотеки `mcp`)
- Обработка разных типов контента: text, image, blob

**Зависимости:**
- `httpx` для async HTTP
- `mcp.types` для MCP типов

---

### 4. `mcp_server.py` - Ядро MCP-сервера

**Назначение:** Реализация MCP-протокола, регистрация обработчиков и управление жизненным циклом.

**Глобальная переменная:**

```python
current_onec_credentials: contextvars.ContextVar[Optional[Tuple[str, str]]] = contextvars.ContextVar(
	'current_onec_credentials',
	default=None
)
```
- Context var для передачи креденшилов между middleware и MCP-сервером
- Используется в OAuth2 режиме для per-session авторизации

**Класс `MCPProxy`:**

```python
class MCPProxy:
	def __init__(self, config: Config):
		self.config = config
		self.onec_client: Optional[OneCClient] = None
		self.server = Server(name=config.server_name, lifespan=self._lifespan)
		self._register_handlers()
```

**Методы:**

1. `async _lifespan(server: Server) -> AsyncIterator[Dict[str, Any]]`
   - **Ключевая логика выбора креденшилов:**
     ```python
     if config.auth_mode == "oauth2":
         session_creds = current_onec_credentials.get()
         if session_creds:
             username, password = session_creds  # Per-session креды
         else:
             # Fallback на дефолтные
             username, password = config.onec_username, config.onec_password
     else:
         # Режим none - дефолтные креды
         username, password = config.onec_username, config.onec_password
     ```
   - Создание `OneCClient` с выбранными кредами
   - Проверка подключения через `check_health()`
   - Yield контекста для обработчиков
   - Cleanup: закрытие OneCClient

2. `_register_handlers()`
   - Регистрация декорированных обработчиков MCP:
     - `@server.list_tools()` → `handle_list_tools()`
     - `@server.call_tool()` → `handle_call_tool(name, arguments)`
     - `@server.list_resources()` → `handle_list_resources()`
     - `@server.read_resource()` → `handle_read_resource(uri)`
     - `@server.list_prompts()` → `handle_list_prompts()`
     - `@server.get_prompt()` → `handle_get_prompt(name, arguments)`
   
   - Все обработчики:
     1. Получают `onec_client` из `server.request_context.lifespan_context`
     2. Делегируют вызов в `onec_client.{метод}()`
     3. Обрабатывают ошибки и возвращают MCP-типы

3. `get_capabilities() -> Dict`
   - Декларация capabilities сервера: tools, resources, prompts с listChanged

4. `get_initialization_options() -> InitializationOptions`
   - Опции для инициализации MCP соединения

**Зависимости:**
- `mcp.server.Server` - core MCP сервер
- `OneCClient` - для вызовов в 1С
- `Config` - конфигурация

---

### 5. `http_server.py` - HTTP/SSE транспорт + OAuth2

**Назначение:** HTTP-сервер на FastAPI с двумя транспортами MCP (SSE и Streamable HTTP) и полной OAuth2 авторизацией.

#### Класс `OAuth2BearerMiddleware(BaseHTTPMiddleware)`

**Назначение:** ASGI middleware для проверки Bearer токенов и установки per-session креденшилов.

```python
class OAuth2BearerMiddleware(BaseHTTPMiddleware):
	def __init__(self, app, oauth2_service: Optional[OAuth2Service], auth_mode: str):
		self.oauth2_service = oauth2_service
		self.auth_mode = auth_mode
		self.protected_paths = ["/mcp/", "/sse"]
```

**Логика `dispatch()`:**

1. Если `auth_mode != "oauth2"` → пропустить авторизацию
2. Проверить, защищён ли путь (`/mcp/`, `/sse`)
3. Извлечь `Authorization: Bearer <token>`
4. Валидировать токен (два формата):
   - **Простой формат:** `simple_base64(username:password)` - для Password Grant
   - **OAuth2 формат:** через `oauth2_service.validate_access_token()`
5. Установить креденшилы: `current_onec_credentials.set((login, password))`
6. Делегировать запрос дальше

**Ответ на ошибки:**
- 401 Unauthorized с заголовком `WWW-Authenticate: Bearer error="invalid_token"`

#### Класс `MCPHttpServer`

**Компоненты:**

```python
class MCPHttpServer:
	def __init__(self, config: Config):
		self.config = config
		self.mcp_proxy = MCPProxy(config)
		self.streamable_session_manager = StreamableHTTPSessionManager(self.mcp_proxy.server)
		
		# OAuth2 (если включено)
		if config.auth_mode == "oauth2":
			self.oauth2_store = OAuth2Store()
			self.oauth2_service = OAuth2Service(store, code_ttl, access_ttl, refresh_ttl)
		
		self.app = FastAPI(...)
		# Middleware: CORS → OAuth2Bearer
		self.app.add_middleware(CORSMiddleware, ...)
		self.app.add_middleware(OAuth2BearerMiddleware, ...)
		
		self._mount_transports()
		self._register_routes()
```

**Методы:**

1. `async _lifespan(app: FastAPI)`
   - Запуск задачи очистки OAuth2 токенов (если включено)
   - Запуск `streamable_session_manager.run()`
   - Cleanup при завершении

2. `_create_sse_starlette_app() -> Starlette`
   - Создание Starlette app для SSE транспорта
   - Маршруты:
     - `GET /sse` → SSE соединение
     - `POST /sse/messages/` → отправка сообщений

3. `_create_streamable_http_asgi()`
   - ASGI handler для Streamable HTTP (новый транспорт MCP)
   - Делегирует в `streamable_session_manager.handle_request()`

4. `_mount_transports()`
   - Монтирует SSE: `app.mount("/sse", sse_app)`
   - Монтирует Streamable HTTP: `app.mount("/mcp/", streamable_app)`

5. `_register_routes()`
   - Основные маршруты:
     - `GET /` → информация о сервере
     - `GET /info` → подробная информация
     - `GET /health` → проверка состояния (незащищённый)
   - При `auth_mode=oauth2` вызывает `_register_oauth2_routes()`

6. `_register_oauth2_routes()`
   - **Discovery endpoints:**
     - `GET /.well-known/oauth-protected-resource` → PRM документ (RFC 9728)
     - `GET /.well-known/oauth-authorization-server` → AS Metadata (RFC 8414)
   
   - **Dynamic Client Registration (RFC 7591):**
     - `POST /register` → фиксированный `client_id = "mcp-public-client"`
   
   - **Authorization Code Flow:**
     - `GET /authorize` → HTML форма логин/пароль
     - `POST /authorize` → валидация через 1С health, генерация code, редирект
   
   - **Token endpoint:**
     - `POST /token` с `grant_type`:
       - `password` → простой токен `simple_base64(username:password)`
       - `authorization_code` → PKCE валидация, выдача access/refresh
       - `refresh_token` → ротация refresh токена

7. `async start()`
   - Запуск uvicorn сервера

**Зависимости:**
- `FastAPI`, `uvicorn` - HTTP сервер
- `mcp.server.sse.SseServerTransport` - SSE транспорт
- `mcp.server.streamable_http_manager.StreamableHTTPSessionManager` - Streamable HTTP
- `auth.OAuth2Service`, `auth.OAuth2Store` - OAuth2 логика

---

### 6. `stdio_server.py` - Stdio транспорт

**Назначение:** Запуск MCP-сервера в режиме stdio для нативных MCP-клиентов.

```python
async def run_stdio_server(config: Config):
	mcp_proxy = MCPProxy(config)
	
	async with mcp.server.stdio.stdio_server() as (read_stream, write_stream):
		await mcp_proxy.server.run(
			read_stream,
			write_stream,
			mcp_proxy.get_initialization_options()
		)
```

**Особенности:**
- Использует stdin/stdout для MCP-протокола
- Логи идут в stderr (важно!)
- Не поддерживает OAuth2 (при auth_mode=oauth2 запуск завершается ошибкой)

**Зависимости:**
- `mcp.server.stdio.stdio_server()` - stdio транспорт из MCP SDK

---

## Подсистема авторизации

Расположена в модуле `auth/`, реализует опциональную OAuth2 авторизацию.

### Модуль `auth/oauth2.py`

#### Модели данных (dataclasses):

```python
@dataclass
class AuthCodeData:
	login: str
	password: str
	redirect_uri: str
	code_challenge: str  # PKCE S256
	exp: datetime

@dataclass
class AccessTokenData:
	login: str
	password: str
	exp: datetime

@dataclass
class RefreshTokenData:
	login: str
	password: str
	exp: datetime
	rotation_counter: int = 0
```

#### Класс `OAuth2Store`

**Назначение:** In-memory хранилище токенов с автоматической очисткой по TTL.

**Структуры данных:**

```python
self.auth_codes: Dict[str, AuthCodeData] = {}
self.access_tokens: Dict[str, AccessTokenData] = {}
self.refresh_tokens: Dict[str, RefreshTokenData] = {}
self._cleanup_task: Optional[asyncio.Task] = None
```

**Методы:**

1. **Управление задачей очистки:**
   - `async start_cleanup_task(interval: int = 60)`
   - `async stop_cleanup_task()`
   - `async _cleanup_loop(interval: int)` - периодический цикл
   - `_cleanup_expired()` - удаление истёкших токенов

2. **Authorization Codes:**
   - `save_auth_code(code: str, data: AuthCodeData)`
   - `get_auth_code(code: str) -> Optional[AuthCodeData]` - одноразовый (удаляется при чтении)

3. **Access Tokens:**
   - `save_access_token(token: str, data: AccessTokenData)`
   - `get_access_token(token: str) -> Optional[AccessTokenData]` - проверка TTL

4. **Refresh Tokens:**
   - `save_refresh_token(token: str, data: RefreshTokenData)`
   - `get_refresh_token(token: str) -> Optional[RefreshTokenData]` - удаляется при чтении (ротация)

**Особенности:**
- Всё в оперативной памяти (при рестарте сброс)
- Автоматическая очистка по TTL каждые 60 секунд
- Логирование всех операций

#### Класс `OAuth2Service`

**Назначение:** Бизнес-логика OAuth2 flows.

```python
class OAuth2Service:
	def __init__(self, store: OAuth2Store, code_ttl: int, access_ttl: int, refresh_ttl: int):
		self.store = store
		self.code_ttl = code_ttl      # 120 сек
		self.access_ttl = access_ttl  # 3600 сек
		self.refresh_ttl = refresh_ttl  # 1209600 сек (14 дней)
```

**Методы:**

1. `generate_prm_document(public_url: str) -> dict`
   - Генерация Protected Resource Metadata (RFC 9728)
   - Возвращает JSON с `resource`, `authorization_servers`, endpoints

2. `generate_authorization_code(login, password, redirect_uri, code_challenge) -> str`
   - Генерация случайного кода (secrets.token_urlsafe)
   - Сохранение в store с TTL

3. `validate_pkce(code_verifier: str, code_challenge: str) -> bool`
   - Вычисление SHA256 от verifier
   - Base64url encoding и сравнение с challenge
   - **Только S256**, plain не поддерживается

4. `exchange_code_for_tokens(code, redirect_uri, code_verifier) -> Optional[Tuple[...]]`
   - Получение и удаление authorization code
   - Проверка redirect_uri
   - Валидация PKCE
   - Генерация access + refresh токенов
   - Возврат: `(access_token, "Bearer", expires_in, refresh_token)`

5. `refresh_tokens(refresh_token: str) -> Optional[Tuple[...]]`
   - Получение и удаление старого refresh (ротация!)
   - Генерация новых access + refresh токенов
   - Инкремент rotation_counter

6. `validate_access_token(token: str) -> Optional[Tuple[str, str]]`
   - Проверка токена в store
   - Возврат `(login, password)` или `None`

**Особенности:**
- Все токены генерируются через `secrets.token_urlsafe(32)`
- PKCE обязателен для Authorization Code flow
- Refresh token ротация (старый инвалидируется при использовании)

---

## Протокол взаимодействия с 1С

### Endpoints 1С HTTP-сервиса

Базовый URL: `{onec_url}/hs/{service_root}/` (по умолчанию: `http://localhost/base/hs/mcp/`)

1. **GET `/health`**
   - Проверка доступности
   - Ответ: `{"status": "ok"}`
   - Используется для валидации креденшилов в OAuth2

2. **POST `/rpc`**
   - JSON-RPC endpoint для всех MCP-операций
   - Content-Type: `application/json`
   - Basic Auth: `username:password`

### JSON-RPC методы

#### Tools:
- `tools/list` → `{"tools": [...]}`
- `tools/call` → `{"content": [...], "isError": false}`

#### Resources:
- `resources/list` → `{"resources": [...]}`
- `resources/read` → `{"contents": [{"type": "text"|"blob", ...}]}`

#### Prompts:
- `prompts/list` → `{"prompts": [...]}`
- `prompts/get` → `{"description": "...", "messages": [...]}`

### Формат запроса

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "tools/call",
  "params": {
    "name": "get_metadata",
    "arguments": {"type": "Document"}
  }
}
```

### Формат ответа

**Успех:**
```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "content": [{"type": "text", "text": "..."}],
    "isError": false
  }
}
```

**Ошибка:**
```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "error": {
    "code": -32601,
    "message": "Method not found"
  }
}
```

---

## Конфигурация

### Переменные окружения

Все переменные имеют префикс `MCP_` и могут быть заданы в `.env` файле или через CLI.

#### Обязательные:
- `MCP_ONEC_URL` - URL базы 1С (например, `http://localhost/base`)
- `MCP_ONEC_USERNAME` - Имя пользователя 1С (обязательно при `MCP_AUTH_MODE=none`)
- `MCP_ONEC_PASSWORD` - Пароль пользователя 1С (обязательно при `MCP_AUTH_MODE=none`)

#### Опциональные (основные):
- `MCP_ONEC_SERVICE_ROOT` - корень HTTP-сервиса (по умолчанию: `mcp`)
- `MCP_HOST` - хост HTTP-сервера (по умолчанию: `127.0.0.1`)
- `MCP_PORT` - порт HTTP-сервера (по умолчанию: `8000`)
- `MCP_SERVER_NAME` - имя MCP-сервера (по умолчанию: `1C Configuration Data Tools`)
- `MCP_LOG_LEVEL` - уровень логирования (по умолчанию: `INFO`)
- `MCP_CORS_ORIGINS` - CORS origins (по умолчанию: `["*"]`)

#### OAuth2:
- `MCP_AUTH_MODE` - режим авторизации: `none` (default) или `oauth2`
- `MCP_PUBLIC_URL` - публичный URL прокси для OAuth2 (если не задан, формируется из запроса)
- `MCP_OAUTH2_CODE_TTL` - TTL authorization code в секундах (по умолчанию: `120`)
- `MCP_OAUTH2_ACCESS_TTL` - TTL access token в секундах (по умолчанию: `3600`)
- `MCP_OAUTH2_REFRESH_TTL` - TTL refresh token в секундах (по умолчанию: `1209600`)
  - `MCP_ONEC_USERNAME`/`MCP_ONEC_PASSWORD` игнорируются при `MCP_AUTH_MODE=oauth2`

### Файл `.env`

Пример:
```ini
MCP_ONEC_URL=http://localhost/base
MCP_ONEC_USERNAME=admin
MCP_ONEC_PASSWORD=secret
MCP_ONEC_SERVICE_ROOT=mcp

MCP_AUTH_MODE=oauth2
MCP_PUBLIC_URL=http://localhost:8000

MCP_LOG_LEVEL=DEBUG
```

### CLI аргументы

Переопределяют переменные окружения:

```bash
python -m src.py_server http \
  --onec-url http://server/base \
  --onec-username admin \
  --onec-password secret \
  --auth-mode oauth2 \
  --public-url http://proxy.local:8000 \
  --port 8000 \
  --log-level DEBUG
```

---

## Типы данных и модели

### MCP типы (из библиотеки `mcp`)

```python
from mcp import types

# Tools
types.Tool(name: str, description: str, inputSchema: dict)
types.CallToolResult(content: List[Content], isError: bool)

# Resources
types.Resource(uri: str, name: str, description: str, mimeType: Optional[str])
types.ReadResourceResult(contents: List[ResourceContents])

# Prompts
types.Prompt(name: str, description: str, arguments: List[PromptArgument])
types.GetPromptResult(description: str, messages: List[PromptMessage])

# Content types
types.TextContent(type="text", text: str)
types.ImageContent(type="image", data: str, mimeType: str)
ReadResourceContents(content: str | bytes, mime_type: str)
```

### Внутренние модели

```python
# Config
Config (Pydantic BaseSettings)

# OAuth2
AuthCodeData, AccessTokenData, RefreshTokenData (dataclasses)

# Context vars
Tuple[str, str]  # (username, password) в current_onec_credentials
```

---

## Потоки данных

### 1. Stdio режим (нативные MCP-клиенты)

```
┌─────────────┐
│ MCP Client  │
│ (Cursor)    │
└──────┬──────┘
       │ stdin/stdout
       │ MCP Protocol
┌──────▼──────┐
│ stdio_server│
│ MCPProxy    │
│ OneCClient  │ Basic Auth (username:password из config)
└──────┬──────┘
       │ HTTP JSON-RPC
┌──────▼──────┐
│ 1C Service  │
│ /hs/mcp/rpc │
└─────────────┘
```

### 2. HTTP режим без OAuth2

```
┌─────────────┐
│ Web Client  │
└──────┬──────┘
       │ HTTP POST /mcp/
┌──────▼──────┐
│ http_server │
│ (no auth)   │
│ MCPProxy    │
│ OneCClient  │ Basic Auth (username:password из config)
└──────┬──────┘
       │ HTTP JSON-RPC
┌──────▼──────┐
│ 1C Service  │
└─────────────┘
```

### 3. HTTP режим с OAuth2 (Authorization Code + PKCE)

```
┌─────────────┐
│ MCP Client  │
└──────┬──────┘
       │ 1. POST /mcp/ → 401
       │ 2. GET /.well-known/oauth-protected-resource
       │ 3. GET /.well-known/oauth-authorization-server
       │ 4. POST /register → client_id
       │ 5. GET /authorize → HTML форма
       │ 6. POST /authorize (username:password)
       │    ├─→ Проверка через 1С health
       │    └─→ 302 redirect с code
       │ 7. POST /token (code, code_verifier)
       │    └─→ access_token, refresh_token
       │ 8. POST /mcp/ (Bearer token)
┌──────▼──────┐
│ http_server │
│ OAuth2      │
│ Middleware  │ Извлекает (username,password) из токена
│             │ Устанавливает current_onec_credentials
│ MCPProxy    │ Читает context var → создаёт OneCClient
│ OneCClient  │ Basic Auth (username:password из токена!)
└──────┬──────┘
       │ HTTP JSON-RPC
┌──────▼──────┐
│ 1C Service  │
└─────────────┘
```

### 4. HTTP режим с OAuth2 (Password Grant)

```
┌─────────────┐
│ MCP Client  │
└──────┬──────┘
       │ 1. POST /mcp/ → 401
       │ 2. Discovery...
       │ 3. POST /token (grant_type=password, username, password)
       │    ├─→ Проверка через 1С health
       │    └─→ simple_base64(username:password) токен
       │ 4. POST /mcp/ (Bearer token)
┌──────▼──────┐
│ http_server │
│ OAuth2      │
│ Middleware  │ Декодирует simple_* токен → (username,password)
│             │ Устанавливает current_onec_credentials
│ MCPProxy    │ Читает context var → создаёт OneCClient
│ OneCClient  │ Basic Auth (username:password из токена!)
└──────┬──────┘
       │ HTTP JSON-RPC
┌──────▼──────┐
│ 1C Service  │
└─────────────┘
```

---

## Обработка ошибок

### Уровни обработки

1. **OneCClient:**
   - HTTP ошибки (connection refused, timeout) → `httpx.HTTPError`
   - JSON-RPC ошибки → `Exception` с описанием
   - Логирование всех ошибок

2. **MCPProxy handlers:**
   - Перехват исключений от OneCClient
   - Возврат MCP-совместимых ошибок:
     - `types.CallToolResult(content=[TextContent(text="Ошибка...")], isError=True)`
     - `types.ReadResourceResult(contents=[TextResourceContents(text="Ошибка...")])`

3. **HTTP Server:**
   - OAuth2 ошибки → HTTP 400/401/503 с JSON: `{"error": "...", "error_description": "..."}`
   - Middleware ошибки → HTTP 401 с `WWW-Authenticate: Bearer`
   - Общие ошибки → HTTP 500

4. **Main:**
   - Перехват `KeyboardInterrupt` → graceful shutdown
   - Общие исключения → логирование, exit(1)

### Логирование

Все модули используют `logging.getLogger(__name__)`:

```python
logger.debug("Детальная информация")
logger.info("Событие жизненного цикла")
logger.warning("Предупреждение, но не критично")
logger.error("Ошибка, требует внимания")
```

Логи идут в **stderr** (важно для stdio режима!)

---

## Точки расширения

### 1. Новые транспорты MCP

Для добавления нового транспорта:

1. Создать модуль `{name}_server.py`
2. Реализовать `async run_{name}_server(config: Config)`
3. Использовать `MCPProxy` для обработки MCP
4. Добавить в `main.py` новый режим

Пример: WebSocket транспорт.

### 2. Новые типы контента

В `OneCClient.call_tool()` и `read_resource()`:

```python
elif content_type == "audio":
	content.append(types.AudioContent(
		type="audio",
		data=item.get("data"),
		mimeType=item.get("mimeType")
	))
```

### 3. Новые OAuth2 grant types

В `http_server._register_oauth2_routes()`, метод `token_endpoint()`:

```python
elif grant_type == "client_credentials":
	# Реализация Client Credentials Grant
	...
```

### 4. Кэширование

Добавить кэш-слой между `MCPProxy` и `OneCClient`:

```python
class CachedOneCClient(OneCClient):
	def __init__(self, *args, cache_ttl=300, **kwargs):
		super().__init__(*args, **kwargs)
		self._cache = {}
	
	async def list_tools(self):
		if "tools" in self._cache:
			return self._cache["tools"]
		tools = await super().list_tools()
		self._cache["tools"] = tools
		return tools
```

### 5. Метрики и мониторинг

Добавить Prometheus metrics:

```python
from prometheus_client import Counter, Histogram

tool_calls = Counter("mcp_tool_calls_total", "Total tool calls")
tool_duration = Histogram("mcp_tool_duration_seconds", "Tool call duration")

@tool_duration.time()
async def call_tool(name, arguments):
	tool_calls.inc()
	return await onec_client.call_tool(name, arguments)
```

### 6. Альтернативные хранилища для OAuth2

Заменить `OAuth2Store` на Redis/PostgreSQL:

```python
class RedisOAuth2Store(OAuth2Store):
	def __init__(self, redis_client):
		self.redis = redis_client
	
	def save_access_token(self, token, data):
		self.redis.setex(
			f"access:{token}",
			data.exp.timestamp(),
			json.dumps(dataclasses.asdict(data))
		)
```

### 7. Динамическая маршрутизация 1С

Для работы с несколькими базами 1С:

```python
class MultiBaseOneCClient:
	def __init__(self, bases_config: Dict[str, Config]):
		self.clients = {
			name: OneCClient(cfg.onec_url, ...)
			for name, cfg in bases_config.items()
		}
	
	async def call_tool(self, name, arguments):
		base_name = arguments.pop("_base", "default")
		client = self.clients[base_name]
		return await client.call_tool(name, arguments)
```

---

## Важные замечания для генерации кода

### 1. Асинхронность

**ВСЕ** I/O операции должны быть асинхронными:
- Используйте `async def` и `await`
- HTTP: `httpx.AsyncClient`, не `requests`
- Сохраняйте `asyncio.Task` для фоновых задач

### 2. Context vars

При работе с `current_onec_credentials`:

```python
# ПРАВИЛЬНО - установка в middleware, чтение в lifespan
current_onec_credentials.set((login, password))
creds = current_onec_credentials.get()

# НЕПРАВИЛЬНО - изменение из другой задачи
# Context vars изолированы между asyncio tasks!
```

### 3. OAuth2 токены

Два формата:
- `simple_*` - декодируется как base64, содержит `username:password`
- Обычные - проверяются через `OAuth2Store`

Middleware должен поддерживать оба!

### 4. Логирование

```python
# ПРАВИЛЬНО - в stderr
logger = logging.getLogger(__name__)
logger.info("Message")

# НЕПРАВИЛЬНО - в stdout (ломает stdio режим!)
print("Message")
```

### 5. Зависимости

При добавлении новых зависимостей:
1. Добавить в `requirements.txt`
2. Проверить совместимость версий
3. Учитывать зависимости MCP SDK (mcp library)

### 6. Типизация

Используйте type hints:

```python
from typing import Optional, Dict, List, Tuple

async def my_func(param: str) -> Optional[Dict[str, Any]]:
	...
```

### 7. Pydantic

Для валидации всегда используйте Pydantic:

```python
from pydantic import BaseModel, Field

class MyModel(BaseModel):
	field: str = Field(..., description="Required field")
	optional: Optional[int] = None
```

---

## Тестирование

### Health check

```bash
# Stdio режим - проверка подключения к 1С
python -m src.py_server stdio --log-level DEBUG

# HTTP режим - проверка endpoints
curl http://localhost:8000/health
curl http://localhost:8000/info
```

---

**Конец документации**

Этот файл содержит полное описание архитектуры, компонентов и взаимосвязей MCP-прокси сервера. Используйте его как справочник при генерации кода, добавлении новых фич или рефакторинге существующих модулей.

