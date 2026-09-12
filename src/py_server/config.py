"""Конфигурация MCP-прокси сервера."""

import os
from typing import Optional, Literal
from pydantic import Field, field_validator
from pydantic_settings import BaseSettings


class Config(BaseSettings):
	"""Настройки MCP-прокси сервера."""
	
	# Настройки сервера
	host: str = Field(default="127.0.0.1", description="Хост для HTTP-сервера")
	port: int = Field(default=8000, description="Порт для HTTP-сервера")
	
	# Настройки подключения к 1С
	# Обязателен только при transport=http (проверяется в main.py) — file/httppoll
	# ходят в 1С без URL.
	onec_url: str = Field(default="", description="URL базы 1С (обязателен при transport=http)")
	onec_username: Optional[str] = Field(default=None, description="Имя пользователя 1С")
	onec_password: Optional[str] = Field(default=None, description="Пароль пользователя 1С")
	onec_service_root: str = Field(default="mcp", description="Корневой URL HTTP-сервиса в 1С")
	onec_unlock_code: Optional[str] = Field(default=None, description="Код разрешения (unlock code) для входа при блокировке начала сеансов; передаётся как query-параметр uc")

	# Транспорт до 1С: http (HTTP-сервис), file (обмен через папку) или
	# httppoll (обратный HTTP: агент 1С сам опрашивает листенер прокси)
	transport: Literal["http", "file", "httppoll"] = Field(default="http", description="Транспорт до 1С: http, file или httppoll")
	http_timeout: float = Field(default=120.0, description="Сколько (сек) ждать ответ 1С для transport=http, затем ошибка")
	file_exchange_dir: Optional[str] = Field(default=None, description="Папка обмена для transport=file: локальный путь/UNC или ftp://user:pass@host:port/путь (внутри — подпапки in/ и out/)")
	file_poll_interval: Optional[float] = Field(default=None, description="Как часто (сек) проверять появление ответа в out/ для transport=file; по умолчанию 0.2 для папки и 1.0 для FTP")
	file_timeout: float = Field(default=30.0, description="Сколько (сек) ждать ответ 1С для transport=file, затем ошибка")

	# Настройки transport=httppoll (листенер, который опрашивает агент 1С)
	httppoll_host: str = Field(default="127.0.0.1", description="Адрес листенера httppoll")
	httppoll_port: int = Field(default=9090, description="Порт листенера httppoll (его же пробрасывает NX-туннель)")
	httppoll_timeout: float = Field(default=60.0, description="Сколько (сек) ждать ответ агента 1С для transport=httppoll, затем ошибка")
	
	# Настройки MCP
	server_name: str = Field(default="1C Configuration Data Tools", description="Имя MCP-сервера")
	server_version: str = Field(default="1.6.1", description="Версия MCP-сервера")
	
	# Настройки логирования
	log_level: str = Field(default="INFO", description="Уровень логирования")
	
	# Настройки безопасности
	cors_origins: list[str] = Field(default=["*"], description="Разрешенные CORS origins")
	
	# Настройки авторизации OAuth2
	auth_mode: Literal["none", "oauth2"] = Field(default="none", description="Режим авторизации: none или oauth2")

	@field_validator("auth_mode", mode="before")
	@classmethod
	def normalize_auth_mode(cls, v: str) -> str:
		if isinstance(v, str):
			return v.lower()
		return v
	public_url: Optional[str] = Field(default=None, description="Публичный URL прокси для OAuth2 (если не задан, формируется из запроса)")
	oauth2_code_ttl: int = Field(default=120, description="TTL authorization code в секундах")
	oauth2_access_ttl: int = Field(default=3600, description="TTL access token в секундах")
	oauth2_refresh_ttl: int = Field(default=1209600, description="TTL refresh token в секундах (14 дней)")
	oauth2_allowed_redirect_uris: Optional[str] = Field(default=None, description="Разрешённые redirect_uri через запятую (пусто = принимаются любые). Элемент с '*' на конце — совпадение по префиксу; для localhost/127.0.0.1 порт игнорируется")
	
	class Config:
		env_file = ".env"
		env_prefix = "MCP_"


def get_config() -> Config:
	"""Получить конфигурацию."""
	return Config() 
