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
	onec_url: str = Field(..., description="URL базы 1С")
	onec_username: Optional[str] = Field(default=None, description="Имя пользователя 1С")
	onec_password: Optional[str] = Field(default=None, description="Пароль пользователя 1С")
	onec_service_root: str = Field(default="mcp", description="Корневой URL HTTP-сервиса в 1С")
	
	# Настройки MCP
	server_name: str = Field(default="1C Configuration Data Tools", description="Имя MCP-сервера")
	server_version: str = Field(default="1.0.0", description="Версия MCP-сервера")
	
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
	
	class Config:
		env_file = ".env"
		env_prefix = "MCP_"


def get_config() -> Config:
	"""Получить конфигурацию."""
	return Config() 
