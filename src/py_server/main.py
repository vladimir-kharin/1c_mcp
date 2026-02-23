"""Основной файл запуска MCP-прокси сервера."""

import asyncio
import logging
import os
import sys
from typing import Optional
import argparse
from pathlib import Path

from dotenv import load_dotenv

from .config import get_config
from .http_server import run_http_server
from .stdio_server import run_stdio_server


def setup_logging(level: str = "INFO"):
	"""Настройка логирования.
	
	Args:
		level: Уровень логирования
	"""
	logging.basicConfig(
		level=getattr(logging, level.upper()),
		format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
		handlers=[
			logging.StreamHandler(sys.stderr)  # Логи должны идти в stderr, не в stdout!
		]
	)


def create_parser() -> argparse.ArgumentParser:
	"""Создание парсера аргументов командной строки."""
	parser = argparse.ArgumentParser(
		description="MCP-прокси сервер для взаимодействия с 1С",
		formatter_class=argparse.RawDescriptionHelpFormatter,
		epilog="""
Примеры использования:

  # Запуск в режиме stdio (по умолчанию)
  python -m src.py_server
  python -m src.py_server stdio

  # Запуск HTTP-сервера на порту 8000
  python -m src.py_server http --port 8000

  # Запуск с конфигурацией из .env файла
  python -m src.py_server --env-file .env

Переменные окружения:
  MCP_ONEC_URL           - URL базы 1С (обязательно)
  MCP_ONEC_USERNAME      - Имя пользователя 1С (обязательно при auth_mode=none)
  MCP_ONEC_PASSWORD      - Пароль пользователя 1С (обязательно при auth_mode=none)
  MCP_ONEC_SERVICE_ROOT  - Корневой URL HTTP-сервиса (по умолчанию: mcp)
  MCP_HOST               - Хост HTTP-сервера (по умолчанию: 127.0.0.1)
  MCP_PORT               - Порт HTTP-сервера (по умолчанию: 8000)
  MCP_LOG_LEVEL          - Уровень логирования (по умолчанию: INFO)
  MCP_AUTH_MODE          - Режим авторизации: none или oauth2 (по умолчанию: none)
  MCP_PUBLIC_URL         - Публичный URL для OAuth2 (опционально)
  MCP_OAUTH2_CODE_TTL    - TTL authorization code в секундах (по умолчанию: 120)
  MCP_OAUTH2_ACCESS_TTL  - TTL access token в секундах (по умолчанию: 3600)
  MCP_OAUTH2_REFRESH_TTL - TTL refresh token в секундах (по умолчанию: 1209600)
		"""
	)
	
	# Режим работы как позиционный аргумент с значением по умолчанию
	parser.add_argument(
		"mode",
		nargs="?",
		default="stdio",
		choices=["stdio", "http"],
		help="Режим работы сервера (по умолчанию: stdio)"
	)
	
	# Общие аргументы доступны всегда
	parser.add_argument(
		"--env-file",
		type=str,
		help="Путь к .env файлу с конфигурацией"
	)
	parser.add_argument(
		"--onec-url",
		type=str,
		help="URL базы 1С"
	)
	parser.add_argument(
		"--onec-username",
		type=str,
		help="Имя пользователя 1С"
	)
	parser.add_argument(
		"--onec-password",
		type=str,
		help="Пароль пользователя 1С"
	)
	parser.add_argument(
		"--onec-service-root",
		type=str,
		help="Корневой URL HTTP-сервиса в 1С"
	)
	parser.add_argument(
		"--log-level",
		type=str,
		choices=["DEBUG", "INFO", "WARNING", "ERROR"],
		help="Уровень логирования"
	)
	
	# HTTP-специфичные аргументы
	parser.add_argument(
		"--host", 
		type=str, 
		help="Хост для HTTP-сервера (только для режима http)"
	)
	parser.add_argument(
		"--port", 
		type=int, 
		help="Порт для HTTP-сервера (только для режима http)"
	)
	
	# OAuth2 аргументы
	parser.add_argument(
		"--auth-mode",
		type=str.lower,
		choices=["none", "oauth2"],
		help="Режим авторизации: none или oauth2"
	)
	parser.add_argument(
		"--public-url",
		type=str,
		help="Публичный URL прокси для OAuth2"
	)
	
	return parser


async def main():
	"""Основная функция."""
	# Принудительная настройка кодировки UTF-8 для Windows
	if sys.platform == "win32":
		import locale
		
		# Устанавливаем кодировку для Python I/O
		os.environ['PYTHONIOENCODING'] = 'utf-8'
		
		# Устанавливаем локаль
		try:
			locale.setlocale(locale.LC_ALL, 'ru_RU.UTF-8')
		except:
			try:
				locale.setlocale(locale.LC_ALL, 'Russian_Russia.1251')
			except:
				pass  # Игнорируем ошибки локали
	
	# Убеждаемся, что stderr работает без буферизации
	sys.stderr.flush()
	
	parser = create_parser()
	args = parser.parse_args()
	
	# Загружаем .env файл если указан
	if args.env_file:
		env_path = Path(args.env_file)
		if env_path.exists():
			load_dotenv(env_path)
		else:
			print(f"Предупреждение: файл {args.env_file} не найден", file=sys.stderr)
	else:
		# Пытаемся загрузить .env из текущей директории
		load_dotenv()
	
	# ИСПРАВЛЕНИЕ: Устанавливаем переменные окружения из аргументов ДО создания Config
	if args.onec_url:
		os.environ["MCP_ONEC_URL"] = args.onec_url
	if args.onec_username:
		os.environ["MCP_ONEC_USERNAME"] = args.onec_username
	if args.onec_password is not None:
		os.environ["MCP_ONEC_PASSWORD"] = args.onec_password
	if args.onec_service_root:
		os.environ["MCP_ONEC_SERVICE_ROOT"] = args.onec_service_root
	if args.host:
		os.environ["MCP_HOST"] = args.host
	if args.port:
		os.environ["MCP_PORT"] = str(args.port)
	if args.log_level:
		os.environ["MCP_LOG_LEVEL"] = args.log_level
	if args.auth_mode:
		os.environ["MCP_AUTH_MODE"] = args.auth_mode
	if args.public_url:
		os.environ["MCP_PUBLIC_URL"] = args.public_url
	
	# Получаем конфигурацию (теперь валидация пройдет успешно)
	try:
		config = get_config()
		
		# Убираем старые переопределения - теперь они не нужны
		# Все значения уже установлены через переменные окружения
			
	except Exception as e:
		print(f"Ошибка конфигурации: {e}", file=sys.stderr)
		print("\nПроверьте, что указаны все обязательные параметры:", file=sys.stderr)
		print("- MCP_ONEC_URL (URL базы 1С)", file=sys.stderr)
		sys.exit(1)
	
	# Настройка логирования
	setup_logging(config.log_level)
	logger = logging.getLogger(__name__)

	# Валидация режима авторизации
	if args.mode == "stdio" and config.auth_mode == "oauth2":
		logger.error("OAuth2 не поддерживается в режиме stdio. Используйте auth_mode=none.")
		sys.exit(1)

	if config.auth_mode == "none":
		if not config.onec_username or not config.onec_password:
			logger.error("Для auth_mode=none обязательны MCP_ONEC_USERNAME и MCP_ONEC_PASSWORD.")
			sys.exit(1)
	else:
		if config.onec_username or config.onec_password:
			logger.warning("MCP_ONEC_USERNAME/MCP_ONEC_PASSWORD заданы, но будут игнорироваться при auth_mode=oauth2.")
	
	# Отладочная информация через logger (подчиняется уровню логирования)
	logger.debug(f"Режим работы: {args.mode}")
	logger.debug(f"Аргументы: {args}")
	logger.debug(f"Python версия: {sys.version}")
	logger.debug(f"Рабочая директория: {os.getcwd()}")
	
	logger.debug(f"Запуск MCP-прокси сервера в режиме: {args.mode}")
	logger.debug(f"Подключение к 1С: {config.onec_url}")
	logger.debug(f"Пользователь: {config.onec_username}")
	
	try:
		if args.mode == "stdio":
			await run_stdio_server(config)
		elif args.mode == "http":
			logger.debug(f"HTTP-сервер будет запущен на {config.host}:{config.port}")
			await run_http_server(config)
		else:
			logger.error(f"Неизвестный режим: {args.mode}")
			sys.exit(1)
			
	except KeyboardInterrupt:
		logger.debug("Получен сигнал прерывания, завершение работы...")
	except Exception as e:
		logger.error(f"Критическая ошибка: {e}")
		sys.exit(1)


if __name__ == "__main__":
	asyncio.run(main()) 
