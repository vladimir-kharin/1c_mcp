# Dockerfile для 1C MCP Proxy
FROM python:3.13-slim

# Метаданные
LABEL maintainer="1C MCP Proxy"
LABEL description="MCP-прокси для решения инфраструктурных проблем подключения к MCP-серверу, реализованному в 1С:Предприятие"

# Рабочая директория
WORKDIR /app

# Копирование файлов зависимостей
COPY src/py_server/requirements.txt /app/src/py_server/requirements.txt

# Установка зависимостей
RUN pip install --no-cache-dir -r /app/src/py_server/requirements.txt

# Копирование исходного кода
COPY src/py_server /app/src/py_server

# Порт по умолчанию
EXPOSE 8000

# Healthcheck
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
  CMD python -c "import httpx; httpx.get('http://localhost:8000/health', timeout=5.0)" || exit 1

# Запуск в HTTP режиме
ENTRYPOINT ["python", "-m", "src.py_server"]
CMD ["http", "--host", "0.0.0.0", "--port", "8000"]
