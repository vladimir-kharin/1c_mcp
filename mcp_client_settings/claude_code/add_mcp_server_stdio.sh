# Команда добавления mcp-сервера для claude_code
# Определяет подключение к 1С через стандартный ввод-вывод (stdio)
# с использованием Python-скрипта в качестве прокси-сервера.

claude mcp add --transport stdio 1c-md \
  # --env PYTHONPATH: путь к репозиторию 1C_MCP
  --env PYTHONPATH=D:/rep/1c_mcp \
  # --env PYTHONIOENCODING: кодировка для взаимодействия с Python
  --env PYTHONIOENCODING=utf-8 \
  # --env MCP_ONEC_URL: адрес опубликованной на веб-сервере базы 1С
  --env MCP_ONEC_URL=http://localhost/my_base \
  # --env MCP_ONEC_USERNAME: имя пользователя 1С
  --env MCP_ONEC_USERNAME=<пользователь 1С> \
  # --env MCP_ONEC_PASSWORD: пароль пользователя 1С
  --env MCP_ONEC_PASSWORD=<пароль пользователя 1С> \
  # --: указывает, что далее следует команда для запуска.
  # <путь к Python если нужно>python.exe -m src.py_server: команда запуска Python-сервера
  -- d:/rep/1c_mcp/venv/Scripts/python.exe -m src.py_server
