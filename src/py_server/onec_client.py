"""Клиент для взаимодействия с 1С.

OneCClient — транспортно-независимое ядро: формирует JSON-RPC запросы MCP и
разбирает ответы. Доставку строки запроса/ответа выполняет объект-транспорт
(см. transport.py). Выбор транспорта — фабрика create_onec_client.
"""

import json
import logging
from typing import Any, Dict, List, Optional, TYPE_CHECKING
import httpx
from mcp import types
from mcp.server.lowlevel.helper_types import ReadResourceContents
import base64

from .transport import Transport, HttpTransport, FileTransport, FtpFileTransport, ReverseHttpTransport

if TYPE_CHECKING:
    from .config import Config


logger = logging.getLogger(__name__)


class OneCClient:
    """Транспортно-независимый клиент MCP-сервера 1С."""

    def __init__(self, transport: Transport):
        """Инициализация клиента.

        Args:
            transport: Объект-транспорт (HttpTransport / FileTransport),
                доставляющий строку JSON-RPC запроса и возвращающий строку ответа.
        """
        self._transport = transport

    async def check_health(self) -> bool:
        """Проверить доступность 1С через текущий транспорт."""
        return await self._transport.check_health()

    async def call_rpc(self, method: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Выполнить JSON-RPC запрос к 1С.

        Args:
            method: Имя метода
            params: Параметры метода

        Returns:
            Результат выполнения метода
        """
        try:
            # Формируем JSON-RPC запрос
            rpc_request = {
                "jsonrpc": "2.0",
                "id": 1,
                "method": method,
                "params": params or {}
            }

            logger.debug(f"JSON-RPC запрос: {rpc_request}")

            # Доставку строки запроса/ответа выполняет транспорт
            request_body = json.dumps(rpc_request, ensure_ascii=False)
            response_text = await self._transport.send(request_body)

            rpc_response = json.loads(response_text)
            logger.debug(f"JSON-RPC ответ: {rpc_response}")

            # Проверяем на ошибки JSON-RPC
            if "error" in rpc_response:
                error = rpc_response["error"]
                raise Exception(f"JSON-RPC ошибка {error.get('code', 'unknown')}: {error.get('message', 'Unknown error')}")

            return rpc_response.get("result", {})

        except httpx.HTTPError as e:
            logger.error(f"Ошибка HTTP при вызове RPC: {e}")
            raise
        except json.JSONDecodeError as e:
            logger.error(f"Ошибка парсинга JSON ответа RPC: {e}")
            raise

    async def list_tools(self) -> List[types.Tool]:
        """Получить список доступных инструментов.

        Returns:
            Список инструментов MCP
        """
        result = await self.call_rpc("tools/list")
        tools_data = result.get("tools", [])

        tools = []
        for tool_data in tools_data:
            tool = types.Tool(
                name=tool_data["name"],
                description=tool_data.get("description", ""),
                inputSchema=tool_data.get("inputSchema", {})
            )
            tools.append(tool)

        return tools

    async def call_tool(self, name: str, arguments: Dict[str, Any]) -> types.CallToolResult:
        """Вызвать инструмент.

        Args:
            name: Имя инструмента
            arguments: Аргументы инструмента

        Returns:
            Результат выполнения инструмента
        """
        result = await self.call_rpc("tools/call", {
            "name": name,
            "arguments": arguments
        })

        # Преобразуем результат в формат MCP
        content = []
        if "content" in result:
            for item in result["content"]:
                content_type = item.get("type")

                if content_type == "text":
                    content.append(types.TextContent(
                        type="text",
                        text=item.get("text", "")
                    ))

                elif content_type == "image":
                    content.append(types.ImageContent(
                        type="image",
                        data=item.get("data", ""),
                        mimeType=item.get("mimeType", "image/png")
                    ))

                else:
                    # Неизвестный тип - логируем предупреждение и обрабатываем как текст
                    logger.warning(f"Неизвестный тип контента: {content_type}, обрабатываем как текст")
                    content.append(types.TextContent(
                        type="text",
                        text=str(item.get("text", item))
                    ))

        return types.CallToolResult(
            content=content,
            isError=result.get("isError", False)
        )

    async def list_resources(self) -> List[types.Resource]:
        """Получить список доступных ресурсов.

        Returns:
            Список ресурсов MCP
        """
        result = await self.call_rpc("resources/list")
        resources_data = result.get("resources", [])

        resources = []
        for resource_data in resources_data:
            resource = types.Resource(
                uri=resource_data["uri"],
                name=resource_data.get("name", ""),
                description=resource_data.get("description", ""),
                mimeType=resource_data.get("mimeType")
            )
            resources.append(resource)

        return resources

    async def read_resource(self, uri: str) -> List[ReadResourceContents]:
        """Прочитать ресурс.

        Args:
            uri: URI ресурса

        Returns:
            Список частей содержимого ресурса (текст/бинарные данные)
        """
        # MCP декоратор может передать сюда AnyUrl; приводим к строке перед JSON-RPC
        uri_str = str(uri)
        result = await self.call_rpc("resources/read", {"uri": uri_str})

        # Преобразуем результат в Iterable[ReadResourceContents] для декоратора read_resource
        contents: List[ReadResourceContents] = []
        if "contents" in result:
            for item in result["contents"]:
                content_type = item.get("type")
                mime_type = item.get("mimeType")
                if content_type == "text":
                    contents.append(ReadResourceContents(
                        content=item.get("text", ""),
                        mime_type=mime_type or "text/plain"
                    ))
                elif content_type == "blob":
                    blob_b64 = item.get("blob", "") or ""
                    try:
                        data_bytes = base64.b64decode(blob_b64)
                    except Exception:
                        # В случае некорректной base64 — вернем как текст для диагностики
                        contents.append(ReadResourceContents(
                            content=f"Invalid base64 blob: length={len(blob_b64)}",
                            mime_type="text/plain"
                        ))
                    else:
                        contents.append(ReadResourceContents(
                            content=data_bytes,
                            mime_type=mime_type or "application/octet-stream"
                        ))
                else:
                    # Fallback: сериализуем как текст
                    contents.append(ReadResourceContents(
                        content=f"Unknown resource content type '{content_type}': {json.dumps(item, ensure_ascii=False)}",
                        mime_type="text/plain"
                    ))
        else:
            # Если сервер вернул не ожидаемую структуру — вернем весь результат текстом
            contents.append(ReadResourceContents(
                content=json.dumps(result, ensure_ascii=False),
                mime_type="application/json"
            ))

        return contents

    async def list_prompts(self) -> List[types.Prompt]:
        """Получить список доступных промптов.

        Returns:
            Список промптов MCP
        """
        result = await self.call_rpc("prompts/list")
        prompts_data = result.get("prompts", [])

        prompts = []
        for prompt_data in prompts_data:
            arguments = []
            if "arguments" in prompt_data:
                for arg_data in prompt_data["arguments"]:
                    arguments.append(types.PromptArgument(
                        name=arg_data["name"],
                        description=arg_data.get("description", ""),
                        required=arg_data.get("required", False)
                    ))

            prompt = types.Prompt(
                name=prompt_data["name"],
                description=prompt_data.get("description", ""),
                arguments=arguments
            )
            prompts.append(prompt)

        return prompts

    async def get_prompt(self, name: str, arguments: Optional[Dict[str, str]] = None) -> types.GetPromptResult:
        """Получить промпт.

        Args:
            name: Имя промпта
            arguments: Аргументы промпта

        Returns:
            Результат промпта
        """
        result = await self.call_rpc("prompts/get", {
            "name": name,
            "arguments": arguments or {}
        })

        # Преобразуем результат в формат MCP
        messages = []
        if "messages" in result:
            for msg_data in result["messages"]:
                content = types.TextContent(
                    type="text",
                    text=msg_data.get("content", {}).get("text", "")
                )

                message = types.PromptMessage(
                    role=msg_data.get("role", "user"),
                    content=content
                )
                messages.append(message)

        return types.GetPromptResult(
            description=result.get("description", ""),
            messages=messages
        )

    async def close(self):
        """Закрыть клиент (освобождает ресурсы транспорта)."""
        await self._transport.close()


def create_onec_client(config: "Config", username: Optional[str], password: Optional[str]) -> OneCClient:
    """Создать OneCClient с транспортом, выбранным по конфигурации.

    Статичные параметры (base_url, service_root, unlock_code, тип транспорта)
    берутся из config; динамические креды (username/password, зависят от сессии
    в режиме OAuth2) передаются аргументами.

    Args:
        config: Конфигурация прокси.
        username: Имя пользователя 1С (для HTTP-транспорта; для файлового не нужно).
        password: Пароль пользователя 1С (аналогично).

    Returns:
        Готовый OneCClient с настроенным транспортом.
    """
    transport_kind = getattr(config, "transport", "http")

    if transport_kind == "http":
        transport: Transport = HttpTransport(
            base_url=config.onec_url,
            username=username,
            password=password,
            service_root=config.onec_service_root,
            unlock_code=config.onec_unlock_code,
            timeout=config.http_timeout,
        )
    elif transport_kind == "file":
        if not config.file_exchange_dir:
            raise ValueError("transport=file требует MCP_FILE_EXCHANGE_DIR (папка обмена)")
        exchange = config.file_exchange_dir.strip()
        if exchange.lower().startswith("ftps://"):
            raise ValueError("FTPS не поддерживается — укажите ftp:// (агент 1С тоже работает без шифрования)")
        if exchange.lower().startswith("ftp://"):
            # Папка обмена на FTP-сервере (например, на третьей машине).
            # Интервал опроса по умолчанию реже, чем для локальной папки:
            # каждый опрос — LIST-команда к удалённому серверу.
            transport = FtpFileTransport(
                url=exchange,
                poll_interval=config.file_poll_interval if config.file_poll_interval is not None else 1.0,
                timeout=config.file_timeout,
            )
        else:
            transport = FileTransport(
                exchange_dir=exchange,
                poll_interval=config.file_poll_interval if config.file_poll_interval is not None else 0.2,
                timeout=config.file_timeout,
            )
    elif transport_kind == "httppoll":
        transport = ReverseHttpTransport(
            host=config.httppoll_host,
            port=config.httppoll_port,
            timeout=config.httppoll_timeout,
        )
    else:
        raise ValueError(f"Неизвестный транспорт MCP_TRANSPORT={transport_kind!r} (ожидается 'http', 'file' или 'httppoll')")

    return OneCClient(transport)
