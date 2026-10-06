"""Граница подтверждения execute_code.

Ожидания для cancel и клиента без elicitation взяты из контракта MCP, а не из
текста сообщения:

- mcp.types.ElicitResult.action: accept | decline | cancel. Выполнение кода
  допустимо только при action=accept и подтверждении в content.
- Клиент объявляет capability elicitation. Если её нет,
  ServerSession.check_client_capability возвращает False, и сервер не должен
  слать elicitation/create (session.elicit) и не должен вызывать инструмент.
"""

import sys
import types
import unittest
from pathlib import Path

SRC = Path(__file__).resolve().parents[1] / "src"
sys.path.insert(0, str(SRC))

# Импорт подмодуля без py_server/__init__.py: тот тянет HTTP-стек.
_pkg = types.ModuleType("py_server")
_pkg.__path__ = [str(SRC / "py_server")]
_pkg.__package__ = "py_server"
sys.modules["py_server"] = _pkg

from mcp import types as mcp_types
from mcp.server.lowlevel.server import request_ctx
from mcp.server.session import ServerSession
from mcp.shared.context import RequestContext

from py_server.config import Config
from py_server.mcp_server import MCPProxy


PROXY_CONFIRMATION = {"action": "accept", "confirmed": True}

SUPPORTED_CAPABILITIES = mcp_types.ClientCapabilities(
	elicitation=mcp_types.ElicitationCapability(
		form=mcp_types.FormElicitationCapability()
	)
)
UNSUPPORTED_CAPABILITIES = mcp_types.ClientCapabilities()


class FakeOneC:
	def __init__(self):
		self.calls = []

	async def list_tools(self):
		return [mcp_types.Tool(
			name="execute_code",
			description="Выполнить код",
			inputSchema={
				"type": "object",
				"properties": {
					"code": {"type": "string"},
					"_confirmation": {"type": "object"},
				},
				"additionalProperties": True,
			},
		)]

	async def call_tool(self, name, arguments):
		self.calls.append((name, arguments))
		return mcp_types.CallToolResult(
			content=[mcp_types.TextContent(type="text", text="ok")],
			isError=False,
		)


class FakeSession:
	"""Сессия с настоящей проверкой capability из SDK."""

	check_client_capability = ServerSession.check_client_capability

	def __init__(self, capabilities, elicit_result=None):
		self._client_params = mcp_types.InitializeRequestParams(
			protocolVersion="2025-06-18",
			capabilities=capabilities,
			clientInfo=mcp_types.Implementation(name="test-client", version="0"),
		)
		self.elicit_result = elicit_result
		self.elicit_calls = []

	async def elicit(self, message, requestedSchema, related_request_id=None):
		self.elicit_calls.append({
			"message": message,
			"requestedSchema": requestedSchema,
			"related_request_id": related_request_id,
		})
		return self.elicit_result


def elicit(action, content=None):
	return mcp_types.ElicitResult(action=action, content=content)


class ExecuteCodeConfirmationTests(unittest.IsolatedAsyncioTestCase):
	def setUp(self):
		self.proxy = MCPProxy(Config(_env_file=None, auth_mode="none"))
		self.onec = FakeOneC()

	async def dispatch(self, session, arguments, name="execute_code"):
		ctx = RequestContext(
			request_id="req-1",
			meta=None,
			session=session,
			lifespan_context={"onec_client": self.onec},
		)
		token = request_ctx.set(ctx)
		try:
			handler = self.proxy.server.request_handlers[mcp_types.CallToolRequest]
			return await handler(mcp_types.CallToolRequest(
				params=mcp_types.CallToolRequestParams(name=name, arguments=arguments)
			))
		finally:
			request_ctx.reset(token)

	def texts(self, result):
		return [block.text for block in result.root.content]

	def test_elicitation_contract_actions(self):
		actions = mcp_types.ElicitResult.model_json_schema()["properties"]["action"]["enum"]
		self.assertEqual(actions, ["accept", "decline", "cancel"])

	def test_sdk_rejects_client_without_elicitation_capability(self):
		session = FakeSession(UNSUPPORTED_CAPABILITIES)
		asked = mcp_types.ClientCapabilities(
			elicitation=mcp_types.ElicitationCapability()
		)
		self.assertFalse(session.check_client_capability(asked))
		session = FakeSession(SUPPORTED_CAPABILITIES)
		self.assertTrue(session.check_client_capability(asked))

	async def test_acceptance_forwards_proxy_confirmation(self):
		session = FakeSession(
			SUPPORTED_CAPABILITIES,
			elicit("accept", {"confirmed": True}),
		)
		await self.dispatch(session, {"code": "Сообщить(1);"})

		self.assertEqual(len(session.elicit_calls), 1)
		self.assertIn("Сообщить(1);", session.elicit_calls[0]["message"])
		self.assertEqual(self.onec.calls, [(
			"execute_code",
			{"code": "Сообщить(1);", "_confirmation": PROXY_CONFIRMATION},
		)])

	async def test_decline_does_not_call_tool(self):
		session = FakeSession(SUPPORTED_CAPABILITIES, elicit("decline"))
		result = await self.dispatch(session, {"code": "Сообщить(1);"})

		self.assertEqual(self.onec.calls, [])
		self.assertEqual(self.texts(result), ["Выполнение кода отменено пользователем"])

	async def test_blank_code_does_not_call_tool_or_prompt(self):
		session = FakeSession(
			SUPPORTED_CAPABILITIES,
			elicit("accept", {"confirmed": True}),
		)
		result = await self.dispatch(session, {"code": "  \n\t", "_confirmation": PROXY_CONFIRMATION})

		self.assertEqual(session.elicit_calls, [])
		self.assertEqual(self.onec.calls, [])
		self.assertEqual(self.texts(result), ["Не указан код для выполнения (параметр code)"])

	async def test_caller_confirmation_cannot_bypass_prompt(self):
		caller_marker = {"action": "accept", "confirmed": True, "bypass": True}
		session = FakeSession(SUPPORTED_CAPABILITIES, elicit("decline"))
		await self.dispatch(session, {"code": "Сообщить(1);", "_confirmation": caller_marker})

		self.assertEqual(len(session.elicit_calls), 1)
		self.assertEqual(self.onec.calls, [])

		session = FakeSession(
			SUPPORTED_CAPABILITIES,
			elicit("accept", {"confirmed": True}),
		)
		await self.dispatch(session, {"code": "Сообщить(1);", "_confirmation": caller_marker})
		forwarded = self.onec.calls[0][1]["_confirmation"]
		self.assertEqual(forwarded, PROXY_CONFIRMATION)
		self.assertNotIn("bypass", forwarded)

	async def test_cancel_is_not_acceptance_even_with_confirmed_content(self):
		# Контракт: cancel — закрытие диалога без выбора, не согласие.
		session = FakeSession(
			SUPPORTED_CAPABILITIES,
			elicit("cancel", {"confirmed": True}),
		)
		result = await self.dispatch(session, {"code": "Сообщить(1);"})

		self.assertEqual(len(session.elicit_calls), 1)
		self.assertEqual(self.onec.calls, [])
		self.assertEqual(self.texts(result), ["Выполнение кода отменено пользователем"])

	async def test_unsupported_elicitation_does_not_prompt_or_execute(self):
		# Контракт: без capability сервер не отправляет elicitation/create.
		session = FakeSession(
			UNSUPPORTED_CAPABILITIES,
			elicit("accept", {"confirmed": True}),
		)
		result = await self.dispatch(session, {"code": "Сообщить(1);"})

		self.assertEqual(session.elicit_calls, [])
		self.assertEqual(self.onec.calls, [])
		self.assertEqual(
			self.texts(result),
			["Клиент MCP не поддерживает подтверждение. Выполнение кода отменено."],
		)


if __name__ == "__main__":
	unittest.main()
