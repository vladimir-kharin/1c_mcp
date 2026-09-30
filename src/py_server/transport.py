"""Транспорты для OneCClient.

Транспорт отвечает ТОЛЬКО за доставку строки JSON-RPC запроса в 1С и получение
строки ответа. Формирование JSON-RPC и разбор результата — в OneCClient.
Контракт зеркалит 1С-сторону (mcp_Диспетчер.ОбработатьСтроку: строка → строка).
"""

import asyncio
import json
import logging
import os
import time
import uuid
from pathlib import Path
from typing import Optional, Protocol, runtime_checkable
import httpx


logger = logging.getLogger(__name__)


@runtime_checkable
class Transport(Protocol):
    """Контракт транспорта: строка запроса → строка ответа."""

    async def send(self, request_body: str) -> str:
        """Доставить тело JSON-RPC запроса и вернуть тело ответа.

        Для notifications (запрос без id) 1С отвечает пустым телом — возвращается "".
        """
        ...

    async def check_health(self) -> bool:
        """Проверить доступность 1С данным транспортом."""
        ...

    async def close(self) -> None:
        """Освободить ресурсы транспорта."""
        ...


class HttpTransport:
    """HTTP-транспорт к HTTP-сервису 1С (прямой режим или через прокси).

    Переносит без изменений логику работы с httpx из прежнего OneCClient.
    """

    def __init__(self, base_url: str, username: Optional[str], password: Optional[str],
                 service_root: str = "mcp", unlock_code: Optional[str] = None,
                 timeout: float = 30.0):
        """Инициализация транспорта.

        Args:
            base_url: Базовый URL 1С (например, http://localhost/base)
            username: Имя пользователя
            password: Пароль
            service_root: Корневой URL HTTP-сервиса (по умолчанию "mcp")
            unlock_code: Код разрешения (unlock code) для входа при блокировке
                начала сеансов. Передаётся в каждый запрос как query-параметр uc.
            timeout: Сколько (сек) ждать ответ 1С, затем httpx-таймаут.
        """
        self.base_url = base_url.rstrip('/')
        self.service_root = service_root.strip('/')
        self.auth = httpx.BasicAuth(username, password)
        self.timeout = timeout

        # Код разрешения для обхода блокировки начала сеансов (?uc=<код>)
        self.request_params = {"uc": unlock_code} if unlock_code else None

        # Используем метод для создания клиента
        self.client = self._create_client()

        # Формируем базовый URL для HTTP-сервиса
        self.service_base_url = f"{self.base_url}/hs/{self.service_root}"
        logger.debug(f"Базовый URL HTTP-сервиса: {self.service_base_url}")

    def _create_client(self) -> httpx.AsyncClient:
        """Создание нового HTTP-клиента."""
        return httpx.AsyncClient(
            auth=self.auth,
            timeout=self.timeout,
            headers={"Content-Type": "application/json"}
        )

    async def _ensure_client(self):
        """Проверка состояния клиента и восстановление при необходимости."""
        if self.client.is_closed:
            logger.warning("HTTP-клиент был закрыт, выполняется восстановление...")
            self.client = self._create_client()
            logger.info("HTTP-клиент успешно восстановлен")

    async def send(self, request_body: str) -> str:
        """Отправить тело JSON-RPC запроса POST-ом на /rpc, вернуть тело ответа."""
        await self._ensure_client()

        url = f"{self.service_base_url}/rpc"

        response = await self.client.post(
            url,
            content=request_body.encode("utf-8"),
            params=self.request_params,
        )
        response.raise_for_status()

        return response.text

    async def check_health(self) -> bool:
        """Проверить состояние HTTP-сервиса 1С.

        Returns:
            True, если сервис доступен и здоров, иначе вызывает исключение.
        """
        import json

        try:
            # Проверяем и восстанавливаем клиент при необходимости
            await self._ensure_client()

            url = f"{self.service_base_url}/health"
            logger.debug(f"Запрос состояния здоровья: {url}")

            response = await self.client.get(url, params=self.request_params)
            response.raise_for_status()

            # Проверяем JSON ответ от 1C healthGET
            try:
                response_json = response.json()
                if response_json.get("status") == "ok":
                    logger.debug("Сервис 1С доступен и здоров (статус OK).")
                    return True
                else:
                    logger.warning(f"1C health check вернул неожиданный статус: {response_json}")
                    raise httpx.HTTPStatusError(f"1C service reported not healthy: {response_json}", request=response.request, response=response)
            except json.JSONDecodeError as e:
                logger.error(f"Ошибка парсинга JSON ответа health-check 1С: {response.text}")
                raise httpx.HTTPStatusError(f"Invalid JSON response from 1C health check: {e}", request=response.request, response=response)

        except httpx.HTTPError as e:
            logger.error(f"Ошибка HTTP при проверке состояния 1С: {type(e).__name__}: {str(e) or repr(e)}")
            raise

    async def close(self) -> None:
        """Закрыть HTTP-клиент."""
        await self.client.aclose()


class FileTransport:
    """Файловый транспорт: обмен с 1С-агентом через папку (для тестов без веб-сервера).

    Протокол (зеркалит форму mcp_УправлениеСервером):
    - запрос кладётся в `<exchange_dir>/in/<uuid>.json`;
    - 1С-агент по таймеру забирает `in/*.json`, обрабатывает через
      mcp_Диспетчер.ОбработатьСтроку и пишет ответ в `out/<то же имя>`,
      а запрос из `in/` удаляет;
    - Python опрашивает `out/<uuid>.json`, читает, удаляет.

    Запрос пишется атомарно (через временное имя + rename), чтобы 1С (маска
    `*.json`) не подхватил недописанный файл. Ответ 1С локально пишет НЕ атомарно,
    поэтому при незавершённой записи (JSON ещё не парсится) ждём следующий опрос.
    """

    def __init__(self, exchange_dir: str, poll_interval: float = 0.2, timeout: float = 30.0):
        """Инициализация транспорта.

        Args:
            exchange_dir: Папка обмена; внутри — подпапки in/ и out/.
            poll_interval: Как часто (сек) проверять появление ответа в out/.
            timeout: Сколько (сек) ждать ответ, затем TimeoutError.
        """
        self.exchange_dir = Path(exchange_dir)
        self.in_dir = self.exchange_dir / "in"
        self.out_dir = self.exchange_dir / "out"
        self.poll_interval = poll_interval
        self.timeout = timeout

    def _ensure_dirs(self) -> None:
        """Гарантировать наличие in/ и out/ (создание идемпотентно)."""
        self.in_dir.mkdir(parents=True, exist_ok=True)
        self.out_dir.mkdir(parents=True, exist_ok=True)

    async def send(self, request_body: str) -> str:
        """Положить запрос в in/, дождаться ответа в out/ (под тем же именем)."""
        self._ensure_dirs()

        # Notifications (запрос без id) 1С-агент не отвечает — не ждём ответа.
        # OneCClient всегда шлёт id, ветка на всякий случай.
        try:
            is_notification = "id" not in json.loads(request_body)
        except (json.JSONDecodeError, TypeError):
            is_notification = False

        name = f"{uuid.uuid4().hex}.json"
        req_path = self.in_dir / name
        resp_path = self.out_dir / name
        tmp_path = self.in_dir / f"{name}.tmp"

        # Атомарная запись запроса: пишем во временный файл, затем rename в *.json
        tmp_path.write_text(request_body, encoding="utf-8")
        os.replace(tmp_path, req_path)

        if is_notification:
            return ""

        deadline = time.monotonic() + self.timeout
        while True:
            if resp_path.exists():
                try:
                    # utf-8-sig снимает BOM, который пишет 1С ЗаписьТекста
                    text = resp_path.read_text(encoding="utf-8-sig")
                    json.loads(text)  # проверка, что ответ дописан целиком
                except (json.JSONDecodeError, UnicodeDecodeError, OSError):
                    # ответ ещё пишется — ждём следующий опрос
                    pass
                else:
                    try:
                        resp_path.unlink()
                    except OSError:
                        pass
                    return text

            if time.monotonic() >= deadline:
                # Уберём наш запрос, чтобы не копился, если агент не отвечает
                try:
                    req_path.unlink()
                except OSError:
                    pass
                raise TimeoutError(
                    f"Ответ 1С не получен за {self.timeout} с (файл {resp_path}). "
                    f"Проверьте, что 1С-агент запущен и опрашивает {self.in_dir}."
                )

            await asyncio.sleep(self.poll_interval)

    async def check_health(self) -> bool:
        """Проверить доступность ПАПКИ ОБМЕНА (не самой 1С).

        Файловый транспорт не может проверить, запущен ли 1С-агент, — это выяснится
        таймаутом на первом вызове. Здесь проверяется только доступность каталога.
        """
        try:
            self._ensure_dirs()
            # Проба на запись — каталог in/ действительно пригоден
            probe = self.in_dir / f".health_{uuid.uuid4().hex}.tmp"
            probe.write_text("", encoding="utf-8")
            probe.unlink()
        except OSError as e:
            logger.error(f"Папка обмена недоступна ({self.exchange_dir}): {e}")
            raise
        logger.info(
            f"Файловый транспорт: папка обмена доступна ({self.exchange_dir}: in/, out/). "
            f"Доступность 1С-агента этим НЕ проверяется — выяснится при первом вызове."
        )
        return True

    async def close(self) -> None:
        """Файловому транспорту нечего закрывать."""
        return None


class FtpFileTransport:
    """Файловый транспорт через FTP: та же папка обмена, но доступная прокси
    только по протоколу FTP.

    Сценарий: FTP-сервер на третьей машине, которую видят и прокси, и 1С —
    при этом ни общей файловой системы, ни прямой сети между ними нет
    (httppoll в такой топологии не работает: агенту 1С не достучаться до
    листенера прокси).

    Протокол обмена идентичен FileTransport (запрос in/<uuid>.json, ответ
    out/<то же имя>); агент 1С работает с той же папкой своей FTP-веткой.
    Атомарность записи запроса — загрузка под именем *.json.tmp и
    переименование (RNFR/RNTO), чтобы агент (маска *.json) не подхватил
    недописанный файл. Агент отвечает так же атомарно, но json.loads-проверка
    оставлена как страховка.

    Адрес: ftp://[пользователь[:пароль]@]хост[:порт]/путь — тот же формат,
    что на форме агента. FTPS не поддерживается (агент 1С тоже ходит без
    шифрования). ftplib синхронный, поэтому весь send выполняется одним
    блокирующим куском в worker-потоке (asyncio.to_thread); соединение
    открывается на каждый вызов — без разделяемого состояния и гонок.
    """

    def __init__(self, url: str, poll_interval: float = 1.0, timeout: float = 30.0):
        """Инициализация транспорта.

        Args:
            url: Адрес папки обмена: ftp://[user[:pass]@]host[:port]/path.
            poll_interval: Как часто (сек) проверять появление ответа в out/.
            timeout: Сколько (сек) ждать ответ, затем TimeoutError.
        """
        from urllib.parse import urlsplit, unquote

        parts = urlsplit(url.strip())
        if parts.scheme.lower() != "ftp":
            raise ValueError(f"FtpFileTransport ожидает адрес ftp://, получено: {url!r}")

        self.url = url.strip()
        self.host = parts.hostname or ""
        self.port = parts.port or 21
        self.user = unquote(parts.username) if parts.username else ""
        self.password = unquote(parts.password) if parts.password else ""
        if not self.host:
            raise ValueError(f"В FTP-адресе не указан хост: {url!r}")

        base = parts.path.rstrip("/")
        self.in_dir = f"{base}/in"
        self.out_dir = f"{base}/out"
        self.poll_interval = poll_interval
        self.timeout = timeout

    # --- Синхронные помощники (выполняются в worker-потоке) ---

    def _connect(self):
        """Открыть FTP-соединение (пассивный режим — как у агента 1С)."""
        import ftplib

        ftp = ftplib.FTP()
        ftp.connect(self.host, self.port, timeout=10)
        ftp.login(self.user, self.password)
        ftp.set_pasv(True)
        return ftp

    def _ensure_dirs(self, ftp) -> None:
        """Гарантировать наличие in/ и out/ вместе с родительскими каталогами
        (аналог mkdir(parents=True); ошибки «уже существует» игнорируются)."""
        import ftplib

        for target in (self.in_dir, self.out_dir):
            path = ""
            for segment in (s for s in target.split("/") if s):
                path += "/" + segment
                try:
                    ftp.mkd(path)
                except ftplib.error_perm:
                    pass  # уже существует (или нет прав — выяснится при записи)

    def _exists(self, ftp, directory: str, name: str) -> bool:
        """Есть ли файл name в каталоге directory (по листингу NLST)."""
        import ftplib

        try:
            listing = ftp.nlst(directory)
        except ftplib.error_perm:
            return False  # пустой каталог у части серверов — 550
        # NLST возвращает имена или пути — сравниваем по последнему сегменту
        return any(entry.replace("\\", "/").rsplit("/", 1)[-1] == name for entry in listing)

    def _upload(self, ftp, remote_path: str, body: str) -> None:
        """Загрузить строку как файл (бинарно, UTF-8 без BOM)."""
        import io

        ftp.storbinary(f"STOR {remote_path}", io.BytesIO(body.encode("utf-8")))

    def _download(self, ftp, remote_path: str) -> str:
        """Скачать файл в строку (utf-8-sig снимает BOM, который пишет 1С)."""
        import io

        buffer = io.BytesIO()
        ftp.retrbinary(f"RETR {remote_path}", buffer.write)
        return buffer.getvalue().decode("utf-8-sig")

    def _delete_quiet(self, ftp, remote_path: str) -> None:
        """Удалить файл, игнорируя ошибки (очистка)."""
        try:
            ftp.delete(remote_path)
        except Exception:
            pass

    def _sync_send(self, request_body: str, is_notification: bool) -> str:
        """Полный цикл send одним блокирующим куском (для worker-потока)."""
        name = f"{uuid.uuid4().hex}.json"
        req_path = f"{self.in_dir}/{name}"
        resp_path = f"{self.out_dir}/{name}"
        tmp_path = f"{req_path}.tmp"

        ftp = self._connect()
        try:
            self._ensure_dirs(ftp)

            # Атомарная публикация запроса: STOR во временное имя + RNFR/RNTO
            self._upload(ftp, tmp_path, request_body)
            ftp.rename(tmp_path, req_path)

            if is_notification:
                return ""

            deadline = time.monotonic() + self.timeout
            while True:
                if self._exists(ftp, self.out_dir, name):
                    try:
                        text = self._download(ftp, resp_path)
                        json.loads(text)  # страховка: ответ дописан целиком
                    except (json.JSONDecodeError, UnicodeDecodeError, OSError):
                        pass  # дождёмся следующего опроса
                    else:
                        self._delete_quiet(ftp, resp_path)
                        return text

                if time.monotonic() >= deadline:
                    # Уберём наш запрос, чтобы не копился, если агент не отвечает
                    self._delete_quiet(ftp, req_path)
                    raise TimeoutError(
                        f"Ответ 1С не получен за {self.timeout} с (файл {resp_path} на {self.host}). "
                        f"Проверьте, что 1С-агент запущен и опрашивает {self.url}."
                    )

                time.sleep(self.poll_interval)
        finally:
            try:
                ftp.quit()
            except Exception:
                ftp.close()

    # --- Асинхронный интерфейс Transport ---

    async def send(self, request_body: str) -> str:
        """Положить запрос в in/ по FTP, дождаться ответа в out/."""
        # Notifications (запрос без id) 1С-агент не отвечает — не ждём ответа.
        try:
            is_notification = "id" not in json.loads(request_body)
        except (json.JSONDecodeError, TypeError):
            is_notification = False

        return await asyncio.to_thread(self._sync_send, request_body, is_notification)

    async def check_health(self) -> bool:
        """Проверить доступность FTP-СЕРВЕРА и папки обмена (не самой 1С).

        Как и у FileTransport: запущен ли 1С-агент, выяснится таймаутом на
        первом вызове. Здесь — коннект, наличие in/ и out/, проба на запись.
        """

        def _sync_health() -> None:
            ftp = self._connect()
            try:
                self._ensure_dirs(ftp)
                probe = f"{self.in_dir}/.health_{uuid.uuid4().hex}.tmp"
                self._upload(ftp, probe, "")
                self._delete_quiet(ftp, probe)
            finally:
                try:
                    ftp.quit()
                except Exception:
                    ftp.close()

        try:
            await asyncio.to_thread(_sync_health)
        except Exception as e:
            logger.error(f"FTP-папка обмена недоступна ({self.url}): {e}")
            raise
        logger.info(
            f"FTP-транспорт: папка обмена доступна ({self.host}:{self.port}, in/, out/). "
            f"Доступность 1С-агента этим НЕ проверяется — выяснится при первом вызове."
        )
        return True

    async def close(self) -> None:
        """Соединение открывается на каждый вызов — закрывать нечего."""
        return None


class ReverseHttpTransport:
    """Обратный HTTP-транспорт (httppoll): агент 1С сам опрашивает прокси.

    Для изолированных контуров, куда с локальной машины есть только проброс
    TCP-порта (например, NX-туннель NoMachine): прокси поднимает листенер на
    127.0.0.1:<port>, агент 1С (форма mcp_УправлениеСервером) по таймеру
    забирает запросы GET /poll и возвращает ответы POST /result/<тикет>.
    Направление TCP-соединения — всегда «агент → прокси», на серверной машине
    не нужны ни веб-сервер, ни открытые входящие порты.

    Протокол:
    - GET /poll: 200 + сырое тело JSON-RPC + заголовок X-MCP-Ticket, либо 204
      (очередь пуста). Каждый запрос выдаётся ровно одному опросчику.
    - POST /result/<тикет>: тело — сырой JSON-RPC-ответ; 204 принято,
      404 неизвестный тикет, 410 тикет истёк/ответ не ожидается.
    - GET /health: {"status":"ok","pending":N,"inflight":M} — диагностика туннеля.

    Забранный агентом, но не отвеченный запрос НЕ перевыдаётся: тикет истекает
    по таймауту (инструменты бывают неидемпотентными, двойное исполнение хуже
    таймаута). Листенер — эксклюзивный ресурс (порт), поэтому транспорт
    поддерживается только в stdio-режиме прокси (один клиент на процесс).
    """

    # Сколько секунд помнить истёкшие тикеты — только чтобы отличать 410 от 404
    EXPIRED_TTL = 600.0

    def __init__(self, host: str = "127.0.0.1", port: int = 9090, timeout: float = 60.0):
        """Инициализация транспорта.

        Args:
            host: Адрес листенера (обычно 127.0.0.1 — наружу выводит NX-туннель).
            port: Порт листенера.
            timeout: Сколько (сек) ждать, пока агент заберёт запрос и вернёт ответ.
        """
        self.host = host
        self.port = port
        self.timeout = timeout

        self._server: Optional[asyncio.AbstractServer] = None
        # Невыданные запросы: тикет -> тело (dict в Python упорядочен — это и очередь)
        self._pending: dict[str, str] = {}
        # Ожидающие ответа future: тикет -> future (у нотификаций future нет)
        self._futures: dict[str, "asyncio.Future[str]"] = {}
        # Истёкшие/не ожидающие ответа тикеты: тикет -> момент, когда запись можно забыть
        self._expired: dict[str, float] = {}

    async def _ensure_server(self) -> None:
        """Лениво поднять листенер; занятый порт — понятная ошибка сразу."""
        if self._server is not None:
            return
        try:
            self._server = await asyncio.start_server(self._handle_connection, self.host, self.port)
        except OSError as e:
            raise OSError(
                f"Не удалось занять {self.host}:{self.port} для httppoll-листенера: {e}. "
                f"Порт занят другим процессом (или вторым экземпляром прокси)?"
            ) from e
        logger.info(f"httppoll: листенер запущен на {self.host}:{self.port}, ждём опросов агента 1С")

    async def send(self, request_body: str) -> str:
        """Поставить запрос в очередь и дождаться, пока агент вернёт ответ."""
        await self._ensure_server()

        # Notifications (запрос без id) ответа не имеют: выдаём агенту штатно,
        # но future не заводим и возвращаем "" сразу.
        try:
            is_notification = "id" not in json.loads(request_body)
        except (json.JSONDecodeError, TypeError):
            is_notification = False

        ticket = uuid.uuid4().hex
        self._pending[ticket] = request_body

        if is_notification:
            return ""

        future: "asyncio.Future[str]" = asyncio.get_running_loop().create_future()
        self._futures[ticket] = future
        try:
            return await asyncio.wait_for(future, self.timeout)
        except asyncio.TimeoutError:
            # Убираем следы запроса; поздний POST агента получит 410, а не 404
            self._pending.pop(ticket, None)
            self._futures.pop(ticket, None)
            self._mark_expired(ticket)
            raise TimeoutError(
                f"Агент 1С не вернул ответ за {self.timeout} с (тикет {ticket}). "
                f"Проверьте, что агент запущен (форма mcp_УправлениеСервером, адрес "
                f"http://{self.host}:{self.port}) и порт проброшен туннелем."
            )

    async def check_health(self) -> bool:
        """Проверить, что листенер поднят (bind порта прошёл).

        Живость самого агента 1С не проверяется — как и у файлового транспорта,
        она выяснится таймаутом первого вызова.
        """
        await self._ensure_server()
        logger.info(
            f"httppoll: листенер доступен на {self.host}:{self.port}. "
            f"Доступность агента 1С этим НЕ проверяется — выяснится при первом вызове."
        )
        return True

    async def close(self) -> None:
        """Погасить листенер и разбудить всех ожидающих ошибкой."""
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()
            self._server = None
        self._pending.clear()
        for future in self._futures.values():
            if not future.done():
                future.set_exception(ConnectionError("httppoll-транспорт закрыт"))
        self._futures.clear()
        self._expired.clear()

    # --- внутренняя кухня листенера -------------------------------------

    def _mark_expired(self, ticket: str) -> None:
        """Запомнить тикет как истёкший (для ответа 410) и подчистить старые."""
        now = time.monotonic()
        self._expired[ticket] = now + self.EXPIRED_TTL
        for old, deadline in list(self._expired.items()):
            if deadline <= now:
                del self._expired[old]

    async def _handle_connection(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        """Обслужить одно HTTP-соединение агента (запрос → ответ → закрыть)."""
        try:
            method, path, body = await asyncio.wait_for(self._read_request(reader), timeout=30.0)
            status, headers, response_body = self._route(method, path, body)
        except (asyncio.TimeoutError, asyncio.IncompleteReadError, ValueError, ConnectionError) as e:
            logger.warning(f"httppoll: битый запрос от агента: {type(e).__name__}: {e}")
            status, headers, response_body = 400, {}, b""
        try:
            await self._write_response(writer, status, headers, response_body)
        except (ConnectionError, OSError):
            pass  # агент оборвал соединение — его тик повторит попытку
        finally:
            writer.close()

    @staticmethod
    async def _read_request(reader: asyncio.StreamReader) -> tuple[str, str, bytes]:
        """Разобрать минимальный HTTP/1.1-запрос: строка, заголовки, тело по Content-Length."""
        request_line = (await reader.readline()).decode("latin-1").rstrip("\r\n")
        parts = request_line.split(" ")
        if len(parts) < 3:
            raise ValueError(f"не HTTP-запрос: {request_line!r}")
        method, path = parts[0].upper(), parts[1]

        content_length = 0
        while True:
            line = (await reader.readline()).decode("latin-1").rstrip("\r\n")
            if not line:
                break
            name, _, value = line.partition(":")
            if name.strip().lower() == "content-length":
                content_length = int(value.strip())

        body = await reader.readexactly(content_length) if content_length else b""
        return method, path, body

    def _route(self, method: str, path: str, body: bytes) -> tuple[int, dict, bytes]:
        """Маршрутизация трёх эндпоинтов протокола."""
        path = path.split("?", 1)[0]

        if method == "GET" and path == "/poll":
            if not self._pending:
                return 204, {}, b""
            ticket = next(iter(self._pending))
            request_body = self._pending.pop(ticket)
            if ticket not in self._futures:
                # Нотификация: выдана, но ответ не ожидается — поздний POST получит 410
                self._mark_expired(ticket)
            return 200, {"X-MCP-Ticket": ticket}, request_body.encode("utf-8")

        if method == "POST" and path.startswith("/result/"):
            ticket = path[len("/result/"):]
            future = self._futures.pop(ticket, None)
            if future is not None:
                # utf-8-sig на случай, если 1С всё же добавит BOM
                if not future.done():
                    future.set_result(body.decode("utf-8-sig"))
                self._mark_expired(ticket)
                return 204, {}, b""
            if ticket in self._expired:
                return 410, {}, b""
            return 404, {}, b""

        if method == "GET" and path == "/health":
            payload = json.dumps({
                "status": "ok",
                "pending": len(self._pending),
                "inflight": len(self._futures) - sum(1 for t in self._futures if t in self._pending),
            }).encode("utf-8")
            return 200, {"Content-Type": "application/json; charset=utf-8"}, payload

        return 404, {}, b""

    @staticmethod
    async def _write_response(writer: asyncio.StreamWriter, status: int, headers: dict, body: bytes) -> None:
        """Записать HTTP-ответ; соединение одноразовое (Connection: close)."""
        reasons = {200: "OK", 204: "No Content", 400: "Bad Request", 404: "Not Found", 410: "Gone"}
        lines = [f"HTTP/1.1 {status} {reasons.get(status, 'Unknown')}"]
        if status == 200 and "Content-Type" not in headers:
            lines.append("Content-Type: application/json; charset=utf-8")
        for name, value in headers.items():
            lines.append(f"{name}: {value}")
        lines.append(f"Content-Length: {len(body)}")
        lines.append("Connection: close")
        writer.write(("\r\n".join(lines) + "\r\n\r\n").encode("latin-1") + body)
        await writer.drain()
