"""MessageU server — milestones 1–7 implementation."""

from __future__ import annotations

import argparse
import logging
import socket
import struct
import threading
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Protocol, Tuple

import sqlite3

REQ_FMT = "<16sBHI"
RESP_FMT = "<BHI"

REQ_HEADER_LEN = struct.calcsize(REQ_FMT)
RESP_HEADER_LEN = struct.calcsize(RESP_FMT)

NAME_LEN = 255
PUBKEY_LEN = 160

REQ_REGISTER = 600
REQ_CLIENTS_LIST = 601
REQ_PUBLIC_KEY = 602
REQ_SEND_MESSAGE = 603
REQ_FETCH_MESSAGES = 604

RESP_REGISTER_OK = 2100
RESP_CLIENTS_LIST = 2101
RESP_PUBLIC_KEY = 2102
RESP_MESSAGE_ACCEPTED = 2103
RESP_WAITING_MESSAGES = 2104
RESP_ERROR = 9000

MSG_TYPE_REQUEST_KEY = 1
MSG_TYPE_SEND_KEY = 2
MSG_TYPE_TEXT = 3
MSG_TYPE_FILE = 4

CLIENT_VERSIONS = {1, 2}

HOST = "0.0.0.0"
SCRIPT_DIR = Path(__file__).resolve().parent
MYPORT_PATH = SCRIPT_DIR / "myport.info"
SQLITE_DB_PATH = SCRIPT_DIR / "defensive.db"
DEFAULT_PORT = 1357

_logger = logging.getLogger(__name__)


def pack_resp(code: int, payload: bytes, version: int) -> bytes:
    return struct.pack(RESP_FMT, version, code, len(payload)) + payload


def unpack_req_header(buf: bytes) -> Tuple[bytes, int, int, int]:
    return struct.unpack(REQ_FMT, buf)


def read_exact(sock: socket.socket, size: int) -> bytes:
    data = bytearray()
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise ConnectionError("socket closed")
        data.extend(chunk)
    return bytes(data)


def read_port() -> int:
    try:
        text = MYPORT_PATH.read_text(encoding="ascii").strip()
    except FileNotFoundError:
        _logger.warning("myport.info missing; defaulting to port %s", DEFAULT_PORT)
        return DEFAULT_PORT
    except OSError as exc:
        _logger.warning(
            "Failed to read %s (%s); defaulting to %s", MYPORT_PATH, exc, DEFAULT_PORT
        )
        return DEFAULT_PORT

    try:
        port = int(text)
    except ValueError:
        _logger.warning("Invalid port '%s'; defaulting to %s", text, DEFAULT_PORT)
        return DEFAULT_PORT

    if 1 <= port <= 65535:
        return port

    _logger.warning("Out-of-range port %s; defaulting to %s", port, DEFAULT_PORT)
    return DEFAULT_PORT


@dataclass(slots=True)
class Client:
    id: bytes
    name: str
    pubkey: bytes
    last_seen: datetime


@dataclass(slots=True)
class Message:
    id: int
    to: bytes
    frm: bytes
    typ: int
    content: bytes


class Storage(Protocol):
    def get_client_by_name(self, name: str) -> Optional[Client]:
        """Return client by username."""

    def get_client_by_id(self, client_id: bytes) -> Optional[Client]:
        """Return client by identifier."""

    def add_client(
        self, client_id: bytes, name: str, pubkey: bytes, last_seen: datetime
    ) -> Client:
        """Persist a newly registered client."""

    def list_clients_except(self, client_id: bytes) -> list[Client]:
        """Return all clients except the provided one."""

    def add_message(self, to: bytes, frm: bytes, typ: int, content: bytes) -> int:
        """Persist a new message and return its identifier."""

    def pop_all_messages_for(self, client_id: bytes) -> list[Message]:
        """Return and remove all pending messages for a client."""

    def update_last_seen(self, client_id: bytes, stamp: datetime) -> None:
        """Update the last seen timestamp for the client."""


class RAMStorage:
    def __init__(self) -> None:
        self._clients_by_id: dict[bytes, Client] = {}
        self._clients_by_name: dict[str, Client] = {}
        self._message_queues: dict[bytes, list[Message]] = {}
        self._next_message_id = 1
        self._lock = threading.Lock()

    def get_client_by_name(self, name: str) -> Optional[Client]:
        with self._lock:
            return self._clients_by_name.get(name)

    def get_client_by_id(self, client_id: bytes) -> Optional[Client]:
        with self._lock:
            return self._clients_by_id.get(client_id)

    def add_client(
        self, client_id: bytes, name: str, pubkey: bytes, last_seen: datetime
    ) -> Client:
        client = Client(client_id, name, pubkey, last_seen)
        with self._lock:
            self._clients_by_id[client_id] = client
            self._clients_by_name[name] = client
        return client

    def list_clients_except(self, client_id: bytes) -> list[Client]:
        with self._lock:
            return [
                client
                for cid, client in self._clients_by_id.items()
                if cid != client_id
            ]

    def add_message(self, to: bytes, frm: bytes, typ: int, content: bytes) -> int:
        with self._lock:
            mid = self._next_message_id
            self._next_message_id += 1
            self._message_queues.setdefault(to, []).append(
                Message(mid, to, frm, typ, content)
            )
            return mid

    def pop_all_messages_for(self, client_id: bytes) -> list[Message]:
        with self._lock:
            return self._message_queues.pop(client_id, []).copy()

    def update_last_seen(self, client_id: bytes, stamp: datetime) -> None:
        with self._lock:
            client = self._clients_by_id.get(client_id)
            if client is not None:
                client.last_seen = stamp


class SQLiteStorage:
    def __init__(self, db_path: Path) -> None:
        self._db_path = db_path
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        with self._conn:
            self._conn.execute("PRAGMA foreign_keys=ON")
        self._init_schema()

    def _init_schema(self) -> None:
        with self._conn:
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS clients(
                    ID BLOB(16) PRIMARY KEY,
                    UserName CHAR(255) NOT NULL,
                    PublicKey BLOB(160) NOT NULL,
                    LastSeen TEXT
                );
                """
            )
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS messages(
                    ID INTEGER PRIMARY KEY AUTOINCREMENT,
                    ToClient BLOB(16) NOT NULL,
                    FromClient BLOB(16) NOT NULL,
                    Type INTEGER NOT NULL,
                    Content BLOB NOT NULL
                );
                """
            )

    def _row_to_client(self, row: sqlite3.Row) -> Client:
        last_seen_raw = row["LastSeen"]
        last_seen = (
            datetime.fromisoformat(last_seen_raw)
            if last_seen_raw
            else datetime.now(timezone.utc)
        )
        return Client(
            bytes(row["ID"]), str(row["UserName"]), bytes(row["PublicKey"]), last_seen
        )

    def get_client_by_name(self, name: str) -> Optional[Client]:
        with self._lock:
            cur = self._conn.execute("SELECT * FROM clients WHERE UserName= ?", (name,))
            row = cur.fetchone()
        if row is None:
            return None
        return self._row_to_client(row)

    def get_client_by_id(self, client_id: bytes) -> Optional[Client]:
        with self._lock:
            cur = self._conn.execute("SELECT * FROM clients WHERE ID= ?", (client_id,))
            row = cur.fetchone()
        if row is None:
            return None
        return self._row_to_client(row)

    def add_client(
        self, client_id: bytes, name: str, pubkey: bytes, last_seen: datetime
    ) -> Client:
        stamp = last_seen.isoformat()
        with self._lock:
            with self._conn:
                self._conn.execute(
                    "INSERT INTO clients(ID, UserName, PublicKey, LastSeen) VALUES(?,?,?,?)",
                    (client_id, name, pubkey, stamp),
                )
        return Client(client_id, name, pubkey, last_seen)

    def list_clients_except(self, client_id: bytes) -> list[Client]:
        with self._lock:
            cur = self._conn.execute(
                "SELECT * FROM clients WHERE ID<>? ORDER BY UserName COLLATE NOCASE",
                (client_id,),
            )
            rows = cur.fetchall()
        return [self._row_to_client(row) for row in rows]

    def add_message(self, to: bytes, frm: bytes, typ: int, content: bytes) -> int:
        with self._lock:
            with self._conn:
                cur = self._conn.execute(
                    "INSERT INTO messages(ToClient, FromClient, Type, Content) VALUES(?,?,?,?)",
                    (to, frm, typ, content),
                )
                message_id = cur.lastrowid
        if message_id is None:
            msg = "SQLite failed to return a row id for inserted message"
            raise RuntimeError(msg)
        return int(message_id)

    def pop_all_messages_for(self, client_id: bytes) -> list[Message]:
        with self._lock:
            cur = self._conn.execute(
                "SELECT * FROM messages WHERE ToClient=? ORDER BY ID",
                (client_id,),
            )
            rows = cur.fetchall()
            message_ids = [row["ID"] for row in rows]
            messages = [
                Message(
                    int(row["ID"]),
                    bytes(row["ToClient"]),
                    bytes(row["FromClient"]),
                    int(row["Type"]),
                    bytes(row["Content"]),
                )
                for row in rows
            ]
            if message_ids:
                placeholders = ",".join("?" for _ in message_ids)
                with self._conn:
                    self._conn.execute(
                        f"DELETE FROM messages WHERE ID IN ({placeholders})",
                        message_ids,
                    )
        return messages

    def update_last_seen(self, client_id: bytes, stamp: datetime) -> None:
        with self._lock:
            with self._conn:
                self._conn.execute(
                    "UPDATE clients SET LastSeen=? WHERE ID=?",
                    (stamp.isoformat(), client_id),
                )


VALID_MESSAGE_TYPES = {
    MSG_TYPE_REQUEST_KEY,
    MSG_TYPE_SEND_KEY,
    MSG_TYPE_TEXT,
    MSG_TYPE_FILE,
}


@dataclass(slots=True)
class RequestContext:
    client_id: bytes
    client_version: int
    code: int
    payload: bytes
    conn: socket.socket
    addr: Tuple[str, int]


class MessageUServer:
    def __init__(self, storage: Storage, server_version: int) -> None:
        self._storage = storage
        self._server_version = server_version

    def serve_forever(self) -> None:
        port = read_port()
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.bind((HOST, port))
            srv.listen()
            _logger.info("Server listening on %s:%s", HOST, port)
            while True:
                conn, addr = srv.accept()
                _logger.info("Accepted connection from %s", addr)
                threading.Thread(
                    target=self._handle_client, args=(conn, addr), daemon=True
                ).start()

    def _handle_client(self, conn: socket.socket, addr: Tuple[str, int]) -> None:
        with conn:
            while True:
                try:
                    header = read_exact(conn, REQ_HEADER_LEN)
                except ConnectionError:
                    _logger.info("Connection from %s closed", addr)
                    return
                except OSError as exc:
                    _logger.warning("Socket error from %s: %s", addr, exc)
                    return

                try:
                    client_id, client_version, code, payload_size = unpack_req_header(
                        header
                    )
                    if client_version not in CLIENT_VERSIONS:
                        _logger.warning(
                            "Unsupported client version %s from %s",
                            client_version,
                            addr,
                        )
                        self._send_error(conn)
                        return
                    payload = read_exact(conn, payload_size) if payload_size else b""
                except Exception as exc:  # noqa: BLE001
                    _logger.warning("Malformed request from %s: %s", addr, exc)
                    self._send_error(conn)
                    return

                ctx = RequestContext(
                    client_id, client_version, code, payload, conn, addr
                )
                try:
                    self._process_request(ctx)
                except Exception:  # noqa: BLE001
                    _logger.exception(
                        "Unhandled error processing code %s from %s", code, addr
                    )
                    self._send_error(conn)
                    return

    def _process_request(self, ctx: RequestContext) -> None:
        if ctx.code == REQ_REGISTER:
            self._handle_register(ctx)
        elif ctx.code == REQ_CLIENTS_LIST:
            self._handle_clients_list(ctx)
        elif ctx.code == REQ_PUBLIC_KEY:
            self._handle_public_key(ctx)
        elif ctx.code == REQ_SEND_MESSAGE:
            self._handle_send_message(ctx)
        elif ctx.code == REQ_FETCH_MESSAGES:
            self._handle_fetch_messages(ctx)
        else:
            _logger.warning("Unknown request code %s from %s", ctx.code, ctx.addr)
            self._send_error(ctx.conn)

    def _handle_register(self, ctx: RequestContext) -> None:
        expected_len = NAME_LEN + PUBKEY_LEN
        if len(ctx.payload) != expected_len:
            _logger.warning(
                "Invalid register payload size %s from %s", len(ctx.payload), ctx.addr
            )
            self._send_error(ctx.conn)
            return

        name_field = ctx.payload[:NAME_LEN]
        pubkey = ctx.payload[NAME_LEN:]
        if len(pubkey) != PUBKEY_LEN:
            self._send_error(ctx.conn)
            return

        if b"\x00" not in name_field:
            _logger.warning("Register payload missing NUL from %s", ctx.addr)
            self._send_error(ctx.conn)
            return

        raw_name, _ = name_field.split(b"\x00", 1)
        if not raw_name:
            _logger.warning("Empty username from %s", ctx.addr)
            self._send_error(ctx.conn)
            return

        try:
            name = raw_name.decode("ascii")
        except UnicodeDecodeError:
            _logger.warning("Non-ASCII username from %s", ctx.addr)
            self._send_error(ctx.conn)
            return

        if self._storage.get_client_by_name(name) is not None:
            _logger.warning("Duplicate username '%s' from %s", name, ctx.addr)
            self._send_error(ctx.conn)
            return

        client_id = self._generate_unique_client_id()
        self._storage.add_client(client_id, name, pubkey, datetime.now(timezone.utc))
        _logger.info("Registered new client '%s' from %s", name, ctx.addr)
        self._send_response(ctx.conn, RESP_REGISTER_OK, client_id)

    def _handle_clients_list(self, ctx: RequestContext) -> None:
        if ctx.payload:
            self._send_error(ctx.conn)
            return

        client = self._require_client(ctx)
        if client is None:
            return

        blocks: list[bytes] = []
        for entry in self._storage.list_clients_except(client.id):
            try:
                encoded = entry.name.encode("ascii")
            except UnicodeEncodeError:
                _logger.error("Stored username not ASCII: %s", entry.name)
                self._send_error(ctx.conn)
                return
            if len(encoded) >= NAME_LEN:
                _logger.error("Stored username too long: %s", entry.name)
                self._send_error(ctx.conn)
                return
            name_block = encoded + b"\x00" + bytes(NAME_LEN - len(encoded) - 1)
            blocks.append(entry.id + name_block)

        payload = b"".join(blocks)
        self._send_response(ctx.conn, RESP_CLIENTS_LIST, payload)

    def _handle_public_key(self, ctx: RequestContext) -> None:
        if len(ctx.payload) != 16:
            self._send_error(ctx.conn)
            return
        if self._require_client(ctx) is None:
            return
        target = self._storage.get_client_by_id(ctx.payload)
        if target is None:
            self._send_error(ctx.conn)
            return
        payload = target.id + target.pubkey
        self._send_response(ctx.conn, RESP_PUBLIC_KEY, payload)

    def _handle_send_message(self, ctx: RequestContext) -> None:
        min_len = 16 + 1 + 4
        if len(ctx.payload) < min_len:
            self._send_error(ctx.conn)
            return

        sender = self._require_client(ctx)
        if sender is None:
            return

        to_client = ctx.payload[:16]
        msg_type = ctx.payload[16]
        content_size = struct.unpack("<I", ctx.payload[17:21])[0]
        content = ctx.payload[21:]

        if msg_type not in VALID_MESSAGE_TYPES:
            self._send_error(ctx.conn)
            return

        if len(content) != content_size:
            _logger.warning("Content size mismatch from %s", ctx.addr)
            self._send_error(ctx.conn)
            return

        target = self._storage.get_client_by_id(to_client)
        if target is None:
            self._send_error(ctx.conn)
            return

        message_id = self._storage.add_message(to_client, sender.id, msg_type, content)
        response_payload = to_client + struct.pack("<I", message_id)
        self._send_response(ctx.conn, RESP_MESSAGE_ACCEPTED, response_payload)

    def _handle_fetch_messages(self, ctx: RequestContext) -> None:
        if ctx.payload:
            self._send_error(ctx.conn)
            return

        client = self._require_client(ctx)
        if client is None:
            return

        blocks: list[bytes] = []
        for message in self._storage.pop_all_messages_for(client.id):
            content_size = len(message.content)
            block = (
                message.frm
                + struct.pack("<I", message.id)
                + bytes([message.typ])
                + struct.pack("<I", content_size)
                + message.content
            )
            blocks.append(block)

        payload = b"".join(blocks)
        self._send_response(ctx.conn, RESP_WAITING_MESSAGES, payload)

    def _require_client(self, ctx: RequestContext) -> Optional[Client]:
        client = self._storage.get_client_by_id(ctx.client_id)
        if client is None:
            self._send_error(ctx.conn)
            return None
        self._storage.update_last_seen(client.id, datetime.now(timezone.utc))
        return client

    def _generate_unique_client_id(self) -> bytes:
        while True:
            candidate = uuid.uuid4().bytes
            if self._storage.get_client_by_id(candidate) is None:
                return candidate

    def _send_response(self, conn: socket.socket, code: int, payload: bytes) -> None:
        response = pack_resp(code, payload, self._server_version)
        try:
            conn.sendall(response)
        except OSError as exc:
            _logger.warning("Failed to send response: %s", exc)

    def _send_error(self, conn: socket.socket) -> None:
        try:
            conn.sendall(pack_resp(RESP_ERROR, b"", self._server_version))
        except OSError:
            pass


def main() -> None:
    parser = argparse.ArgumentParser(description="MessageU server")
    parser.add_argument(
        "--sqlite", action="store_true", help="Enable SQLite persistence"
    )
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO, format="[%(asctime)s] %(levelname)s %(name)s: %(message)s"
    )

    if args.sqlite:
        _logger.info("Starting server with SQLite persistence at %s", SQLITE_DB_PATH)
        storage: Storage = SQLiteStorage(SQLITE_DB_PATH)
        server_version = 2
    else:
        _logger.info("Starting server in RAM mode")
        storage = RAMStorage()
        server_version = 1

    server = MessageUServer(storage, server_version)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        _logger.info("Shutdown requested")


if __name__ == "__main__":
    main()
