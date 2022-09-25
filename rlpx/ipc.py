#!/usr/bin/env python
# -*- codeing:utf-8 -*-

__author__ = "XiaoHuiHui"

import asyncio
import logging
import traceback
from asyncio import Event, StreamReader, StreamWriter
from typing import Any, Callable, Coroutine

import rlp
import ujson
from enr.datatypes import ENR
from eth_keys.datatypes import PublicKey

from .datatypes import Addr

logger = logging.getLogger("rlpx.ipc")

Callback = Callable[..., Coroutine[Any, Any, None]]
Rlpdecoded = list[bytes | list[bytes] | list[bytes | list[bytes]]]


class IPCConnection:
    def __init__(
        self,
        id: int,
        server: "IPCServer",
        reader: StreamReader,
        writer: StreamWriter
    ) -> None:
        self.id = id
        self.server = server
        self.reader = reader
        self.writer = writer
        logger.info(f"IPC Connection #{id} is connected.")

    async def run(self) -> None:
        try:
            while not self.reader.at_eof():
                data = await self.reader.readline()
                logger.debug(
                    f"IPC Connection #{self.id} received {data.decode()}"
                )
                d = ujson.loads(data.decode())
                self.receive(d)
        except Exception:
            logger.warning(
                f"IPC Connection #{self.id} received illegal datas."
            )
            logger.debug(traceback.format_exc())
            await self.close()

    def receive(self, data: dict[str, str]) -> None:
        if data["type"] == "ban":
            id = PublicKey.from_compressed_bytes(bytes.fromhex(data["id"]))
            self.server.callbacks["ban"](id)

    async def send(self, data: bytes) -> None:
        self.writer.write(data)
        self.writer.write(b"\n")
        logger.debug(
            f"Send data {data.decode()} to IPC Connection #{self.id}."
        )
        await self.writer.drain()

    async def close(self) -> None:
        logger.debug(f"IPC Connection #{self.id} is closing.")
        self.writer.close()
        await self.writer.wait_closed()
        logger.info(f"IPC Connection #{self.id} is closed.")


class IPCServer:
    def __init__(self, path: str) -> None:
        self.path = path
        self.connections: set[IPCConnection] = set()
        self.id_cnt = 0
        self.callbacks: dict[str, Callable[..., None]] = {}

    def register_callback(
        self, name: str, callback: Callable[..., None]
    ) -> None:
        self.callbacks[name] = callback

    async def bind(self) -> None:
        logger.info(f"IPC server is running on {self.path}")
        self.server = await asyncio.start_unix_server(
            self.on_connect, self.path
        )
        self.task = asyncio.create_task(self.run(), name="ipc_server_run")

    async def run(self) -> None:
        await self.server.serve_forever()

    async def close(self) -> None:
        logger.debug("IPC Server is closing.")
        await self.boardcast_close()
        await asyncio.gather(
            *[conn.close() for conn in self.connections],
            return_exceptions=True
        )
        self.server.close()
        await self.server.wait_closed()
        self.task.cancel()
        await asyncio.sleep(0)
        logger.info("IPC Server is closed.")

    async def send_all(self, data: bytes) -> None:
        results = await asyncio.gather(
            *[conn.send(data) for conn in self.connections],
            return_exceptions=True
        )
        cnt = 0
        for r in results:
            if r is not None:
                logger.warning(
                    f"IPC server failed to boardcast msg to #{cnt}"
                )
            cnt += 1

    async def boardcast_ready(self, addr: Addr, version: int) -> None:
        d = ujson.dumps({
            "type": "ready",
            "addr": str(addr),
            "version": version
        }).encode()
        await self.send_all(d)

    async def boardcast_pop(self, addr: Addr) -> None:
        d = ujson.dumps({
            "type": "pop",
            "addr": str(addr)
        }).encode()
        await self.send_all(d)

    async def boardcast_msg(
        self, addr: Addr, code: int, data: Rlpdecoded
    ) -> None:
        encoded: bytes = rlp.encode(data)  # type: ignore
        d = ujson.dumps({
            "type": "message",
            "addr": str(addr),
            "code": code,
            "data": encoded.hex()
        }).encode()
        await self.send_all(d)

    async def boardcast_close(self) -> None:
        data = ujson.dumps({
            "type": "close"
        }).encode()
        await self.send_all(data)

    async def on_connect(
        self, reader: StreamReader, writer: StreamWriter
    ) -> None:
        conn = IPCConnection(self.id_cnt, self, reader, writer)
        self.id_cnt += 1
        self.connections.add(conn)
        await conn.run()
        self.connections.remove(conn)


class IPCClient:
    def __init__(self, path: str) -> None:
        self.path = path
        self.running = Event()
        self.callbacks: dict[str, Callback] = {}

    def register_callback(self, name: str, callback: Callback) -> None:
        self.callbacks[name] = callback

    async def bind(self) -> None:
        await asyncio.sleep(1)
        while True:
            try:
                self.reader, self.writer = \
                    await asyncio.open_unix_connection(self.path)
                logger.info(
                    f"IPC Client is connected to {self.path}"
                )
                self.running.set()
                self.run_task = asyncio.create_task(
                    self.run(), name="ipc_client_run_loop"
                )
                break
            except Exception:
                logger.warning(
                    "IPC Client connection failed. Retry in 5s.\n"
                    f"Detail: {traceback.format_exc()}"
                )
                await asyncio.sleep(5)

    async def run(self) -> None:
        try:
            while not self.reader.at_eof():
                data = await self.reader.readline()
                logger.debug(f"IPC Client received {data.decode()}")
                try:
                    d = ujson.loads(data.decode())
                    await self.receive(d)
                except Exception:
                    logger.warning(
                        "IPC Client received illegal datas. Ignore it."
                    )
            logger.info("IPC Client normal closed. Reconnect in 5s.")
        except Exception:
            logger.warning(
                f"[Client] IPC failed to connect to {self.path}."
                f" Retry in 5s.\nDetails: {traceback.format_exc()}"
            )
        self.running.clear()
        await asyncio.sleep(5)
        await self.bind()

    async def receive(self, data: dict[str, str]) -> None:
        match data["type"]:
            case "new_enr":
                id = PublicKey(bytes.fromhex(data["id"]))
                enr = ENR.from_text(data["enr"])
                asyncio.create_task(
                    self.callbacks["new_enr"](id, enr), name="raw_new_enr"
                )
            case "close":
                asyncio.create_task(
                    self.callbacks["close"](), name="receive_close"
                )
            case _:
                logger.warning("IPC Client received unsupport data type.")

    async def close(self) -> None:
        logger.debug("IPC Client is closing.")
        if self.running.is_set():
            self.writer.close()
            await self.writer.wait_closed()
        self.run_task.cancel()
        logger.info("IPC Client is closed.")

    async def send(self, data: bytes) -> None:
        self.writer.write(data)
        self.writer.write(b"\n")
        logger.debug(
            f"IPC Client send data {data.decode()} to server."
        )
        await self.writer.drain()

    async def send_ban(self, id: PublicKey) -> None:
        await self.send(
            ujson.dumps({
                "type": "ban",
                "id": id.to_compressed_bytes().hex()
            }).encode()
        )
