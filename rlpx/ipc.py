#!/usr/bin/env python
# -*- codeing:utf-8 -*-

__author__ = "XiaoHuiHui"

import asyncio
import logging
import traceback
from asyncio import StreamReader, StreamWriter
from typing import Callable
from eth_keys.datatypes import PublicKey

import ujson

from enr.datatypes import ENR

logger = logging.getLogger("rlpx.ipc")


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

    async def bind(self) -> None:
        while not self.reader.at_eof():
            data = await self.reader.readline()
            logger.debug(f"received {data.decode()}")
            try:
                d = ujson.loads(data.decode())
                self.receive(d)
            except Exception:
                logger.warning(
                    f"IPC connection #{self.id} received illegal datas."
                )
                logger.debug(traceback.format_exc())
                await self.close()
                break

    def receive(self, data: dict[str, str]) -> None:
        if data["type"] == "ban":
            id = PublicKey.from_compressed_bytes(bytes.fromhex(data["id"]))
            self.server.callbacks["ban"](id)

    async def send(self, data: bytes) -> None:
        self.writer.write(data)
        self.writer.write(b"\n")
        logger.debug(
            f"Send data {data.decode()} to IPC connection #{self.id}."
        )
        await self.writer.drain()

    async def close(self) -> None:
        self.writer.close()
        logger.info(f"IPC connection #{self.id} is closing.")
        await self.writer.wait_closed()


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
        await self.server.serve_forever()

    async def close(self) -> None:
        for conn in self.connections:
            await conn.close()
        self.server.close()
        await self.server.wait_closed()

    async def send_all(self, data: bytes) -> None:
        for conn in self.connections:
            try:
                await conn.send(data)
            except Exception:
                logger.warning(
                    f"IPC server failed to boardcast msg to #{conn.id}"
                )

    async def boardcast_new_enr(self, id: PublicKey, enr: ENR) -> None:
        data = ujson.dumps({
            "type": "new_enr",
            "id": id.to_compressed_bytes().hex(),
            "enr": enr.to_text()
        }).encode()
        await self.send_all(data)

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
        await conn.bind()
        self.connections.remove(conn)


class IPCClient:
    def __init__(self, path: str) -> None:
        self.path = path
        self.callbacks: dict[str, Callable[..., None]] = {}

    def register_callback(
        self, name: str, callback: Callable[..., None]
    ) -> None:
        self.callbacks[name] = callback

    async def bind(self) -> None:
        logger.info(f"IPC client is connecting to {self.path}")
        self.reader, self.writer = await asyncio.open_unix_connection(
            self.path
        )
        while not self.reader.at_eof():
            data = await self.reader.readline()
            logger.debug(f"[Client] Received {data.decode()}")
            try:
                d = ujson.loads(data.decode())
                self.receive(d)
            except Exception:
                logger.warning(
                    "[Client] Received illegal datas."
                )
                logger.debug(traceback.format_exc())
                await self.close()
                break

    def receive(self, data: dict[str, str]) -> None:
        match data["type"]:
            case "new_enr":
                id = PublicKey.from_compressed_bytes(bytes.fromhex(data["id"]))
                enr = ENR.from_text(data["enr"])
                self.callbacks["new_enr"](id, enr)
            case "close":
                self.callbacks["close"]()
            case _:
                logger.warning("[Client] received unsupport data type.")

    async def close(self) -> None:
        self.writer.close()
        logger.info("[Client] Closing.")
        await self.writer.wait_closed()

    async def send(self, data: bytes) -> None:
        self.writer.write(data)
        self.writer.write(b"\n")
        logger.debug(
            f"[Client] Send data {data.decode()} to server."
        )
        await self.writer.drain()

    async def send_ban(self, id: PublicKey) -> None:
        await self.send(
            ujson.dumps({
                "type": "ban",
                "id": id.to_compressed_bytes().hex()
            }).encode()
        )
