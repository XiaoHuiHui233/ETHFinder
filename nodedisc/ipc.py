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

logger = logging.getLogger("nodedisc.ipc")


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
        self.running = False
        logger.info(f"IPC Connection #{id} is connected.")

    async def run(self) -> None:
        self.running = True
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
        if not self.running:
            return
        logger.debug(f"IPC Connection #{self.id} is closing.")
        self.running = False
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
        self.task = asyncio.create_task(self.run(), name="ipc_run")

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

    async def boardcast_new_enr(self, id: PublicKey, enr: ENR) -> None:
        data = ujson.dumps({
            "type": "new_enr",
            "id": id.to_bytes().hex(),
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
        await conn.run()
        self.connections.remove(conn)
