#!/usr/bin/env python
# -*- codeing:utf-8 -*-

__author__ = "XiaoHuiHui"

import asyncio
import logging
import traceback
import typing
from asyncio import Event
from typing import Any, Callable, Coroutine
from eth_keys.datatypes import PublicKey

import ujson
import rlp

logger = logging.getLogger("eth.ipc")

Callback = Callable[..., Coroutine[Any, Any, None]]
Rlpdecoded = list[bytes | list[bytes] | list[bytes | list[bytes]]]


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

    async def receive(self, data: dict[str, str | int]) -> None:
        match data["type"]:
            case "ready":
                addr = typing.cast(str, data["addr"])
                version = typing.cast(int, data["version"])
                asyncio.create_task(
                    self.callbacks["ready"](addr, version),
                    name=f"ready_{addr}"
                )
            case "pop":
                addr = typing.cast(str, data["addr"])
                asyncio.create_task(
                    self.callbacks["pop"](addr),
                    name=f"pop_{addr}"
                )
            case "message":
                addr = typing.cast(str, data["addr"])
                code = typing.cast(int, data["code"])
                d: Rlpdecoded = rlp.decode(  # type: ignore
                    bytes.fromhex(typing.cast(str, data["data"]))
                )
                asyncio.create_task(
                    self.callbacks["message"](addr, code, d),
                    name=f"message_{addr}_{code}"
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
