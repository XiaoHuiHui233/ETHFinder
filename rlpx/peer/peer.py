#!/usr/bin/env python
# -*- codeing:utf-8 -*-
"""A implemention of the peer in Ethereum p2p network.
"""

__author__ = "XiaoHuiHui"

import abc
from abc import ABCMeta
import asyncio
import logging
import traceback
from asyncio import CancelledError, Lock, StreamReader, StreamWriter
from enum import Enum
from typing import Any, Callable, Coroutine, Optional

from eth_keys.datatypes import PrivateKey, PublicKey

from ..utils import Promise
from ..datatypes import Addr
from ..ecies import ECIES

logger = logging.getLogger("rlpx.peer.peer")

Callback = Callable[[bytes], Coroutine[Any, Any, None]]

TIMEOUT = 5


class STATE(Enum):
    AUTH = 0
    ACK = 1
    HEADER = 2
    BODY = 3


class Peer(metaclass=ABCMeta):
    """
    """
    def __init__(
        self,
        addr: Addr,
        private_key: PrivateKey,
        remote_id: Optional[PublicKey],
        reader: StreamReader,
        writer: StreamWriter
    ) -> None:
        self.addr = addr
        self.id = private_key.public_key
        self.remote_id = remote_id
        self.reader = reader
        self.writer = writer
        self.ecies = ECIES(private_key, remote_id)
        self.send_lock = Lock()
        self.has_auth = Promise[bool]()
        self.running = False

    def __str__(self) -> str:
        return str(self.addr)

    def register_callback(self, callback: Callback) -> None:
        self.callback = callback

    async def bind(self) -> None:
        logger.info(f"[{self.addr}] Connection is started.")
        self.timeout_task = asyncio.create_task(
            self.timeout_check(), name=f"check_timeout_{self.addr}"
        )
        self.running = True
        self.run_task = asyncio.create_task(
            self.run(), name=f"peer_run_{self.addr}"
        )
        if self.remote_id is None:
            self.state = STATE.AUTH
            self.next_packet_size = 307
        else:
            self.state = STATE.ACK
            self.next_packet_size = 210
            logger.info(f"[{self.addr}] Active auth.")
            await self.send_auth()

    async def timeout_check(self) -> None:
        try:
            await asyncio.sleep(TIMEOUT)
        except CancelledError:
            return
        if not self.has_auth.is_set():
            logger.warning(f"[{self.addr}] Waiting for auth timeout.")
            await self.close()

    async def close(self) -> None:
        if not self.running:
            return
        self.running = False
        try:
            if not self.has_auth.is_set():
                self.has_auth.set(False)
                self.timeout_task.cancel()
            self.writer.close()
            await self.writer.wait_closed()
            self.run_task.cancel()
        except Exception:
            logger.warning(
                f"[{self.addr}] Failed to close.\n"
                f"Detail: {traceback.format_exc()}"
            )

    async def send(self, datas: bytes) -> None:
        if not self.running:
            logger.warning(
                f"[{self.addr}] Couldn't send datas because "
                "peer is not running!"
            )
            return
        try:
            await asyncio.wait_for(self.send_lock.acquire(), 3)
            self.writer.write(datas)
            await self.writer.drain()
        except Exception:
            logger.warning(
                f"[{self.addr}] Failed to send data.\n"
                f"Detail: {traceback.format_exc()}"
            )
            await self.close()
        finally:
            self.send_lock.release()

    async def send_auth(self) -> None:
        auth_EIP8 = self.ecies.create_auth_EIP8()
        await self.send(auth_EIP8)
        # auth_non_EIP8 = self.ecies.create_auth_non_EIP8()
        # await self.send(auth_non_EIP8)
        logger.info(f"[{self.addr}] Send auth (EIP8: True).")

    async def send_ack(self) -> None:
        if self.ecies.got_EIP8_auth:
            ack_EIP8 = self.ecies.create_ack_EIP8()
            await self.send(ack_EIP8)
        else:
            ack_old = self.ecies.create_ack_old()
            await self.send(ack_old)
        logger.info(
            f"[{self.addr}] Send ack (EIP8: {self.ecies.got_EIP8_auth})."
        )

    async def send_header_and_body(self, code: bytes, data: bytes) -> None:
        msg = b"".join((code, data))
        header = self.ecies.create_header(len(msg))
        body = self.ecies.create_body(msg)
        await self.send(header + body)

    async def run(self) -> None:
        logger.info(f"[{self.addr}] Start receiving data.")
        try:
            while not self.reader.at_eof():
                data = await self.reader.readexactly(self.next_packet_size)
                match self.state:
                    case STATE.AUTH:
                        await self.handle_auth(data)
                    case STATE.ACK:
                        await self.handle_ack(data)
                    case STATE.HEADER:
                        await self.handle_header(data)
                    case STATE.BODY:
                        await self.handle_body(data)
        except Exception:
            logger.warning(
                f"[{self.addr}] Occurred an error when handle msg.\n"
                f"Detail: {traceback.format_exc()}"
            )
            await self.close()

    async def handle_auth(self, data: bytes) -> None:
        if data[0] == 0x04:
            self.ecies.parse_auth_plain(data)
            logger.info(f"[{self.addr}] Received auth (EIP8: False).")
        else:
            self.ecies.got_EIP8_auth = True
            packet_size = int.from_bytes(data[:2], "big")
            data += await self.reader.readexactly(packet_size - 307 + 2)
            self.ecies.parse_auth_EIP8(data)
            logger.info(f"[{self.addr}] Received auth (EIP8: True).")
        self.remote_id = self.ecies.remote_pubkey
        self.state = STATE.HEADER
        self.next_packet_size = 32
        await self.send_ack()
        if not self.has_auth.is_set():
            self.has_auth.set(True)
            self.timeout_task.cancel()
        await self.after_auth()

    async def handle_ack(self, data: bytes) -> None:
        if data[0] == 0x04:
            self.ecies.parse_ack_plain(data)
            logger.info(f"[{self.addr}] Received ack (EIP8: False).")
        else:
            self.ecies.got_EIP8_ack = True
            packet_size = int.from_bytes(data[:2], "big")
            data += await self.reader.readexactly(packet_size - 210 + 2)
            self.ecies.parse_ack_EIP8(data)
            logger.info(f"[{self.addr}] Received ack (EIP8: True).")
        self.state = STATE.HEADER
        self.next_packet_size = 32
        if not self.has_auth.is_set():
            self.has_auth.set(True)
            self.timeout_task.cancel()
        await self.after_auth()

    async def handle_header(self, data: bytes) -> None:
        size = self.ecies.parse_header(data)
        if size <= 0:
            logger.info(
                f"[{self.addr}] Received invalid header size.")
            return
        logger.info(f"[{self.addr}] Received header.")
        self.state = STATE.BODY
        self.next_packet_size = size + 16
        if size % 16 > 0:
            self.next_packet_size += 16 - (size % 16)

    async def handle_body(self, data: bytes) -> None:
        body = self.ecies.parse_body(data)
        if len(body) == 0:
            logger.warning(f"[{self.addr}] Received empty body.")
            return
        logger.info(f"[{self.addr}] Received body.")
        self.state = STATE.HEADER
        self.next_packet_size = 32
        await self.handle_message(body)

    @abc.abstractmethod
    async def after_auth(self) -> None:
        raise NotImplementedError()

    @abc.abstractmethod
    async def handle_message(self, data: bytes) -> None:
        raise NotImplementedError()
