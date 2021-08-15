#!/usr/bin/env python
# -*- codeing:utf-8 -*-

"""A implemention of the peer in Ethereum p2p network.
"""

__author__ = "XiaoHuiHui"
__version__ = "1.1"

from abc import ABCMeta, abstractmethod
import logging
from logging import FileHandler, Formatter
from typing import Union
from enum import Enum
import traceback

from eth_keys.datatypes import PrivateKey, PublicKey
import trio
from trio import SocketStream, Event, StrictFIFOLock

from .ecies import ECIES
import utils

RLP = Union[list[list[bytes]], list[bytes], bytes]

logger = logging.getLogger("rlpx.peer")
fh = FileHandler("./logs/rlpx/peer.log", "w", encoding="utf-8")
fmt = Formatter("%(asctime)s [%(name)s][%(levelname)s] %(message)s")
fh.setFormatter(fmt)
fh.setLevel(logging.WARN)
logger.addHandler(fh)


class STATE(Enum):
    AUTH = 0
    ACK = 1
    HEADER = 2
    BODY = 3


class PeerHandler(metaclass=ABCMeta):
    """
    """
    def bind(self, peer: "Peer") -> None:
        self.peer = peer

    @abstractmethod
    async def successful_authentication(self) -> None:
        return NotImplemented

    @abstractmethod
    async def disconnection(self) -> None:
        return NotImplemented
    
    @abstractmethod
    async def handle_message(self, data: bytes) -> None:
        return NotImplemented


class Peer:
    """
    """

    def __init__(self, private_key: PrivateKey, remote_id: PublicKey,
            socket_stream: SocketStream, EIP8: bool, waiting_timeout: int,
            lock_timeout: int) -> None:
        self.id = private_key.public_key
        self.socket_stream = socket_stream
        self.EIP8 = EIP8
        self.waiting_timeout = waiting_timeout
        self.lock_timeout = lock_timeout
        self.handlers: list[PeerHandler] = []
        self.running = False
        self.rckey = utils.get_socket_rckey(socket_stream)
        self.ecies_session = ECIES(private_key, remote_id)
        self.socket_data = b""
        self.state = STATE.AUTH
        self.next_packet_size = 307
        self.has_auth = Event()
        self.send_lock = StrictFIFOLock()

    async def bind(self, active: bool) -> None:
        async with trio.open_nursery() as peer_loop:
            self.peer_loop = peer_loop
            self.running = True
            peer_loop.start_soon(self.timeout_check)
            if active:
                if not await self.send_auth():
                    self.has_auth.set()
                    await self.end()
                    return
            peer_loop.start_soon(self.recv_loop)

    def register_handler(self, handler: PeerHandler) -> None:
        handler.bind(self)
        self.handlers.append(handler)

    async def timeout_check(self) -> None:
        with trio.move_on_after(self.waiting_timeout) as cancel_scope:
            await self.has_auth.wait()
        if cancel_scope.cancelled_caught:
            if self.has_auth.is_set():
                return
            logger.warn(
                f"Connection to {self.rckey} waiting for auth timeout."
            )
            await self.end()
        
    async def recv_loop(self) -> None:
        try:
            logger.info(f"Start recieving data from {self.rckey}.")
            async for data in self.socket_stream:
                self.socket_data += data
                while len(self.socket_data) >= self.next_packet_size:
                    if self.state == STATE.AUTH:
                        await self.handle_auth()
                    elif self.state == STATE.ACK:
                        await self.handle_ack()
                    elif self.state == STATE.HEADER:
                        await self.handle_header()
                    elif self.state == STATE.BODY:
                        await self.handle_body()
        except Exception:
            logger.warn(
                f"Error on data handling from {self.rckey}."
                f" \nDetail: {traceback.format_exc()}"
            )
            if not self.has_auth.is_set():
                self.has_auth.set()
            await self.end()
            return

    async def end(self) -> None:
        if not self.running:
            return
        self.running = False
        if self.has_auth.is_set():  
            for handler in self.handlers:
                try:
                    await handler.disconnection()
                except Exception:
                    logger.error(
                        f"Error on calling disconnection from peer "
                        f"{self.rckey} to controller.\n"
                        f"Detail: {traceback.format_exc()}"
                    )
        self.peer_loop.cancel_scope.cancel()
        await utils.unsafe_close(self.socket_stream)

    async def send(self, datas: bytes) -> bool:
        """Safe send.
        """
        async with self.send_lock:
            with trio.move_on_after(self.lock_timeout) as cancel_scope:
                try:
                    await self.socket_stream.send_all(datas)
                except Exception:
                    logger.warn(
                        f"Failed to send data to {self.rckey}.\n"
                        f"Detail: {traceback.format_exc()}"
                    )
                    return False
            if cancel_scope.cancelled_caught:
                logger.warn(f"Sending data to {self.rckey} timeout.")
                return False
            return True

    async def handle_auth(self) -> None:
        parse_data = self.socket_data[:self.next_packet_size]
        if not self.ecies_session.got_EIP8_auth:
            if parse_data[0] == 0x04:
                self.ecies_session.parse_auth_plain(parse_data)
            else:
                self.ecies_session.got_EIP8_auth = True
                self.next_packet_size = \
                    int.from_bytes(self.socket_data[:2], "big") + 2
                return
        else:
            self.ecies_session.parse_auth_EIP8(parse_data)
        self.socket_data = self.socket_data[self.next_packet_size:]
        logger.info(
            f"Handle auth (EIP8: {self.ecies_session.got_EIP8_auth}) to "
            f"{self.rckey}."
        )
        self.has_auth.set()
        self.state = STATE.HEADER
        self.next_packet_size = 32
        if not await self.send_ack():
            await self.end()
        else:
            for handler in self.handlers:
                try:
                    await handler.successful_authentication(self)
                except Exception:
                    logger.error(
                        f"Error on calling successful_authentication from "
                        f"peer {self.rckey} to controller.\n"
                        f"Detail: {traceback.format_exc()}"
                    )

    async def send_ack(self) -> bool:
        if self.ecies_session.got_EIP8_auth:
            ack_EIP8 = self.ecies_session.create_ack_EIP8()
            result = await self.send(ack_EIP8)
        else:
            ack_old = self.ecies_session.create_ack_old()
            result = await self.send(ack_old)
        logger.info(
            f"Send ack (EIP8: {self.ecies_session.got_EIP8_auth}) to "
            f"{self.rckey}."
        )
        return result

    async def send_auth(self) -> bool:
        if self.EIP8:
            auth_EIP8 = self.ecies_session.create_auth_EIP8()
            result = await self.send(auth_EIP8)
        else:
            auth_non_EIP8 = self.ecies_session.create_auth_non_EIP8()
            result = await self.send(auth_non_EIP8)
        logger.info(
            f"Send auth (EIP8: {self.EIP8}) to {self.rckey}."
        )
        self.state = STATE.ACK
        self.next_packet_size = 210
        return result

    async def handle_ack(self) -> None:
        parse_data = self.socket_data[:self.next_packet_size]
        if not self.ecies_session.got_EIP8_ack:
            if parse_data[0] == 0x04:
                self.ecies_session.parse_ack_plain(parse_data)
                logger.info(
                    f"Received ack (old format) from {self.rckey}."
                )
            else:
                self.ecies_session.got_EIP8_ack = True
                self.next_packet_size = \
                        int.from_bytes(self.socket_data[:2], "big") + 2
                return
        else:
            self.ecies_session.parse_ack_EIP8(parse_data)
            logger.info(f"Received ack (EIP8) from {self.rckey}.")
        self.socket_data = self.socket_data[self.next_packet_size:]
        self.has_auth.set()
        for handler in self.handlers:
            try:
                await handler.successful_authentication()
            except Exception:
                logger.error(
                    f"Error on calling successful_authentication from peer "
                    f"{self.rckey} to controller.\n"
                    f"Detail: {traceback.format_exc()}"
                )
        self.state = STATE.HEADER
        self.next_packet_size = 32

    async def send_message(self, code: bytes, data: bytes) -> bool:
        msg = b"".join((code, data))
        header = self.ecies_session.create_header(len(msg))
        body = self.ecies_session.create_body(msg)
        return await self.send(header + body)
    
    async def handle_header(self) -> None:
        parse_data = self.socket_data[:self.next_packet_size]
        size = self.ecies_session.parse_header(parse_data)
        self.socket_data = self.socket_data[self.next_packet_size:]
        if size <= 0:
            logger.warn(f"Received invalid header size from {self.rckey}.")
            return
        logger.info(f"Received header from {self.rckey}.")
        self.state = STATE.BODY
        self.next_packet_size = size + 16
        if size % 16 > 0:
            self.next_packet_size += 16 - (size % 16)

    async def safe_handle_message(self, handler: PeerHandler,
            body: bytes) -> None:
        try:
            await handler.handle_message(body)
        except Exception:
            logger.error(
                f"Error on calling handle_message from peer "
                f"{self.rckey} to controller.\n"
                f"Detail: {traceback.format_exc()}"
            )

    async def handle_body(self) -> None:
        parse_data = self.socket_data[:self.next_packet_size]
        self.socket_data = self.socket_data[self.next_packet_size:]
        body = self.ecies_session.parse_body(parse_data)
        if len(body) == 0:
            logger.warn(f"Received empty body from {self.rckey}.")
            return
        logger.info(f"Received body from {self.rckey}.")
        self.state = STATE.HEADER
        self.next_packet_size = 32
        for handler in self.handlers:
            self.peer_loop.start_soon(
                self.safe_handle_message,
                handler,
                body
            )
