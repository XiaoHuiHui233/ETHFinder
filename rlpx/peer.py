import logging
from typing import Callable, Coroutine, TypeVar, List
from enum import Enum

from eth_keys.datatypes import PrivateKey, PublicKey
import trio
from trio import SocketStream, BrokenResourceError, ClosedResourceError, \
    BusyResourceError
from trio._core._run import NurseryManager

import config as opts
from rlpx.ecies import ECIES, ParseError
from rlpx.procotols.p2p import DISCONNECT_REASONS, P2pProcotol

RLP = TypeVar("RLP", List[List[bytes]], List[bytes], bytes)

logger = logging.getLogger("rlpx")


class STATE(Enum):
    AUTH = 0
    ACK = 1
    HEADER = 2
    BODY = 3


class Peer:
    """
    """

    def __init__(self, id: PublicKey, remote_id: PublicKey,
            socket_stream: SocketStream, private_key: PrivateKey,
            after_connected: Callable[["Peer"], Coroutine],
            peer_loop: NurseryManager) -> None:
        self.id = id
        self.remote_id = remote_id
        self.socket_stream = socket_stream
        tp = self.socket_stream.socket.getpeername()
        remote_address, remote_port = tp[0], tp[1]
        if len(tp) > 2:
            self.rckey = f"[{remote_address}]:{remote_port}"
        else:
            self.rckey = f"{remote_address}:{remote_port}"
        self.after_connected = after_connected
        self.peer_loop = peer_loop
        self.ecies_session = ECIES(private_key, id, remote_id)
        self.base_protocol = P2pProcotol(self, peer_loop)
        self.socket_data = b""
        self.state = STATE.AUTH
        self.next_packet_size = 307
        self.closed = False
        

    def __str__(self) -> str:
        return self.rckey

    async def timeout_check(self) -> Coroutine:
        await trio.sleep(3)
        if self.state != STATE.HEADER and self.state != STATE.BODY:
            await self.end()

    async def recv_loop(self) -> Coroutine:
        while not self.closed:
            try:
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
            except BrokenResourceError as err:
                logger.warning(
                    "Error on peer socket data handling from "
                    f"{self.rckey}: {err}"
                )
                self.closed = True
                break
            except ClosedResourceError:
                self.closed = True
                break

    async def handle_auth(self) -> Coroutine:
        parse_data = self.socket_data[:self.next_packet_size]
        try:
            if not self.ecies_session.got_EIP8_auth:
                if parse_data[0] == 0x04:
                    self.ecies_session.parse_auth_plain(parse_data)
                else:
                    self.ecies_session.got_EIP8_auth = True
                    self.next_packet_size = \
                        int.from_bytes(self.socket_data[:2], byteorder="big") + 2
                    return
            else:
                self.ecies_session.parse_auth_EIP8(parse_data)
        except ParseError as err:
            logger.warning(f"Except parse error, detail: {err}")
            await self.end()
            return
        self.socket_data = self.socket_data[self.next_packet_size:]
        self.state = STATE.HEADER
        self.next_packet_size = 32
        self.peer_loop.start_soon(self.send_ack)

    async def send_ack(self) -> Coroutine:
        logger.debug(
            f"Send ack (EIP8: {self.ecies_session.got_EIP8_auth}) to "
            f"{self.rckey}."
        )
        try:
            if self.ecies_session.got_EIP8_auth:
                ack_EIP8 = self.ecies_session.create_ack_EIP8()
                await self.socket_stream.send_all(ack_EIP8)
            else:
                ack_old = self.ecies_session.create_ack_old()
                await self.socket_stream.send_all(ack_old)
        except BrokenResourceError as err:
            logger.warning(f"Broken resource error, detail: {err}")
            return
        except ClosedResourceError:
            return
        self.state = STATE.HEADER
        self.next_packet_size = 32
        self.peer_loop.start_soon(self.after_connected, self)
        self.peer_loop.start_soon(self.base_protocol.send_hello)

    async def send_message(self, code: bytes, data: bytes) -> Coroutine:
        msg = b"".join((code, data))
        header = self.ecies_session.create_header(len(msg))
        body = self.ecies_session.create_body(msg)
        try:
            await self.socket_stream.send_all(header + body)
        except BrokenResourceError as err:
            logger.warning(f"Broken resource error, detail: {err}")
            return
        except ClosedResourceError:
            return
        except BusyResourceError as err:
            logger.warning(
                f"Error on data sending to {self.rckey}: {err}"
            )
            return


    async def end(self) -> Coroutine:
        self.closed = True
        try:
            await self.socket_stream.aclose()
        except ClosedResourceError:
            return

    async def send_auth(self) -> Coroutine:
        logger.debug(
            f"Send auth (EIP8: {opts.EIP8}) to {self.rckey}."
        )
        try:
            if opts.EIP8:
                auth_EIP8 = self.ecies_session.create_auth_EIP8()
                await self.socket_stream.send_all(auth_EIP8)
            else:
                auth_non_EIP8 = self.ecies_session.create_auth_non_EIP8()
                await self.socket_stream.send_all(auth_non_EIP8)
        except BrokenResourceError as err:
            logger.warning(f"Broken resource error, detail: {err}")
            return
        except ClosedResourceError:
            return
        self.state = STATE.ACK
        self.next_packet_size = 210

    async def handle_ack(self) -> Coroutine:
        parse_data = self.socket_data[:self.next_packet_size]
        try:
            if not self.ecies_session.got_EIP8_ack:
                if parse_data[0] == 0x04:
                    self.ecies_session.parse_ack_plain(parse_data)
                    logger.debug(
                        f"Received ack (old format) from {self.rckey}."
                    )
                else:
                    self.ecies_session.got_EIP8_ack = True
                    self.next_packet_size = \
                        int.from_bytes(self.socket_data[:2], byteorder="big") + 2
                    return
            else:
                self.ecies_session.parse_ack_EIP8(parse_data)
                logger.debug(
                    f"Received ack (EIP8) from {self.rckey}."
                )
        except ParseError as err:
            logger.warning(f"Except parse error, detail: {err}")
            await self.end()
            return
        self.socket_data = self.socket_data[self.next_packet_size:]
        self.state = STATE.HEADER
        self.next_packet_size = 32
        self.peer_loop.start_soon(self.after_connected, self)
        self.peer_loop.start_soon(self.base_protocol.send_hello)
    
    async def handle_header(self) -> Coroutine:
        parse_data = self.socket_data[:self.next_packet_size]
        logger.debug(
            f"Received header from {self.rckey}."
        )
        try:
            size = self.ecies_session.parse_header(parse_data)
        except ParseError as err:
            logger.warning(f"Except parse error, detail: {err}")
            self.peer_loop.start_soon(
                self.base_protocol.send_disconnect,
                DISCONNECT_REASONS.PROTOCOL_ERROR
            )
            return
        if size == 0:
            logger.debug("Invalid header size!")
            return
        self.socket_data = self.socket_data[self.next_packet_size:]
        self.state = STATE.BODY
        self.next_packet_size = size + 16
        if size % 16 > 0:
            self.next_packet_size += 16 - (size % 16)

    async def handle_body(self) -> Coroutine:
        parse_data = self.socket_data[:self.next_packet_size]
        logger.debug(
            f"Received body from {self.rckey}."
        )
        try:
            body = self.ecies_session.parse_body(parse_data)
        except ParseError as err:
            logger.warning(f"Except parse error, detail: {err}")
            self.peer_loop.start_soon(
                self.base_protocol.send_disconnect,
                DISCONNECT_REASONS.PROTOCOL_ERROR
            )
            return
        if len(body) == 0:
            logger.debug("Empty body!")
            return
        self.socket_data = self.socket_data[self.next_packet_size:]
        self.state = STATE.HEADER
        self.next_packet_size = 32
        await self.base_protocol.handle_message(body)

