#!/usr/bin/env python
# -*- codeing:utf-8 -*-
"""A implemention of RLPx protocol.
"""

__author__ = "XiaoHuiHui"

import abc
import asyncio
import logging
import traceback
import typing
from abc import ABCMeta
from asyncio import CancelledError, Event, StreamReader, StreamWriter, Task
from datetime import datetime
from enum import Enum
from typing import Any, Callable, NamedTuple, Optional

import rlp
import snappy
from eth_keys.datatypes import PrivateKey, PublicKey

from ..datatypes import DC_REASONS, Addr, Capability, PeerParams
from ..utils import Promise
from .peer import Peer

logger = logging.getLogger("rlpx.peer.p2p")

Rlpable = list[int | bytes | str | list[Any]]
Rlpdecoded = list[bytes | list[bytes] | list[bytes | list[bytes]]]


TIMEOUT = 5
INTERVAL = 60


def now() -> int:
    return int(datetime.utcnow().timestamp())


class BASE_PREFIXES(Enum):
    HELLO = 0x00
    DISCONNECT = 0x01
    PING = 0x02
    PONG = 0x03


class Protocol(metaclass=ABCMeta):
    def __init__(self, peer: "P2pPeer", cap: Capability, offset: int) -> None:
        self.peer = peer
        self.cap = cap
        self.offset = offset

    @abc.abstractmethod
    async def after_hello(self) -> None:
        raise NotImplementedError()

    @abc.abstractmethod
    async def received_message(self, code: int, data: Rlpdecoded) -> None:
        raise NotImplementedError()

    @abc.abstractmethod
    def exit(self) -> None:
        raise NotImplementedError()


class HelloMessage(NamedTuple):
    version: int
    client_id: str
    capabilities: list[Capability]
    port: int
    id: PublicKey

    @classmethod
    def from_RLP(
        cls, payload: Rlpdecoded
    ) -> "HelloMessage":
        return cls(
            int.from_bytes(typing.cast(bytes, payload[0]), byteorder="big"),
            typing.cast(bytes, payload[1]).decode(),
            [
                Capability(
                    i[0].decode(), int.from_bytes(i[1], byteorder="big"), 0
                ) for i in typing.cast(list[list[bytes]], payload[2])
            ],
            int.from_bytes(typing.cast(bytes, payload[3]), byteorder="big"),
            PublicKey(typing.cast(bytes, payload[4])),
        )

    def to_RLP(self) -> Rlpable:
        return [
            self.version,
            self.client_id,
            [capability.to_RLP() for capability in self.capabilities],
            self.port,
            self.id.to_bytes(),
        ]

    def __repo__(self) -> str:
        return "Hello Message: [\n" \
            f"    Protocol Version: {self.version}\n" \
            f"    Client ID: {self.client_id}\n" \
            "    Capabilities: [\n" + \
            "".join(
                [
                    f"        {cap}\n" for cap in self.capabilities
                ]
            ) + \
            f"    ]\n    Port: {self.port}\n" \
            f"    Id: {self.id.to_bytes().hex()[:7]}\n]"


class P2pPeer(Peer):
    """
    """
    P2P_RESERVED: int = 0x10

    def __init__(
        self,
        hello_msg: HelloMessage,
        capabilities: list[Capability],
        caps_callables: dict[Capability, Callable[..., Protocol]],
        peer_params: PeerParams
    ) -> None:
        super().__init__(*peer_params)
        self.hello_msg = hello_msg
        self.capabilities = capabilities
        self.caps_callables = caps_callables
        self.compressed = False
        self.hear_hello = False
        self.helloed = False
        self.disconnected = False
        self.last_pong: int = 0
        self.pong_task: Optional[Task[None]] = None
        self.safe_close_task: Optional[Task[None]] = None
        self.has_hello = Promise[bool]()
        self.has_closed = Event()
        self.protocols: list[Protocol] = []

    def get_protocol(self, code: int) -> Protocol:
        last_protocol: Optional[Protocol] = None
        for protocol in self.protocols:
            if code < protocol.offset:
                assert last_protocol is not None
                return last_protocol
            last_protocol = protocol
        assert last_protocol is not None
        assert code < last_protocol.offset + last_protocol.cap.length
        return last_protocol

    async def after_auth(self) -> None:
        await self.send_hello()

    def match_caps(self, his_hello: HelloMessage) -> dict[str, Capability]:
        shared: dict[str, Capability] = {}
        his: dict[str, set[int]] = {}
        my: dict[str, set[int]] = {}
        lengths: dict[tuple[str, int], int] = {}
        for his_cap in his_hello.capabilities:
            if his_cap.name not in his:
                his[his_cap.name] = set()
            his[his_cap.name].add(his_cap.version)
        for my_cap in self.capabilities:
            if my_cap.name not in my:
                my[my_cap.name] = set()
            my[my_cap.name].add(my_cap.version)
            lengths[(my_cap.name, my_cap.version)] = my_cap.length
        for name in my:
            if name in his:
                cross = his[name] & my[name]
                if len(cross) != 0:
                    version = max(cross)
                    shared[name] = \
                        Capability(name, version, lengths[(name, version)])
        return shared

    def generate_protocols(self, shared: dict[str, Capability]) -> None:
        offset = self.P2P_RESERVED
        ls = sorted(shared.values(), key=lambda d: d.name)
        for cap in ls:
            protocol = self.caps_callables[cap](self, cap, offset)
            self.protocols.append(protocol)
            offset += cap.length

    async def send_message(self, code: int, payload: Rlpable) -> None:
        encoded_code: bytes = rlp.encode(code)  # type: ignore
        encoded_content: bytes = rlp.encode(payload)  # type: ignore
        if self.compressed:
            snappy_content: bytes = snappy.compress(  # type: ignore
                encoded_content
            )
            await self.send_header_and_body(encoded_code, snappy_content)
        else:
            await self.send_header_and_body(encoded_code, encoded_content)

    async def send_hello(self) -> None:
        await self.send_message(
            BASE_PREFIXES.HELLO.value, self.hello_msg.to_RLP()
        )
        logger.info(f"[{self.addr}] Send HELLO.")
        self.hello_timeout_task = \
            asyncio.create_task(
                self.wait_for_hello(), name=f"wait_hello_{self.addr}"
            )

    async def send_ping(self) -> None:
        logger.info(f"[{self.addr}] Send PING.")
        await self.send_message(BASE_PREFIXES.PING.value, [])

    async def send_pong(self) -> None:
        logger.info(f"[{self.addr}] Send PONG.")
        await self.send_message(BASE_PREFIXES.PONG.value, [])

    async def send_dc(
        self, reason: DC_REASONS = DC_REASONS.DC_REQUESTED
    ) -> None:
        logger.info(f"[{self.addr}] Send DISCONNECT (reason: {reason}).")
        data = [reason.value]
        await self.send_message(BASE_PREFIXES.DISCONNECT.value, data)

    async def received_message(self, code: int, data: Rlpdecoded) -> None:
        if not self.hear_hello and code >= 2:
            logger.error(
                f"[{self.addr}] Except HELLO or DISCONNECT but else received."
            )
            await self.disconnect(DC_REASONS.PROTOCOL_ERROR)
            return
        if code < self.P2P_RESERVED:
            code_e = BASE_PREFIXES(code)
            match code_e:
                case BASE_PREFIXES.HELLO:
                    await self.received_hello(data)
                case BASE_PREFIXES.DISCONNECT:
                    await self.received_dc(data)
                case BASE_PREFIXES.PING:
                    await self.received_ping()
                case BASE_PREFIXES.PONG:
                    await self.received_pong()
        else:
            protocol = self.get_protocol(code)
            await protocol.received_message(
                code - protocol.offset,
                data
            )

    def bytes_to_length(self, data: bytes) -> int:
        length = 0
        epoch = 0
        for byte in data:
            if byte > 0x80:
                length += (byte - 0x80) << (7*epoch)
                epoch += 1
            else:
                length += byte << (7*epoch)
                break
        return length

    def handle_uncompress(self, data: bytes) -> tuple[bool, Rlpdecoded]:
        try:
            decoded: Rlpdecoded = rlp.decode(data)  # type: ignore
            return True, decoded
        except Exception:
            logger.warning(f"[{self.addr}] Try decode uncompress, failed.")
            logger.debug(f"Detail: {traceback.format_exc()}")
            return False, []

    def handle_compress(self, data: bytes) -> tuple[bool, Rlpdecoded]:
        length = self.bytes_to_length(data[:8])
        if length > 1 << 24 or length <= 0:
            logger.warning(
                f"[{self.addr}] Received data too big after decompressing!"
            )
            return False, []
        try:
            payload: bytes = snappy.uncompress(data)  # type: ignore
            decoded: Rlpdecoded = rlp.decode(payload)  # type: ignore
            return True, decoded
        except Exception:
            logger.warning(f"[{self.addr}] Try decode compress, failed.")
            logger.debug(f"Detail: {traceback.format_exc()}")
            return False, []

    async def handle_message(self, data: bytes) -> None:
        if len(data) >= 1 << 24:
            logger.warning(f"[{self.addr}] Received data too big!")
            await self.disconnect(DC_REASONS.PROTOCOL_ERROR)
            return
        code: int = data[0]
        if code == 0x80:
            code = 0
        logger.info(f"[{self.addr}] Handle message {code}.")
        if self.compressed:
            flag, decoded = self.handle_compress(data[1:])
        else:
            flag, decoded = self.handle_uncompress(data[1:])
        if flag:
            await self.received_message(code, decoded)
        else:
            logger.warning(f"[{self.addr}] Failed to decode msg.")

    async def received_hello(self, payload: Rlpdecoded) -> None:
        self.hear_hello = True
        if self.has_hello.is_set():
            return
        self.has_hello.set(True)
        self.hello_timeout_task.cancel()
        logger.info(f"[{self.addr}] received HELLO.")
        try:
            hello = HelloMessage.from_RLP(payload)
        except Exception:
            logger.warning(
                f"[{self.addr}] Occurred an error when decoding HELLO.\n"
                f"Detail: {traceback.format_exc()}"
            )
            await self.disconnect(DC_REASONS.PROTOCOL_ERROR)
            return
        logger.debug(f"[{self.addr}] HIS HELLO {hello}")
        logger.info(
            f"[{self.addr}] Remote client id: {hello.client_id} "
            f"(Version: {hello.version})"
        )
        self.compressed = hello.version >= 5
        if hello.version < 4:
            logger.warning(f"[{self.addr}] Unsupported p2p protocol version.")
            await self.disconnect(DC_REASONS.INCOMPATIBLE_VERSION)
            return
        if self.remote_id is None:
            logger.warning(f"[{self.addr}] Null identity.")
            await self.disconnect(DC_REASONS.INVALID_IDENTITY)
            return
        if self.remote_id != hello.id:
            logger.warning(f"[{self.addr}] Different identities.")
            await self.disconnect(DC_REASONS.UNEXPECTED_IDENTITY)
            return
        shared = self.match_caps(hello)
        self.generate_protocols(shared)
        if len(self.protocols) == 0:
            logger.warning(f"[{self.addr}] No suitable protocol.")
            await self.disconnect(DC_REASONS.USELESS_PEER)
            return
        logger.info(f"[{self.addr}] Successfully connected.")
        await self.after_hello()

    async def received_dc(self, payload: Rlpdecoded) -> None:
        self.disconnected = True
        code = payload[0]
        if type(code) == bytes:
            code = code[0]
        dc_reason = DC_REASONS.DC_REQUESTED
        try:
            dc_reason = DC_REASONS(code)
        except Exception:
            logger.warning(
                f"[{self.addr}] Disconnect reason can't be parsed.\n"
                f"Details: {traceback.format_exc()}"
            )
        logger.info(
            f"[{self.addr}] Received DISCONNECT. (Reason: {dc_reason})"
        )
        await self.close()

    async def received_ping(self) -> None:
        logger.info(f"[{self.addr}] Received PING.")
        await self.send_pong()

    async def received_pong(self) -> None:
        logger.info(f"[{self.addr}] Received PONG.")
        self.last_pong = now()
        if self.pong_task is not None:
            self.pong_task.cancel()
            await asyncio.sleep(0)
            self.pong_task = None

    async def disconnect(
        self, reason: DC_REASONS = DC_REASONS.DC_REQUESTED
    ) -> None:
        if not self.disconnected:
            self.disconnected = True
            await self.send_dc(reason)
            try:
                await asyncio.sleep(2)
            except CancelledError:
                return
            self.safe_close_task = asyncio.create_task(
                self.close(), name=f"safe_close_{self.addr}"
            )

    async def wait_for_hello(self) -> None:
        try:
            await asyncio.sleep(TIMEOUT)
        except CancelledError:
            return
        if not self.running:
            return
        if not self.hear_hello:
            self.has_hello.set(False)
            logger.warning(
                f"[{self.addr}] Received HELLO message timeout."
            )
            await self.send_dc(DC_REASONS.TIMEOUT)

    async def after_hello(self) -> None:
        self.helloed = True
        self.ping_task = asyncio.create_task(
            self.ping_loop(), name=f"ping_loop_{self.addr}"
        )
        for protocol in self.protocols:
            await protocol.after_hello()

    async def ping_loop(self) -> None:
        while not self.disconnected:
            await asyncio.sleep(INTERVAL)
            await self.send_ping()
            self.pong_task = asyncio.create_task(
                self.wait_for_pong(), name=f"wait_pong_{self.addr}"
            )

    async def wait_for_pong(self) -> None:
        try:
            await asyncio.sleep(TIMEOUT)
        except CancelledError:
            return
        if self.last_pong - now() > 2 * TIMEOUT:
            logger.warning(f"[{self.addr}] TIMEOUT for PONG.")
            await self.send_dc(DC_REASONS.TIMEOUT)

    async def close(self) -> None:
        if self.has_closed.is_set():
            return
        self.has_closed.set()
        if not self.has_hello.is_set():
            self.has_hello.set(False)
            self.hello_timeout_task.cancel()
        if self.helloed:
            for protocol in self.protocols:
                protocol.exit()
            try:
                self.ping_task.cancel()
                if self.pong_task is not None:
                    self.pong_task.cancel()
            except Exception:
                logger.warning(
                    f"[{self.addr}] Failed to close in p2ppeer.\n"
                    f"Detail: {traceback.format_exc()}"
                )
        await super().close()


class P2pPeerFactory:
    PROTOCOL_VERSION = 5

    def __init__(
        self,
        private_key: PrivateKey,
        client_id: str,
    ) -> None:
        self.private_key = private_key
        self.client_id = client_id
        self.capabilities: list[Capability] = []
        self.cap_callables: dict[Capability, Callable[..., Protocol]] = {}
        self.changed = True

    def register_capability(
        self, cap: Capability, callable: Callable[..., Protocol]
    ) -> None:
        self.changed = True
        self.capabilities.append(cap)
        self.cap_callables[cap] = callable

    def hello(self, port: int) -> HelloMessage:
        if self.changed:
            self.hello_msg = HelloMessage(
                self.PROTOCOL_VERSION,
                self.client_id,
                self.capabilities,
                port,
                self.private_key.public_key
            )
            self.changed = False
        return self.hello_msg

    def create(
        self,
        addr: Addr,
        port: int,
        remote_id: Optional[PublicKey],
        reader: StreamReader,
        writer: StreamWriter
    ) -> P2pPeer:
        return P2pPeer(
            self.hello(port),
            self.capabilities,
            self.cap_callables,
            PeerParams(addr, self.private_key, remote_id, reader, writer)
        )
