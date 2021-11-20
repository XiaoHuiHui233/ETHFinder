#!/usr/bin/env python
# -*- codeing:utf-8 -*-
"""A implemention of RLPx protocol.
"""

__author__ = "XiaoHuiHui"
__version__ = "1.1"

from abc import ABCMeta, abstractmethod
from enum import Enum
import logging
from logging import FileHandler, Formatter
from typing import Union
import traceback

from eth_keys.datatypes import PublicKey
import trio
from trio import Event
import rlp
import snappy

from ..peer import PeerHandler
from .datatypes import Capability

logger = logging.getLogger("rlpx.protocols.p2p")
fh = FileHandler("./logs/rlpx/protocols/p2p.log", "w", encoding="utf-8")
fmt = Formatter("%(asctime)s [%(name)s][%(levelname)s] %(message)s")
fh.setFormatter(fmt)
fh.setLevel(logging.WARN)
logger.addHandler(fh)

RLP = Union[list[list[bytes]], list[bytes], bytes]


class Protocol(metaclass=ABCMeta):
    """
    """

    rel: dict[Capability, type["Protocol"]] = {}

    def __init__(
        self, base: "P2p", capability: Capability, offset: int
    ) -> None:
        self.base = base
        self.name = capability.name
        self.version = capability.version
        self.length = capability.length
        self.offset = offset

    def __str__(self) -> str:
        return f"{self.name}, {self.version}, {self.length}, {self.offset}"

    @abstractmethod
    async def after_hello(self) -> None:
        return NotImplemented

    @abstractmethod
    async def handle_message(self, code: int, payload: RLP) -> None:
        return NotImplemented

    @abstractmethod
    async def disconnect(self) -> None:
        return NotImplemented

    @classmethod
    def register(
        cls, capability: Capability, protocol: type["Protocol"]
    ) -> None:
        cls.rel[capability] = protocol

    @classmethod
    def generate(
        cls, base: "P2p", capability: Capability, offset: int
    ) -> "Protocol":
        return cls.rel[capability](base, capability, offset)


class BASE_PREFIXES(Enum):
    HELLO = 0x00
    DISCONNECT = 0x01
    PING = 0x02
    PONG = 0x03


class DISCONNECT_REASONS(Enum):
    DISCONNECT_REQUESTED = 0x00
    NETWORK_ERROR = 0x01
    PROTOCOL_ERROR = 0x02
    USELESS_PEER = 0x03
    TOO_MANY_PEERS = 0x04
    ALREADY_CONNECTED = 0x05
    INCOMPATIBLE_VERSION = 0x06
    INVALID_IDENTITY = 0x07
    CLIENT_QUITTING = 0x08
    UNEXPECTED_IDENTITY = 0x09
    SAME_IDENTITY = 0x0a
    TIMEOUT = 0x0b
    SUBPROTOCOL_ERROR = 0x10


class HelloMessage:
    """
    """
    def __init__(
        self,
        protocol_version: int,
        client_id: str,
        capabilities: list[Capability],
        port: int,
        id: PublicKey
    ) -> None:
        self.protocol_version = protocol_version
        self.client_id = client_id
        self.capabilities = capabilities
        self.port = port
        self.id = id

    @classmethod
    def from_RLP(cls, payload: RLP) -> "HelloMessage":
        return cls(
            int.from_bytes(payload[0], byteorder="big"),
            payload[1].decode(),
            [
                Capability(
                    i[0].decode(), int.from_bytes(i[1], byteorder="big"), 0
                ) for i in payload[2]
            ],
            int.from_bytes(payload[3], byteorder="big"),
            PublicKey(payload[4]),
        )

    def to_RLP(self) -> RLP:
        return [
            self.protocol_version,
            self.client_id,
            [
                capability.to_RLP() for capability in self.capabilities
            ],
            self.port,
            self.id.to_bytes(),
        ]

    def __str__(self) -> str:
        return "Hello Message: [\n" \
            f"    Protocol Version: {self.protocol_version}\n" \
            f"    Client ID: {self.client_id}\n" \
            "    Capabilities: [\n" + \
            "".join(
                [
                    f"        {cap}\n" for cap in self.capabilities
                ]
            ) + \
            f"    ]\n    Port: {self.port}\n" \
            f"    Id: {self.id.to_bytes().hex()[:7]}\n]"


class P2pListener(metaclass=ABCMeta):
    """
    """
    @abstractmethod
    def on_protocols(self, protocols: list[Protocol]) -> None:
        return NotImplemented


class P2p(PeerHandler):
    """
    """
    def __init__(
        self,
        protocol_version: int,
        protocol_length: int,
        client_id: str,
        port: int,
        remote_id_filter: list[str],
        ping_interval: int,
        ping_timeout: int,
        hello_timeout: int
    ) -> None:
        self.protocol_version = protocol_version
        self.protocol_length = protocol_length
        self.client_id = client_id
        self.capabilities = list(Protocol.rel.keys())
        self.port = port
        self.remote_id_filter = remote_id_filter
        self.ping_interval = ping_interval
        self.ping_timeout = ping_timeout
        self.hello_timeout = hello_timeout
        self.hello_event = Event()
        self.disconnect = False
        self.protocols: list[Protocol] = []
        self.compress = False
        self.listeners: list[P2pListener] = []

    def register_listener(self, listener: P2pListener) -> None:
        self.listeners.append(listener)

    async def successful_authentication(self) -> None:
        self.rckey = self.peer.rckey
        await self.send_hello()

    async def disconnection(self) -> None:
        for protocol in self.protocols:
            try:
                await protocol.disconnect()
            except Exception:
                logger.error(
                    f"Error on calling disconnect from {self.rckey} "
                    f"to protocol.\nDetail: {traceback.format_exc()}"
                )
        if not self.disconnect:
            await self.send_disconnect(DISCONNECT_REASONS.PROTOCOL_ERROR)

    async def send_message(self, code: int, payload: RLP) -> bool:
        if self.compress:
            return await self.peer.send_message(
                rlp.encode(code), snappy.compress(rlp.encode(payload))
            )
        else:
            return await self.peer.send_message(
                rlp.encode(code), rlp.encode(payload)
            )

    async def send_disconnect(
        self,
        reason: DISCONNECT_REASONS = DISCONNECT_REASONS.DISCONNECT_REQUESTED
    ) -> None:
        logger.info(
            f"Send DISCONNECT to {self.peer.rckey} (reason: {reason})."
        )
        self.disconnect = True
        data = [reason.value]
        await self.send_message(BASE_PREFIXES.DISCONNECT.value, data)
        await self.peer.end()

    async def waiting_for_hello(self) -> None:
        with trio.move_on_after(self.hello_timeout) as cancel_scope:
            await self.hello_event.wait()
        if cancel_scope.cancelled_caught:
            if self.hello_event.is_set():
                return
            logger.warn(f"Recieved hello message timeout from {self.rckey}.")
            await self.send_disconnect(DISCONNECT_REASONS.TIMEOUT)

    async def send_hello(self) -> None:
        logger.info(f"Send HELLO to {self.rckey}.")
        self.we_hello = HelloMessage(
            self.protocol_version,
            self.client_id,
            self.capabilities,
            self.port,
            self.peer.id
        )
        await self.send_message(
            BASE_PREFIXES.HELLO.value, self.we_hello.to_RLP()
        )
        self.peer.peer_loop.start_soon(self.waiting_for_hello)

    def get_protocol(self, code: int) -> Protocol:
        for protocol in self.protocols:
            if code >= protocol.offset and \
                    code < protocol.offset + protocol.length:
                return protocol
        return None

    async def handle_message(self, body: bytes) -> None:
        code = body[0]
        if code == 0x80:
            code = 0
        logger.info(f"Handle message {code} from {self.rckey}.")
        if self.compress:
            try:
                payload = snappy.uncompress(body[1:])
            except Exception:
                logger.warn(
                    f"Error when uncompress from {self.rckey}, "
                    "try parse directly."
                )
                payload = body[1:]
            payload = rlp.decode(payload)
        else:
            payload = rlp.decode(body[1:])
        if code < self.protocol_length:
            code = BASE_PREFIXES(code)
            if code == BASE_PREFIXES.HELLO:
                await self.handle_hello(payload)
            elif code == BASE_PREFIXES.DISCONNECT:
                await self.handle_disconnect(payload)
            elif not self.hello_event.is_set():
                logger.warn(f"Never recieved hello message from {self.rckey}.")
            elif code == BASE_PREFIXES.PING:
                await self.handle_ping()
            elif code == BASE_PREFIXES.PONG:
                await self.handle_pong()
        else:
            protocol = self.get_protocol(code)
            if protocol is None:
                logger.warn(f"No suitable protocol from {self.rckey}.")
                await self.send_disconnect(DISCONNECT_REASONS.PROTOCOL_ERROR)
            else:
                code -= protocol.offset
                await protocol.handle_message(code, payload)

    async def after_hello(self) -> None:
        self.peer.peer_loop.start_soon(self.ping_loop)
        for protocol in self.protocols:
            try:
                await protocol.after_hello()
            except Exception:
                logger.error(
                    f"Error on calling after_hello from {self.rckey} to "
                    f"protocol.\nDetails: {traceback.format_exc()}"
                )

    async def handle_hello(self, payload: RLP) -> None:
        self.hello_event.set()
        logger.info(f"Recieved HELLO from {self.rckey}.")
        try:
            hello = HelloMessage.from_RLP(payload)
        except Exception:
            logger.warn(
                f"Occurred an exception when parsing hello from {self.rckey}."
            )
            await self.send_disconnect(DISCONNECT_REASONS.INVALID_IDENTITY)
            return
        self.compress = hello.protocol_version >= 5
        if self.peer.ecies_session.remote_pubkey != hello.id:
            logger.warn(f"Invalid identity from {self.rckey}.")
            await self.send_disconnect(DISCONNECT_REASONS.INVALID_IDENTITY)
            return
        for filter in self.remote_id_filter:
            if hello.client_id.lower().find(filter.lower()) != -1:
                logger.warn(f"Peer from {self.rckey} is in black-list.")
                await self.send_disconnect(DISCONNECT_REASONS.USELESS_PEER)
                return
        shared = {}
        for his_capability in hello.capabilities:
            for my_capability in self.capabilities:
                if my_capability != his_capability:
                    continue
                if my_capability.name in shared and \
                        shared[my_capability.name] > my_capability:
                    continue
                shared[my_capability.name] = my_capability
        offset = self.protocol_length
        self.protocols: list[Protocol] = []
        ls = sorted(shared.values(), key=lambda d: d.name)
        for capability in ls:
            protocol = Protocol.generate(
                self,
                capability,
                offset,
            )
            self.protocols.append(protocol)
            offset += capability.length
        if not self.protocols:
            logger.warn(f"No suitable protocol from {self.rckey}.")
            await self.send_disconnect(DISCONNECT_REASONS.USELESS_PEER)
            return
        for listener in self.listeners:
            try:
                listener.on_protocols(self.protocols)
            except Exception:
                logger.error(
                    f"Error on calling on_protocols from {self.rckey} to"
                    f" listener.\nDetail: {traceback.format_exc()}"
                )
        logger.info(
            f"Successfully connected to {self.rckey}({hello.client_id})."
        )
        await self.after_hello()

    async def handle_disconnect(self, payload: RLP) -> None:
        self.disconnect = True
        code = int.from_bytes(payload[0], byteorder="big")
        try:
            disconnect_reason = DISCONNECT_REASONS(code)
        except Exception:
            logger.warn(
                f"Disconnect reason can't be parsed.\n"
                f"Details: {traceback.format_exc()}"
            )
            disconnect_reason = DISCONNECT_REASONS.PROTOCOL_ERROR
        logger.info(
            f"Recieved DISCONNECT from {self.rckey} "
            f"(reason: {disconnect_reason})."
        )
        await self.peer.end()

    async def ping_loop(self) -> None:
        while self.peer.running:
            await trio.sleep(self.ping_interval)
            await self.send_ping()

    async def waiting_for_pong(self) -> None:
        with trio.move_on_after(self.ping_timeout) as cancel_scope:
            await self.ping_event.wait()
        if cancel_scope.cancelled_caught:
            if self.ping_event.is_set():
                return
            logger.warn(f"Recieved pong timeout from {self.rckey}.")
            await self.send_disconnect(DISCONNECT_REASONS.TIMEOUT)

    async def send_ping(self) -> None:
        logger.info(f"Send PING to {self.rckey}.")
        await self.send_message(BASE_PREFIXES.PING.value, [])
        self.ping_event = Event()
        self.peer.peer_loop.start_soon(self.waiting_for_pong)

    async def send_pong(self) -> None:
        logger.info(f"Send PONG to {self.rckey}.")
        await self.send_message(BASE_PREFIXES.PONG.value, [])

    async def handle_ping(self) -> None:
        logger.info(f"Recieved PING from {self.rckey}.")
        await self.send_pong()

    async def handle_pong(self) -> None:
        logger.info(f"Recieved PONG from {self.rckey}.")
        if not self.ping_event.is_set():
            self.ping_event.set()
