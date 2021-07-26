from __future__ import annotations
from enum import Enum
from typing import Coroutine, TypeVar, List, TYPE_CHECKING
import logging
from logging import FileHandler, Formatter
import time

from eth_keys.datatypes import PublicKey
from eth_utils.exceptions import ValidationError
import trio
from trio._core._run import NurseryManager
import rlp
import snappy

from rlpx.procotols.procotol import Capability, Procotol
if TYPE_CHECKING:
    from rlpx.peer import Peer
import config as opts

BASE_PROTOCOL_VERSION = 5
BASE_PROTOCOL_LENGTH = 16
PING_INTERVAL = 15

logger = logging.getLogger("rlpx.p2p")
fh = FileHandler('./logs/rlpx.log')
fmt = Formatter("%(asctime)s [%(name)s][%(levelname)s] %(message)s")
fh.setFormatter(fmt)
fh.setLevel(logging.INFO)
logger.addHandler(fh)

RLP = TypeVar("RLP", List[List[bytes]], List[bytes], bytes, int)


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

    def __init__(self, protocol_version: int, client_id: str,
            capabilities: List[Capability], port: int, id: PublicKey) -> None:
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
                    i[0].decode(),
                    int.from_bytes(i[1], byteorder="big"),
                    0
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
                capability.to_RLP() \
                    for capability in self.capabilities
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
                    f"        {capability}\n" \
                        for capability in self.capabilities
                ]
            ) + \
            f"    ]\n    Port: {self.port}\n" \
            f"    Id: {self.id.to_bytes().hex()[:7]}\n]"


class P2pProcotol:
    """
    """

    def __init__(self, sender: Peer, peer_loop: NurseryManager) -> None:
        self.sender = sender
        self.rckey = sender.rckey
        self.peer_loop = peer_loop
        self.hello = None
        self.we_hello = None
        self.disconnect_reason = None
        self.we_disconnect = False
        self.disconnect = False
        self.capabilities = opts.CAPABILITIES
        self.protocols: List[Procotol] = []
        self.compress = False
    
    async def handle_message(self, body: bytes) -> Coroutine:
        code = body[0]
        if code == 0x80:
            code = 0
        logger.debug(f"Handle message {code} from {self.rckey}.")
        if self.compress:
            try:
                payload = rlp.decode(snappy.uncompress(body[1:]))
            except:
                logger.warning(
                    f"Error when uncompress from {self.rckey}, "
                    "try parse directly."
                )
                payload = rlp.decode(body[1:])
        else:
            payload = rlp.decode(body[1:])
        if code < BASE_PROTOCOL_LENGTH:
            code = BASE_PREFIXES(code)
            if code == BASE_PREFIXES.HELLO:
                await self.handle_hello(payload)
            elif code == BASE_PREFIXES.DISCONNECT:
                await self.handle_disconnect(payload)
            elif self.hello is None:
                logger.warning(
                    f"Never recieved hello message from {self.rckey}."
                )
                self.peer_loop.start_soon(
                    self.send_disconnect,
                    DISCONNECT_REASONS.PROTOCOL_ERROR
                )
            elif code == BASE_PREFIXES.PING:
                await self.handle_ping()
            elif code == BASE_PREFIXES.PONG:
                await self.handle_pong()
            else:
                raise Exception("Unreachable")
        else:
            protocol = self.get_protocol(code)
            if protocol is None:
                logger.warning(
                    f"No suitable protocol from {self.rckey}."
                )
                self.peer_loop.start_soon(
                    self.send_disconnect,
                    DISCONNECT_REASONS.PROTOCOL_ERROR
                )
                return
            msg_code = code - protocol.offset
            await protocol.handle_message(msg_code, payload)

    def get_protocol(self, code: int) -> Procotol:
        for protocol in self.protocols:
            if code >= protocol.offset \
                and code < protocol.offset + protocol.length:
                return protocol
        return None
    
    async def handle_hello(self, payload: RLP) -> Coroutine:
        logger.info(f"Recieved HELLO from {self.rckey}.")
        try:
            self.hello = HelloMessage.from_RLP(payload)
        except ValidationError:
            logger.warning(
                f"Invalid pubkey id from {self.rckey}."
            )
            self.peer_loop.start_soon(
                self.send_disconnect,
                DISCONNECT_REASONS.INVALID_IDENTITY
            )
            return
        self.compress = self.hello.protocol_version >= 5
        if self.sender.remote_id is None:
            self.sender.remote_id = self.hello.id
        elif self.sender.remote_id != self.hello.id:
            logger.warning(
                f"Invalid identity from {self.rckey}."
            )
            self.peer_loop.start_soon(
                self.send_disconnect,
                DISCONNECT_REASONS.INVALID_IDENTITY
            )
            return
        for filter in opts.REMOTE_ID_FILTER:
            if self.hello.client_id.lower().find(filter.lower()) != -1:
                logger.warning(
                    f"Peer from {self.rckey} is in black-list."
                )
                self.peer_loop.start_soon(
                    self.send_disconnect,
                    DISCONNECT_REASONS.USELESS_PEER
                )
                return
        shared = {}
        for his_capability in self.hello.capabilities:
            for my_capability in self.capabilities:
                if my_capability != his_capability:
                    continue
                if my_capability.name in shared \
                    and shared[my_capability.name] > my_capability:
                    continue
                shared[my_capability.name] = my_capability
        offset = BASE_PROTOCOL_LENGTH
        self.protocols = []
        ls = sorted(shared.values(), key=lambda d: d.name)
        for capability in ls:
            procotol = Procotol.generate(
                self,
                capability,
                offset,
                self.peer_loop
            )
            self.protocols.append(procotol)
            self.peer_loop.start_soon(procotol.bind)
            offset += capability.length
        if len(self.protocols) == 0:
            logger.warning(
                f"No suitable protocol from {self.rckey}."
            )
            self.peer_loop.start_soon(
                self.send_disconnect,
                DISCONNECT_REASONS.USELESS_PEER
            )
            return
        self.peer_loop.start_soon(self.ping_loop)

    async def send_hello(self) -> Coroutine:
        logger.info(f"Send HELLO to {self.rckey}.")
        self.we_hello = HelloMessage(
            BASE_PROTOCOL_VERSION,
            opts.CLIENT_ID,
            self.capabilities,
            opts.SERVER_ENDPOINT.tcp_port,
            self.sender.id
        )
        await self.send_message(
            BASE_PREFIXES.HELLO.value,
            self.we_hello.to_RLP()
        )
        await trio.sleep(3)
        if self.hello is None:
            logger.warning(
                f"Recieved hello message timeout from {self.rckey}."
            )
            self.peer_loop.start_soon(
                self.send_disconnect,
                DISCONNECT_REASONS.TIMEOUT
            )
    
    async def send_disconnect(
            self,
            reason: DISCONNECT_REASONS = \
                DISCONNECT_REASONS.DISCONNECT_REQUESTED
            ) -> Coroutine:
        logger.info(
            f"Send DISCONNECT to {self.rckey} (reason: {reason})."
        )
        self.disconnect_reason = reason
        self.we_disconnect = True
        data = [reason.value]
        await self.send_message(BASE_PREFIXES.DISCONNECT.value, data)
        self.peer_loop.start_soon(self.sender.end)
    
    async def handle_disconnect(self, payload: RLP) -> Coroutine:
        self.disconnect = True
        if isinstance(payload[0], bytes):
            code = int.from_bytes(payload[0], byteorder="big")
        elif isinstance(payload[0], int):
            code = payload[0]
        elif isinstance(payload[0], list):
            code = payload[0][0]
        try:
            self.disconnect_reason = DISCONNECT_REASONS(code)
        except ValueError as err:
            logger.warning(
                f"Disconnect reason can't be parsed, details: {err}"
            )
            self.disconnect_reason = DISCONNECT_REASONS.PROTOCOL_ERROR
        logger.info(
            f"Recieved DISCONNECT from {self.rckey} "
            f"(reason: {self.disconnect_reason})."
        )
        self.peer_loop.start_soon(self.sender.end)

    async def ping_loop(self) -> Coroutine:
        async with trio.open_nursery() as ping_loop:
            while not self.sender.closed:
                await trio.sleep(PING_INTERVAL)
                ping_loop.start_soon(self.send_ping)

    async def send_ping(self) -> Coroutine:
        logger.info(f"Send PING to {self.rckey}.")
        data = []
        await self.send_message(BASE_PREFIXES.PING.value, data)
        self.last_ping_time = time.time()
        self.had_recieved_pong = False
        await trio.sleep(opts.RLPX_TIMEOUT)
        delta = time.time() - self.last_ping_time
        if delta < opts.RLPX_TIMEOUT:
            return
        if self.had_recieved_pong:
            return
        logger.info(
            f"Recieved pong timeout from {self.rckey}."
        )
        self.peer_loop.start_soon(
            self.send_disconnect,
            DISCONNECT_REASONS.TIMEOUT
        )

    async def send_pong(self) -> Coroutine:
        logger.info(f"Send PONG to {self.rckey}.")
        data = []
        await self.send_message(BASE_PREFIXES.PONG.value, data)

    async def handle_ping(self) -> Coroutine:
        logger.info(f"Recieved PING from {self.rckey}.")
        self.peer_loop.start_soon(self.send_pong)

    async def handle_pong(self) -> Coroutine:
        logger.info(f"Recieved PONG from {self.rckey}.")
        self.had_recieved_pong = True

    async def send_message(self, code: int, payload: RLP) -> Coroutine:
        if self.compress:
            await self.sender.send_message(
                rlp.encode(code),
                snappy.compress(rlp.encode(payload))
            )
        else:
            await self.sender.send_message(
                rlp.encode(code),
                rlp.encode(payload)
            )