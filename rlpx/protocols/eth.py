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
import traceback
from typing import Union

import trio
from trio import Event

from .datatypes import Capability
from .p2p import DISCONNECT_REASONS, P2p, Protocol
import config as opts

RLP = Union[list[list[bytes]], list[bytes], bytes]

logger = logging.getLogger("rlpx.protocols.eth")
fh = FileHandler("./logs/rlpx/protocols/eth.log", "w", encoding="utf-8")
fmt = Formatter("%(asctime)s [%(name)s][%(levelname)s] %(message)s")
fh.setFormatter(fmt)
fh.setLevel(logging.WARN)
logger.addHandler(fh)

eth62 = Capability("eth", 62, 8)
eth63 = Capability("eth", 63, 17)
eth64 = Capability("eth", 64, 29)
eth65 = Capability("eth", 65, 29)
eth66 = Capability("eth", 66, 29)


class MESSAGE_CODES(Enum):
    # eth62
    STATUS = 0x00
    NEW_BLOCK_HASHES = 0x01
    TX = 0x02
    GET_BLOCK_HEADERS = 0x03
    BLOCK_HEADERS = 0x04
    GET_BLOCK_BODIES = 0x05
    BLOCK_BODIES = 0x06
    NEW_BLOCK = 0x07
    # eth63
    GET_NODE_DATA = 0x0d
    NODE_DATA = 0x0e
    GET_RECEIPTS = 0x0f
    RECEIPTS = 0x10
    # eth65
    NEW_POOLED_TRANSACTION_HASHES = 0x08
    GET_POOLED_TRANSACTIONS = 0x09
    POOLED_TRANSACTIONS = 0x0a


class Status:
    """
    """
    def __init__(
        self,
        version: int,
        network_id: int,
        td: int,
        best_hash: bytes,
        genesis_hash: bytes,
        fork_id: tuple[bytes, int] = None
    ) -> None:
        self.version = version
        self.network_id = network_id
        self.td = td
        self.best_hash = best_hash
        self.genesis_hash = genesis_hash
        self.fork_id = fork_id

    @classmethod
    def from_RLP(cls, payload: RLP, is_eth64: bool) -> "Status":
        if is_eth64:
            return cls(
                int.from_bytes(payload[0], byteorder="big"),
                int.from_bytes(payload[1], byteorder="big"),
                int.from_bytes(payload[2], byteorder="big"),
                payload[3],
                payload[4], (
                    payload[5][0],
                    int.from_bytes(payload[5][1], byteorder="big")
                )
            )
        else:
            return cls(
                int.from_bytes(payload[0], byteorder="big"),
                int.from_bytes(payload[1], byteorder="big"),
                int.from_bytes(payload[2], byteorder="big"),
                payload[3],
                payload[4]
            )

    def to_RLP(self) -> RLP:
        if self.fork_id is None:
            return [
                self.version,
                self.network_id,
                self.td,
                self.best_hash,
                self.genesis_hash
            ]
        else:
            return [
                self.version,
                self.network_id,
                self.td,
                self.best_hash,
                self.genesis_hash, [self.fork_id[0], self.fork_id[1]]
            ]

    def __str__(self) -> str:
        s = "STATUS MESSAGE: [\n" \
            f"    V:{self.version},\n    NID:{self.network_id},\n" \
            f"    TD:{self.td},\n    BestH:{self.best_hash.hex()},\n" \
            f"    GenH:{self.genesis_hash.hex()}"
        if self.fork_id is not None:
            s += f",\n    ForkHash: {self.fork_id[0].hex()}" \
                f",\n    ForkNext: {self.fork_id[1]}"
        s += "\n]"
        return s


class EthHandler(metaclass=ABCMeta):
    """
    """
    def bind(self, eth: "Eth") -> None:
        self.eth = eth
        self.rckey = eth.rckey
        self.version = eth.version
        self.base_loop = eth.base.peer.peer_loop

    @abstractmethod
    def after_status(self) -> None:
        return NotImplemented

    @abstractmethod
    async def handle_message(self, code: MESSAGE_CODES, data: RLP) -> None:
        return NotImplemented

    @abstractmethod
    async def disconnect(self) -> None:
        return NotImplemented


class Eth(Protocol):
    """
    """
    def __init__(self, base: P2p, capability: Capability, offset: int) -> None:
        super().__init__(base, capability, offset)
        self.rckey = base.rckey
        self.status_event = Event()
        self.handlers: list[EthHandler] = []

    def register_handler(self, handler: EthHandler) -> None:
        handler.bind(self)
        self.handlers.append(handler)

    def bind(
        self,
        status_timeout: int,
        network_id: int,
        genesis_hash: bytes,
        hard_fork_hash: bytes,
        next_fork: int
    ) -> None:
        if self.version >= 64:
            self.status = Status(
                self.version,
                network_id,
                opts.NOW_TD,
                opts.NOW_HASH,
                genesis_hash, (hard_fork_hash, next_fork)
            )
            self.hard_fork_hash = hard_fork_hash
            self.next_fork = next_fork
        else:
            self.status = Status(
                self.version,
                network_id,
                opts.NOW_TD,
                opts.NOW_HASH,
                genesis_hash
            )
        self.status_timeout = status_timeout

    async def waiting_for_status(self) -> None:
        with trio.move_on_after(self.status_timeout) as cancel_scope:
            await self.status_event.wait()
        if cancel_scope.cancelled_caught:
            if self.status_event.is_set():
                return
            logger.warn(f"Recieved status message timeout from {self.rckey}")
            await self.base.send_disconnect(DISCONNECT_REASONS.TIMEOUT)

    async def after_hello(self) -> None:
        await self.send_status()
        self.base.peer.peer_loop.start_soon(self.waiting_for_status)

    async def disconnect(self) -> None:
        for handler in self.handlers:
            try:
                await handler.disconnect()
            except Exception:
                logger.error(
                    f"Error on calling disconnect from {self.rckey} "
                    f"to handler.\nDetail: {traceback.format_exc()}"
                )

    async def handle_message(self, code: int, payload: RLP) -> None:
        code = MESSAGE_CODES(code)
        if code not in [
            MESSAGE_CODES.TX, MESSAGE_CODES.NEW_POOLED_TRANSACTION_HASHES
        ]:
            logger.info(f"Received {code} from {self.rckey}.")
        if code == MESSAGE_CODES.STATUS:
            await self.handle_status(payload)
            return
        elif code in [
            MESSAGE_CODES.TX,
            MESSAGE_CODES.BLOCK_HEADERS,
            MESSAGE_CODES.GET_BLOCK_HEADERS,
            MESSAGE_CODES.NEW_BLOCK_HASHES,
            MESSAGE_CODES.GET_BLOCK_BODIES,
            MESSAGE_CODES.BLOCK_BODIES,
            MESSAGE_CODES.NEW_BLOCK
        ]:
            if self.version < 62:
                return
        elif code in [
            MESSAGE_CODES.GET_NODE_DATA,
            MESSAGE_CODES.NODE_DATA,
            MESSAGE_CODES.GET_RECEIPTS,
            MESSAGE_CODES.RECEIPTS,
        ]:
            if self.version < 63:
                return
        elif code in [
            MESSAGE_CODES.NEW_POOLED_TRANSACTION_HASHES,
            MESSAGE_CODES.GET_POOLED_TRANSACTIONS,
            MESSAGE_CODES.POOLED_TRANSACTIONS
        ]:
            if self.version < 65:
                return
        else:
            return
        for handler in self.handlers:
            try:
                await handler.handle_message(code, payload)
            except Exception:
                logger.error(
                    f"Error on calling handle_message from {self.rckey} "
                    f"to handler.\nDetail: {traceback.format_exc()}"
                )

    async def send_status(self) -> None:
        await self.base.send_message(
            MESSAGE_CODES.STATUS.value + self.offset, self.status.to_RLP()
        )
        logger.info(
            f"Send STATUS message to {self.rckey} "
            f"(eth{self.version})."
        )

    async def handle_status(self, payload: RLP) -> None:
        try:
            self.peer_status = Status.from_RLP(payload, self.version >= 64)
        except Exception:
            logger.warn(f"Status message format mismatch from {self.rckey}.")
            await self.base.send_disconnect(
                DISCONNECT_REASONS.SUBPROTOCOL_ERROR
            )
            return
        logger.info(
            f"Recieved STATUS message from {self.rckey} "
            f"(eth{self.peer_status.version})."
        )
        await self.validate_status()

    async def validate_status(self) -> None:
        self.status_event.set()
        if self.status.version != self.peer_status.version:
            logger.warn(
                f"Protocol version mismatch from {self.rckey} "
                f"(value: {self.peer_status.version})."
            )
            await self.base.send_disconnect(
                DISCONNECT_REASONS.SUBPROTOCOL_ERROR
            )
        elif self.status.network_id != self.peer_status.network_id:
            logger.warn(
                f"Network ID mismatch from {self.rckey} "
                f"(value: {self.peer_status.network_id})."
            )
            await self.base.send_disconnect(
                DISCONNECT_REASONS.SUBPROTOCOL_ERROR
            )
        elif self.status.genesis_hash != self.peer_status.genesis_hash:
            logger.warn(
                f"Genesis block mismatch from {self.rckey} "
                f"(value: {self.peer_status.genesis_hash.hex()[:7]})."
            )
            await self.base.send_disconnect(
                DISCONNECT_REASONS.SUBPROTOCOL_ERROR
            )
        elif self.version >= 64 and \
                not self.validate_fork_id(self.peer_status.fork_id):
            logger.warn(
                f"Hard fork mismatch from {self.rckey} "
                f"(value: {self.peer_status.fork_id[0].hex()})."
            )
            await self.base.send_disconnect(
                DISCONNECT_REASONS.SUBPROTOCOL_ERROR
            )
        # elif self.status.td > self.peer_status.td:
        #     logger.warn(
        #         f"Peer {self.rckey} total difficult is less than ours."
        #         f"(value: {self.peer_status.td})."
        #     )
        #     await self.base.send_disconnect(
        #         DISCONNECT_REASONS.SUBPROTOCOL_ERROR
        #     )
        else:
            logger.info(f"Successfully connected to {self.rckey}.")
            for handler in self.handlers:
                try:
                    handler.after_status()
                except Exception:
                    logger.error(
                        f"Error on calling after_status from {self.rckey}"
                        f" to handler.\nDetail: {traceback.format_exc()}"
                    )

    def validate_fork_id(self, fork_id: list[bytes]) -> None:
        """
        Eth 64 Fork ID validation (EIP-2124)
        @param forkId Remote fork ID
        """
        peer_fork_hash = fork_id[0]
        peer_next_fork = fork_id[1]
        if peer_fork_hash == self.hard_fork_hash and \
                self.next_fork >= peer_next_fork:
            logger.info(
                f"{self.rckey} is advertising a future "
                "fork that passed locally."
            )
            return True
        logger.warn(
            f"{self.rckey} is not advertising a future "
            "fork that passed locally."
        )
        return False

    async def send_message(self, code: MESSAGE_CODES, payload: RLP) -> bool:
        logger.info(f"Send {code} to {self.rckey}.")
        return await self.base.send_message(self.offset + code.value, payload)


# Protocol.register(eth62, Eth)
Protocol.register(eth63, Eth)
Protocol.register(eth64, Eth)
Protocol.register(eth65, Eth)
Protocol.register(eth66, Eth)
