#!/usr/bin/env python
# -*- codeing:utf-8 -*-
"""A implemention of RLPx protocol.
"""

__author__ = "XiaoHuiHui"

import asyncio
import logging
import typing
from asyncio import CancelledError
from enum import Enum
from typing import Any, NamedTuple, Optional

import ujson

from ..datatypes import DC_REASONS, Addr, Capability
from ..ipc import IPCServer
from ..peer.p2p import P2pPeer, Protocol

logger = logging.getLogger("rlpx.protocols.eth")

TIMEOUT = 5

Rlpable = list[int | bytes | str | list[Any]]
Rlpdecoded = list[bytes | list[bytes] | list[bytes | list[bytes]]]


class CODES(Enum):
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


class Status(NamedTuple):
    version: int
    network_id: int
    td: int
    best_hash: bytes
    genesis_hash: bytes
    fork_id: Optional[tuple[bytes, int]]

    @classmethod
    def from_RLP(cls, payload: Rlpdecoded, is_eth64: bool) -> "Status":
        if is_eth64:
            return cls(
                int.from_bytes(typing.cast(bytes, payload[0]), "big"),
                int.from_bytes(typing.cast(bytes, payload[1]), "big"),
                int.from_bytes(typing.cast(bytes, payload[2]), "big"),
                typing.cast(bytes, payload[3]),
                typing.cast(bytes, payload[4]),
                (
                    typing.cast(bytes, payload[5][0]),
                    int.from_bytes(typing.cast(bytes, payload[5][1]), "big")
                )
            )
        else:
            return cls(
                int.from_bytes(
                    typing.cast(bytes, payload[0]), byteorder="big"
                ),
                int.from_bytes(
                    typing.cast(bytes, payload[1]), byteorder="big"
                ),
                int.from_bytes(
                    typing.cast(bytes, payload[2]), byteorder="big"
                ),
                typing.cast(bytes, payload[3]),
                typing.cast(bytes, payload[4]),
                None
            )

    def to_RLP(self) -> Rlpable:
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


class EthController:
    def __init__(
        self,
        network_id: int,
        genesis_hash: bytes,
        hard_fork_hash: bytes,
        next_fork: int,
        cache_file: str,
        ipc_path: Optional[str] = None
    ) -> None:
        self.network_id = network_id
        self.genesis_hash = genesis_hash
        self.hard_fork_hash = hard_fork_hash
        self.next_fork = next_fork
        self.cache_file = cache_file
        self.ipc_path = ipc_path
        self.read_cache()
        self.eths: dict[Addr, Eth] = {}

    async def bind(self) -> None:
        if self.ipc_path is not None:
            self.ipc = IPCServer(self.ipc_path)
            await self.ipc.bind()

    async def close(self) -> None:
        if self.ipc_path is not None:
            await self.ipc.close()

    def read_cache(self) -> None:
        try:
            with open(self.cache_file, "r") as rf:
                data = "\n".join(rf.readlines())
                d = ujson.loads(data)
                self.td = int(d["td"])
                self.hash = bytes.fromhex(d["hash"])
                self.height = d["height"]
        except Exception:
            logger.warning(
                "[Controller] Failed to read cache, try default values."
            )
            self.td = 57839744486336011135818
            self.hash = bytes.fromhex(
                "ee8acc5348aa98500bbda72aa0f4209a"
                "8b17ba9b637845ebdd3a034cda2dd4ef"
            )
            self.height = 15463202

    def write_cache(self) -> None:
        try:
            with open(self.cache_file, "w") as wf:
                data = {
                    "td": str(self.td),
                    "hash": self.hash.hex(),
                    "height": self.height
                }
                wf.write(ujson.dumps(data, indent=4)+"\n")
        except Exception:
            logger.warning(
                "[Controller] Failed to write cache. Ignore for next try."
            )

    def new_eth(
        self, peer: P2pPeer, cap: Capability, offset: int
    ) -> "Eth":
        addr = peer.addr
        assert addr not in self.eths
        self.eths[addr] = Eth(peer, cap, offset, self)
        return self.eths[addr]

    def after_status(self, addr: Addr, version: int) -> None:
        asyncio.create_task(
            self.ipc.boardcast_ready(addr, version), name="bc_ready"
        )

    def pop(self, addr: Addr) -> None:
        asyncio.create_task(
            self.ipc.boardcast_pop(addr), name="bc_pop"
        )
        self.eths.pop(addr)

    async def on_message(
        self, addr: Addr, code: CODES, data: Rlpdecoded
    ) -> None:
        logger.info(f"[Controller] Received {code} from {addr}")
        await self.ipc.boardcast_msg(addr, code.value, data)


class Eth(Protocol):
    """
    """
    def __init__(
        self,
        peer: P2pPeer,
        cap: Capability,
        offset: int,
        controller: EthController,
    ) -> None:
        super().__init__(peer, cap, offset)
        self.controller = controller
        if self.cap.version >= 64:
            self.status = Status(
                self.cap.version,
                controller.network_id,
                controller.td,
                controller.hash,
                controller.genesis_hash,
                (controller.hard_fork_hash, controller.next_fork)
            )
            self.hard_fork_hash = controller.hard_fork_hash
            self.next_fork = controller.next_fork
        else:
            self.status = Status(
                self.cap.version,
                controller.network_id,
                controller.td,
                controller.hash,
                controller.genesis_hash,
                None
            )
        self.hear_status = False

    async def after_hello(self) -> None:
        await self.send_status()
        self.status_timeout_task = asyncio.create_task(
            self.waiting_for_status(), name=f"wait_status_{self.peer.addr}"
        )

    async def waiting_for_status(self) -> None:
        try:
            await asyncio.sleep(TIMEOUT)
        except CancelledError:
            return
        if not self.hear_status:
            logger.warning(
                f"[{self.peer.addr}] Received status message timeout"
            )
            await self.peer.disconnect(DC_REASONS.SUBPROTOCOL_ERROR)

    async def after_status(self) -> None:
        self.controller.after_status(self.peer.addr, self.cap.version)

    async def received_message(self, code: int, data: Rlpdecoded) -> None:
        logger.info(f"[{self.peer.addr}] Received {code}.")
        code_e = CODES(code)
        if code_e == CODES.STATUS:
            await self.received_status(data)
            return
        if not self.hear_status:
            logger.error(
                f"[{self.peer.addr}] Except STATUS but else received."
            )
            await self.peer.disconnect(DC_REASONS.SUBPROTOCOL_ERROR)
            return
        match code_e:
            case CODES.TX | \
                    CODES.BLOCK_HEADERS | \
                    CODES.GET_BLOCK_HEADERS | \
                    CODES.NEW_BLOCK_HASHES | \
                    CODES.GET_BLOCK_BODIES | \
                    CODES.BLOCK_BODIES | \
                    CODES.NEW_BLOCK:
                assert self.cap.version >= 62
            case CODES.GET_NODE_DATA | CODES.NODE_DATA:
                assert self.cap.version >= 63 and self.cap.version < 67
            case CODES.GET_RECEIPTS | CODES.RECEIPTS:
                assert self.cap.version >= 63
            case CODES.NEW_POOLED_TRANSACTION_HASHES | \
                    CODES.GET_POOLED_TRANSACTIONS | \
                    CODES.POOLED_TRANSACTIONS:
                assert self.cap.version >= 64
        await self.controller.on_message(self.peer.addr, code_e, data)

    async def send_status(self) -> None:
        await self.peer.send_message(
            CODES.STATUS.value + self.offset, self.status.to_RLP()
        )
        logger.info(
            f"[{self.peer.addr}] Send STATUS message (eth{self.cap.version})."
        )

    async def received_status(self, data: Rlpdecoded) -> None:
        self.hear_status = True
        self.status_timeout_task.cancel()
        try:
            self.peer_status = Status.from_RLP(data, self.cap.version >= 64)
        except Exception:
            logger.warning(
                f"[{self.peer.addr}] Status message format mismatch."
            )
            await self.peer.disconnect(DC_REASONS.SUBPROTOCOL_ERROR)
            return
        logger.info(
            f"[{self.peer.addr}] Received STATUS message "
            f"(eth{self.peer_status.version})."
        )
        if self.status.version != self.peer_status.version:
            logger.warning(
                f"[{self.peer.addr}] Protocol version mismatch from "
                f"(value: {self.peer_status.version})."
            )
            await self.peer.disconnect(DC_REASONS.SUBPROTOCOL_ERROR)
        elif self.status.network_id != self.peer_status.network_id:
            logger.warning(
                f"[{self.peer.addr}] Network ID mismatch "
                f"(value: {self.peer_status.network_id})."
            )
            await self.peer.disconnect(DC_REASONS.SUBPROTOCOL_ERROR)
        elif self.status.genesis_hash != self.peer_status.genesis_hash:
            logger.warning(
                f"[{self.peer.addr}] Genesis block mismatch "
                f"(value: {self.peer_status.genesis_hash.hex()[:7]})."
            )
            await self.peer.disconnect(DC_REASONS.SUBPROTOCOL_ERROR)
        elif self.cap.version >= 64:
            assert self.peer_status.fork_id is not None
            if not self.validate_fork_id(self.peer_status.fork_id):
                logger.warning(
                    f"[{self.peer.addr}] Hard fork mismatch "
                    f"(value: {self.peer_status.fork_id[0].hex()})."
                )
                await self.peer.disconnect(DC_REASONS.SUBPROTOCOL_ERROR)
        else:
            logger.info(f"[{self.peer.addr}] Successfully connected eth.")
            await self.after_status()

    def validate_fork_id(self, fork_id: tuple[bytes, int]) -> bool:
        """
        Eth 64 Fork ID validation (EIP-2124)
        @param forkId Remote fork ID
        """
        peer_fork_hash = fork_id[0]
        peer_next_fork = fork_id[1]
        if peer_fork_hash == self.hard_fork_hash and \
                peer_next_fork < self.controller.height:
            logger.info(
                f"[{self.peer.addr}] is advertising a future "
                "fork that passed locally."
            )
            return True
        logger.warning(
            f"[{self.peer.addr}] is not advertising a future "
            "fork that passed locally."
        )
        return False

    def exit(self) -> None:
        self.controller.pop(self.peer.addr)
