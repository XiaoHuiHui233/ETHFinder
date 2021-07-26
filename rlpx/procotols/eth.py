from enum import Enum
from typing import Coroutine, TypeVar, List, Tuple
import logging
from logging import FileHandler, Formatter

import trio
from trio import Nursery

from rlpx.procotols.procotol import Capability, Procotol
from rlpx.procotols.p2p import DISCONNECT_REASONS, P2pProcotol
import config as opts


RLP = TypeVar("RLP", List[List[bytes]], List[bytes], bytes)

logger = logging.getLogger("eth")
fh = FileHandler('./logs/eth.log')
fmt = Formatter("%(asctime)s [%(name)s][%(levelname)s] %(message)s")
fh.setFormatter(fmt)
fh.setLevel(logging.INFO)
logger.addHandler(fh)

eth62 = Capability("eth", 62, 8)
eth63 = Capability("eth", 63, 17)
eth64 = Capability("eth", 64, 29)
eth65 = Capability("eth", 65, 29)


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

    def __init__(self, version: int, network_id: int, td: int,
            best_hash: bytes, genesis_hash: bytes,
            fork_id: Tuple[bytes, int] = None) -> None:
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
                payload[4],
                (
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
                self.genesis_hash,
                [
                    self.fork_id[0],
                    self.fork_id[1]
                ]
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


class EthProcotol(Procotol):
    """
    """

    def __init__(self, base: P2pProcotol, capability: Capability,
            offset: int, peer_loop: Nursery) -> None:
        super().__init__(base, capability, offset, peer_loop)
        self.rckey = base.rckey
        self.status: Status = None
        self.peer_status: Status = None
        self.recieved_status = False

    async def bind(self) -> Coroutine:
        self.peer_loop.start_soon(self.send_status)
        await trio.sleep(5)
        if self.recieved_status:
            return
        else:
            logger.warning(
               f"Recieved status message timeout from {self.rckey}"
            )
            self.peer_loop.start_soon(
                self.base.send_disconnect,
                DISCONNECT_REASONS.TIMEOUT
            )

    async def handle_message(self, code: int, payload: RLP) -> Coroutine:
        code = MESSAGE_CODES(code)
        logger.info(
            f"Received {code} from {self.rckey}."
        )
        if code == MESSAGE_CODES.STATUS:
            await self.handle_status(payload)
            return
        elif code in [MESSAGE_CODES.TX,
                    MESSAGE_CODES.BLOCK_HEADERS,
                    MESSAGE_CODES.GET_BLOCK_HEADERS,
                    MESSAGE_CODES.NEW_BLOCK_HASHES,
                    MESSAGE_CODES.GET_BLOCK_BODIES,
                    MESSAGE_CODES.BLOCK_BODIES,
                    MESSAGE_CODES.NEW_BLOCK]:
            if self.version < eth62.version:
                return
        elif code in [MESSAGE_CODES.GET_NODE_DATA,
                    MESSAGE_CODES.NODE_DATA,
                    MESSAGE_CODES.GET_RECEIPTS,
                    MESSAGE_CODES.RECEIPTS,
                    ]:
            if self.version < eth63.version:
                return
        elif code in [MESSAGE_CODES.NEW_POOLED_TRANSACTION_HASHES,
                    MESSAGE_CODES.GET_POOLED_TRANSACTIONS,
                    MESSAGE_CODES.POOLED_TRANSACTIONS]:
            if self.version < eth65.version:
                return
        else:
            return
        from controller import eth_controller
        await eth_controller.handle_message(self, code, payload)
    
    async def send_status(self) -> Coroutine:
        if self.status is not None:
            return
        network_id = 1
        if self.version >= 64:
            self.status = Status(
                self.version,
                network_id,
                opts.NOW_TD,
                opts.NOW_HASH,
                bytes.fromhex(opts.GENESIS_HASH),
                (bytes.fromhex(opts.HARD_FORK_HASH), opts.NEXT_FORK)
            )
        else:
            self.status = Status(
                self.version,
                network_id,
                opts.NOW_TD,
                opts.NOW_HASH,
                bytes.fromhex(opts.GENESIS_HASH)
            )
        logger.info(
            f"Send STATUS message to {self.rckey} "
            f"(eth{self.version})."
        )
        self.peer_loop.start_soon(
            self.base.send_message,
            MESSAGE_CODES.STATUS.value + self.offset,
            self.status.to_RLP()
        )
        await self.validate_status()
    
    async def handle_status(self, payload: RLP) -> None:
        if self.peer_status is not None:
            logger.warning(
                f"Uncontrolled status message from {self.rckey}."
            )
        try:
            self.peer_status = Status.from_RLP(payload, self.version >= 64)
        except IndexError as err:
            logger.warning(
                f"Status message format mismatch from {self.rckey}."
            )
            await self.base.send_disconnect(
                DISCONNECT_REASONS.SUBPROTOCOL_ERROR
            )
            return
        logger.info(
            f"Recieved STATUS message from {self.rckey} "
            f"(eth{self.peer_status.version})."
        )
        self.recieved_status = True
        await self.validate_status()

    async def validate_status(self) -> None:
        if self.status is None or self.peer_status is None:
            return
        elif self.status.version != self.peer_status.version:
            logger.warning(
                f"Protocol version mismatch from {self.rckey} "
                f"(value: {self.peer_status.version})."
            )
            self.peer_loop.start_soon(
                self.base.send_disconnect,
                DISCONNECT_REASONS.SUBPROTOCOL_ERROR
            )
        elif self.status.network_id != self.peer_status.network_id:
            logger.warning(
                f"Network ID mismatch from {self.rckey} "
                f"(value: {self.peer_status.network_id})."
            )
            self.peer_loop.start_soon(
                self.base.send_disconnect,
                DISCONNECT_REASONS.SUBPROTOCOL_ERROR
            )
        elif self.status.genesis_hash != self.peer_status.genesis_hash:
            logger.warning(
                f"Genesis block mismatch from {self.rckey} "
                f"(value: {self.peer_status.genesis_hash.hex()[:7]})."
            )
            self.peer_loop.start_soon(
                self.base.send_disconnect,
                DISCONNECT_REASONS.SUBPROTOCOL_ERROR
            )
        elif self.version >= 64 \
            and not self.validate_fork_id(self.peer_status.fork_id):
            logger.warning(
                f"Hard fork mismatch from {self.rckey} "
                f"(value: {self.peer_status.fork_id[0].hex()})."
            )
            self.peer_loop.start_soon(
                self.base.send_disconnect,
                DISCONNECT_REASONS.SUBPROTOCOL_ERROR
            )
        # elif self.status.td > self.peer_status.td:
        #     logger.warning(
        #         f"Peer {self.rckey} total difficult is less than ours."
        #         f"(value: {self.peer_status.td})."
        #     )
        #     self.peer_loop.start_soon(
        #         self.base.send_disconnect,
        #         DISCONNECT_REASONS.SUBPROTOCOL_ERROR
        #     )
        else:
            from controller import eth_controller
            eth_controller.append(self)
    
    def validate_fork_id(self, fork_id: List[bytes]) -> None:
        """
        Eth 64 Fork ID validation (EIP-2124)
        @param forkId Remote fork ID
        """
        peer_fork_hash = fork_id[0]
        peer_next_fork = fork_id[1]
        if peer_fork_hash == bytes.fromhex(opts.HARD_FORK_HASH) \
            and opts.NEXT_FORK >= peer_next_fork:
            logger.info(
                f"{self.rckey} is advertising a future "
                "fork that passed locally."
            )
            return True
        return False

    async def send_message(self, code: MESSAGE_CODES, payload: RLP):
        self.peer_loop.start_soon(
            self.base.send_message,
            self.offset + code.value,
            payload
        )



Procotol.register(eth62, EthProcotol)
Procotol.register(eth63, EthProcotol)
Procotol.register(eth64, EthProcotol)
Procotol.register(eth65, EthProcotol)