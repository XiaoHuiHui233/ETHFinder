#!/usr/bin/env python
# -*- codeing:utf-8 -*-
"""A implementation of controller of eth protocol.
"""

__author__ = "XiaoHuiHui"
__version__ = "1.3"

from typing import Any
import logging
from logging import FileHandler, Formatter, StreamHandler
import random
import time
from multiprocessing.connection import Connection

import trio
import rlp
from eth_hash.auto import keccak

from rlpx.protocols.eth import Eth
from rlpx.protocols.eth import MESSAGE_CODES
from store import block, peer
import config as opts
from .cache import EthCache
from .handler import MyEthHandler

from utils import RLP

logger = logging.getLogger("eth.controller")
fmt = Formatter("%(asctime)s [%(name)s][%(levelname)s] %(message)s")
fh = FileHandler("./logs/eth/controller.log", "w", encoding="utf-8")
sh = StreamHandler()
fh.setFormatter(fmt)
sh.setFormatter(fmt)
fh.setLevel(logging.INFO)
sh.setLevel(logging.INFO)
logger.addHandler(fh)
logger.addHandler(sh)


class EthController:
    """
    """
    def __init__(self) -> None:
        self.cache = EthCache()
        self.handlers: dict[str, MyEthHandler] = {}
        self.last_receipt_block = 0
        self.last_receipt_block_hash = b"\0"
        self.services_connections: dict[str, Connection] = {}
        self.operators: dict[str, dict[str, callable]] = {
            "get": {
                # low-level
                "block_headers": self.get_block_headers,
                "block_bodies": self.get_block_bodies,
                "pooled_transactions": self.get_pooled_transactions,
                "node_data": self.get_node_data,
                "receipts": self.get_receipts,  # high-level
                "block": self.get_block,
                "blocks": self.get_blocks,
                "block_and_receipts": self.get_block_and_receipts,
                "blocks_and_receipts": self.get_blocks_and_receipts,
            }
        }

    def on_eth(self, eth: Eth) -> None:
        eth.bind(
            opts.ETH_STATUS_TIMEOUT,
            opts.NETWORK_ID,
            opts.GENESIS_HASH,
            opts.HARD_FORK_HASH,
            opts.NEXT_FORK
        )
        handler = MyEthHandler(self)
        eth.register_handler(handler)
        self.handlers[handler.rckey] = handler

    async def bind(self) -> None:
        async with trio.open_nursery() as eth_loop:
            self.eth_loop = eth_loop
            eth_loop.start_soon(self.print_loop)
            for name in self.services_connections:
                eth_loop.start_soon(self.recieve_loop, name)

    async def print_loop(self) -> None:
        while True:
            logger.info(
                f"Now {len(self.handlers)} handlers alive. "
                f"Message queue: {self.channel.qsize()}"
            )
            sample = random.sample(
                list(self.handlers.keys()), min(len(self.handlers), 50)
            )
            cache = []
            for rckey in sample:
                if self.handlers[rckey].running:
                    cache.append(rckey)
            peer.write_peers(cache)
            await trio.sleep(opts.PRINT_INTERVAL)

    async def register_services(
        self, name: str, services_connection: Connection
    ) -> None:
        self.services_connections[name] = services_connection

    async def receive_loop(self, name: str) -> None:
        while True:
            try:
                if self.services_connections[name].poll():
                    request = self.services_connections[name].recv()
                    result = await self.handle_request(request)
                    self.services_connections[name].send(result)
                else:
                    trio.sleep(0)
            except EOFError:
                logger.info(f"EOF on service {name}, stopped.")
                break
            except Exception:
                trio.sleep(0)

    async def handle_request(self, request: dict[str, Any]) -> Any:
        rckey = self.choose_one()
        if request["type"] not in self.operators.keys():
            raise ValueError("Invalid type to get from controller!")
        elif request["obj"] not in self.operators[request["type"]].keys():
            raise ValueError(
                f'Invalid obj in type {request["type"]} to get from '
                "controller!"
            )
        self.operators[request["type"]][request["obj"]
                                        ](rckey, **request["data"])

    def choose_one(self, dont_want: str = None) -> str:
        """Randomly choose a rckey of a handler from handler list.
        """
        rckeys = list(self.handlers.keys())
        if dont_want is not None and dont_want in rckeys:
            rckeys.remove(dont_want)
        if not rckeys:
            return None
        return random.choice(rckeys)

    async def raw_get_headers(self,
                              payload: RLP,
                              from_rckey: str = None) -> list[RLP]:
        if len(payload[0]) == 32:
            startblock = payload[0]
        else:
            startblock = int.from_bytes(payload[0], byteorder="big")
        limit = int.from_bytes(payload[1], byteorder="big")
        skip = int.from_bytes(payload[2], byteorder="big")
        reverse = int.from_bytes(payload[3], byteorder="big") != 0
        headers = self.cache.get_headers(startblock, limit, skip, reverse)
        if not headers:
            rckey = self.choose_one(from_rckey)
            if rckey is None:
                return []
            return await self.handlers[rckey].get_headers(
                startblock, limit, skip, reverse
            )
        return headers

    async def raw_get_bodies(self,
                             payload: RLP,
                             from_rckey: str = None) -> list[RLP]:
        blocks = self.cache.get_bodies(payload)
        if not blocks:
            rckey = self.choose_one(from_rckey)
            if rckey is None:
                return []
            return await self.handlers[rckey].get_bodies(payload)
        return blocks

    async def receipts_after_new_block(
        self, rckey: str, block_payload: RLP, new_hash: str
    ) -> None:
        if rckey in self.handlers:
            receipts = await self.handlers[rckey].get_receipts([new_hash])
            for name in self.services_connections:
                self.services_connections[name].send({
                    "type":
                    "handle_new_block_and_receipts",
                    "block_data":
                    block_payload[0],
                    "receipts_data":
                    receipts
                })

    async def handle_new_block_hash(self, rckey: str, payload: RLP) -> None:
        for name in self.services_connections:
            self.services_connections[name].send({
                "type": "handle_new_block_hash", "data": payload
            })
        for block_data in payload:
            hash = block_data[0]
            number = int.from_bytes(block_data[1], "big")
            logger.info(f"received new block hash {number}.")
            headers = await self.handlers[rckey].get_headers(hash, 1, 0, False)
            if not headers:
                logger.warn(f"received empty new headers from {rckey}.")
                return
            bodies = await self.handlers[rckey].get_bodies([hash])
            if not bodies:
                logger.warn(f"received empty new bodies from {rckey}.")
                return
            await self.handle_new_block(rckey, headers[0], bodies[0])
            keys = list(self.handlers.keys())
            samples = random.sample(keys, min(5, len(self.handlers)))
            for key in samples:
                if key == rckey:
                    continue
                if key in self.handlers:
                    await self.handlers[key].send_message(
                        MESSAGE_CODES.NEW_BLOCK_HASHES, payload
                    )

    async def handle_raw_new_block(self, rckey: str, payload: RLP) -> None:
        for name in self.services_connections:
            self.services_connections[name].send({
                "type": "handle_raw_new_block", "data": payload[0]
            })
        new_height = int.from_bytes(payload[0][0][8], "big")
        new_td = int.from_bytes(payload[1], "big")
        new_hash = keccak(rlp.encode(payload[0][0]))
        block_ts = int.from_bytes(payload[0][0][11], "big")
        receive_ts = int(time.time())
        delta_time = receive_ts - block_ts
        logger.info(
            f"received a raw block {new_height}(Timeout: {delta_time}s)."
        )
        if opts.NOW_HEIGHT < new_height:
            opts.NOW_HEIGHT = new_height
            opts.NOW_TD = new_td
            opts.NOW_HASH = new_hash
            block.write_latest_block(
                opts.NOW_HEIGHT, opts.NOW_HASH, opts.NOW_TD
            )
            await self.receipts_after_new_block(rckey, payload, new_hash)
            self.cache.add_cache(new_height, payload[0])
            keys = list(self.handlers.keys())
            samples = random.sample(keys, min(5, len(self.handlers)))
            for key in samples:
                if key == rckey:
                    continue
                if key in self.handlers:
                    await self.handlers[key].send_message(
                        MESSAGE_CODES.NEW_BLOCK, payload
                    )
        elif opts.NOW_HEIGHT == new_height and opts.NOW_HASH != new_hash:
            logger.info(f"Found a block conflict ({new_hash.hex()}).")

    async def handle_new_block(
        self, rckey: str, header: RLP, body: RLP
    ) -> None:
        for name in self.services_connections:
            self.services_connections[name].send({
                "type":
                "handle_new_block", "data": [header, body[0], body[1]]
            })
        new_height = int.from_bytes(header[8], "big")
        new_td = opts.NOW_TD + int.from_bytes(header[7], "big")
        new_hash = keccak(rlp.encode(header))
        block_ts = int.from_bytes(header[11], "big")
        receive_ts = int(time.time())
        delta_time = receive_ts - block_ts
        logger.info(f"received a block {new_height}(Timeout: {delta_time}s).")
        if opts.NOW_HEIGHT < new_height:
            opts.NOW_HEIGHT = new_height
            opts.NOW_TD = new_td
            opts.NOW_HASH = new_hash
            block.write_latest_block(
                opts.NOW_HEIGHT, opts.NOW_HASH, opts.NOW_TD
            )
            await self.receipts_after_new_block(
                rckey, [header, body[0], body[1]], new_hash
            )
            self.cache.add_cache(new_height, [header, body[0], body[1]])
        elif opts.NOW_HEIGHT == new_height and opts.NOW_HASH != new_hash:
            logger.info(f"Found a block conflict ({new_hash.hex()}).")

    async def handle_new_pooled_tx_hash(
        self, rckey: str, payload: RLP
    ) -> None:
        for name in self.services_connections:
            self.services_connections[name].send({
                "type": "handle_new_pooled_transaction_hash", "data": payload
            })

    async def handle_new_tx(self, rckey: str, payload: RLP) -> None:
        # logger.info(f"received a new tx.")
        for name in self.services_connections:
            self.services_connections[name].send({
                "type": "handle_transactions", "data": payload
            })
        keys = list(self.handlers.keys())
        samples = random.sample(keys, min(5, len(self.handlers)))
        for key in samples:
            if key == rckey:
                continue
            if key in self.handlers:
                await self.handlers[key].send_message(
                    MESSAGE_CODES.TX, payload
                )

    async def get_block_headers(
        self, rckey, startblock, limit, skip, reverse, id
    ):
        headers = await self.handlers[rckey].get_headers(
            startblock, limit, skip, reverse
        )
        return {
            "type": "get_block_headers", "id": id, "headers": headers
        }

    async def get_block_bodies(self, rckey, hashes, id):
        bodies = await self.handlers[rckey].get_bodies(hashes)
        return {
            "type": "get_block_bodies", "id": id, "bodies": bodies
        }

    async def get_pooled_transactions(self, rckey):
        pass

    def get_node_data(self, rckey):
        pass

    async def get_receipts(self, rckey, hashes, id):
        receipts = await self.handlers[rckey].get_receipts(hashes)
        return {
            "type": "get_receipts", "id": id, "receipts": receipts
        }

    async def get_block(self, rckey, way, id, blockhash=None, height=None):
        allowed_ways = ["blockhash", "height"]
        if way not in allowed_ways:
            raise ValueError("Invalid way to get_block from controller!")
        startblock = blockhash if way == "blockhash" else height
        headers = await self.handlers[rckey].get_headers(
            startblock, 1, 0, False
        )
        if way == "height" and not headers:
            headers = []
            bodies = []
        else:
            hash = blockhash if way == "blockhash" else keccak(
                rlp.encode(headers[0])
            )
            bodies = await self.handlers[rckey].get_bodies([hash])
        return {
            "type": f"get_block_by_{way}",
            "id": id,
            "headers": headers,
            "bodies": bodies
        }

    async def get_blocks(self, rckey, way, left, right, id):
        allowed_ways = ["range"]
        if way not in allowed_ways:
            raise ValueError("Invalid way to get_block from controller!")
        headers = await self.handlers[rckey].get_headers(
            left, right - left + 1, 1, False
        )
        hashes = []
        for header in headers:
            hashes.append(keccak(rlp.encode(header)))
        bodies = await self.handlers[rckey].get_bodies(hashes)
        return {
            "type": "get_blocks_in_range",
            "id": id,
            "headers": headers,
            "bodies": bodies
        }

    async def get_block_and_receipts(
        self, rckey, way, id, blockhash=None, height=None
    ):
        allowed_ways = ["blockhash", "height"]
        if way not in allowed_ways:
            raise ValueError("Invalid way to get_block from controller!")
        startblock = blockhash if way == "blockhash" else height
        headers = await self.handlers[rckey].get_headers(
            startblock, 1, 0, False
        )
        if way == "height" and not headers:
            headers = []
            bodies = []
            receipts = []
        else:
            hash = blockhash if way == "blockhash" else keccak(
                rlp.encode(headers[0])
            )
            bodies = await self.handlers[rckey].get_bodies([hash])
            receipts = await self.handlers[rckey].get_receipts([hash])
        return {
            "type": f"get_block_and_receipts_by_{way}",
            "id": id,
            "headers": headers,
            "bodies": bodies,
            "receipts": receipts
        }

    async def get_blocks_and_receipts(self, rckey, way, left, right, id):
        allowed_ways = ["range"]
        if way not in allowed_ways:
            raise ValueError("Invalid way to get_block from controller!")
        headers = await self.handlers[rckey].get_headers(
            left, right - left + 1, 1, False
        )
        hashes = []
        for header in headers:
            hashes.append(keccak(rlp.encode(header)))
        bodies = await self.handlers[rckey].get_bodies(hashes)
        receipts = await self.handlers[rckey].get_receipts(hashes)
        return {
            "type": "get_blocks_and_receipts_in_range",
            "id": id,
            "headers": headers,
            "bodies": bodies,
            "receipts": receipts
        }
