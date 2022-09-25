#!/usr/bin/env python
# -*- codeing:utf-8 -*-
"""A implementation of controller of eth protocol.
"""

__author__ = "XiaoHuiHui"

import asyncio
import logging
import random
import time
import typing
from asyncio import CancelledError
from logging import FileHandler, Formatter, StreamHandler

import rlp
from eth_hash.auto import keccak
from eth.cache import EthCache
from rlpx.protocols.eth import CODES

from .ipc import IPCClient

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

Rlpdecoded = list[bytes | list[bytes] | list[bytes | list[bytes]]]

PRINT_INTERVAL = 10


class EthMain:
    """
    """
    def __init__(self, ipc_client_path: str, cache_limit: int) -> None:
        self.ipc_client = IPCClient(ipc_client_path)
        self.running = False
        self.peers: dict[str, int] = {}
        self.cache = EthCache(cache_limit)
        self.mempool = Mempool()
        self.blooms: dict[str, bytes] = {}

    async def bind(self) -> None:
        await self.ipc_client.bind()
        self.run_task = asyncio.create_task(self.run(), name="run")

    async def run(self) -> None:
        self.running = True
        while True:
            try:
                await asyncio.sleep(PRINT_INTERVAL)
            except CancelledError:
                return
            logger.info(f"Now {len(self.peers)} handlers alive.")

    async def close(self) -> None:
        if self.running:
            self.run_task.cancel()
            await asyncio.sleep(0)
        else:
            logger.warning("Main is not running! Ignore to close.")

    async def on_ready(self, addr: str, version: int) -> None:
        if addr in self.peers:
            logger.warning(f"{addr} is in peers!")
            return
        self.peers[addr] = version

    async def on_pop(self, addr: str) -> None:
        self.peers.pop(addr)

    async def on_message(
        self, addr: str, code: int, data: Rlpdecoded
    ) -> None:
        code_e = CODES(code)
        match(code_e):
            case CODES.STATUS:
                return
            case CODES.NEW_BLOCK_HASHES:
                await self.new_block_hashes(data)
            case CODES.TX:
                await self.new_tx(data)
            case CODES.NEW_BLOCK:
                await self.new_block(addr, data)
            case CODES.NEW_POOLED_TRANSACTION_HASHES:
                await self.new_pooled_tx_hash(addr, data)
            case CODES.GET_BLOCK_HEADERS:
                logger.info(f"receive GET_BLOCK_HEADERS from {self.rckey}.")
                if self.peers[addr] >= 66:
                    request_id = data[0]
                    headers = await self.raw_get_headers(
                        addr, data[1]
                    )
                    await self.send_message(
                        CODES.BLOCK_HEADERS, [request_id, headers]
                    )
                else:
                    headers = await self.raw_get_headers(
                        addr, data
                    )
                await self.send_message(CODES.BLOCK_HEADERS, headers)
            case CODES.GET_BLOCK_BODIES:
                logger.info(f"receive GET_BLOCK_BODIES from {self.rckey}.")
                if self.peers[addr] >= 66:
                    request_id = data[0]
                    bodies = await self.raw_get_bodies(
                        addr, data[1]
                    )
                    await self.send_message(
                        CODES.BLOCK_BODIES, [request_id, bodies]
                    )
                else:
                    bodies = await self.raw_get_bodies(self.rckey, data)
                    await self.send_message(CODES.BLOCK_BODIES, bodies)
            case CODES.GET_RECEIPTS | \
                    CODES.GET_NODE_DATA | \
                    CODES.GET_POOLED_TRANSACTIONS:
                logger.info(f"receive {code} from {self.rckey}.")
                if self.peers[addr] >= 66:
                    request_id = data[0]
                    await self.send_message(CODE_PAIR[code], [request_id, []])
                else:
                    await self.send_message(CODE_PAIR[code], [])
            case CODES.BLOCK_HEADERS | \
                    CODES.BLOCK_BODIES | \
                    CODES.NODE_DATA | \
                    CODES.POOLED_TRANSACTIONS | \
                    CODES.RECEIPTS:
                self.handle_default(code, data)

    async def new_block_hashes(self, data: Rlpdecoded) -> None:
        for ld in data:
            hash = typing.cast(bytes, ld[0])
            number = int.from_bytes(typing.cast(bytes, ld[1]), "big")
            if number 

    async def new_tx(self, data: Rlpdecoded) -> None:

        self.mempool.add()


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
