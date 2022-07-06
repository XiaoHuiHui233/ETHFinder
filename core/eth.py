#!/usr/bin/env python
# -*- codeing:utf-8 -*-
"""A implementation of core controller of eth protocol.
"""

__author__ = "XiaoHuiHui"
__version__ = "1.5"

from typing import Union
import logging
from logging import FileHandler, Formatter, StreamHandler
from collections import OrderedDict
import random
import uuid
import time
from multiprocessing import Queue

import trio
import rlp
from eth_hash.auto import keccak
from lru import LRU

from rlpx import Eth, EthHandler
from rlpx.protocols.eth import MESSAGE_CODES
from utils import Promise
from pyuniswap import simulation
import store
import config as opts

logger = logging.getLogger("core.eth")
fmt = Formatter("%(asctime)s [%(name)s][%(levelname)s] %(message)s")
fh = FileHandler("./logs/core/eth.log", "w", encoding="utf-8")
sh = StreamHandler()
fh.setFormatter(fmt)
sh.setFormatter(fmt)
fh.setLevel(logging.INFO)
sh.setLevel(logging.INFO)
logger.addHandler(fh)
logger.addHandler(sh)

RLP = Union[list[list[list[bytes]]], list[list[bytes]], list[bytes], bytes]

CODE_PAIR = {
    MESSAGE_CODES.BLOCK_HEADERS: MESSAGE_CODES.GET_BLOCK_HEADERS,
    MESSAGE_CODES.BLOCK_BODIES: MESSAGE_CODES.GET_BLOCK_BODIES,
    MESSAGE_CODES.RECEIPTS: MESSAGE_CODES.GET_RECEIPTS,
    MESSAGE_CODES.NODE_DATA: MESSAGE_CODES.GET_NODE_DATA,
    MESSAGE_CODES.POOLED_TRANSACTIONS: MESSAGE_CODES.GET_POOLED_TRANSACTIONS
}

UNISWAP_V3_ADDRESS = bytes.fromhex("8ad599c3a0ff1de082011efddc58f1908eb6e6d8")
UNISWAP_V3_TOPIC = bytes.fromhex(
    "c42079f94a6350d7e6235f29174924f928cc2ac818eb64fed8004e115fbcca67"
)


class MyEthHandler(EthHandler):
    """
    """
    def __init__(self, core: "EthCore") -> None:
        self.core = core
        self.running = False

    def after_status(self) -> None:
        self.running = True
        if self.version >= 66:
            self.promises: dict[int, Promise[RLP]] = LRU(100)
        else:
            self.promises: dict[MESSAGE_CODES, Promise[RLP]] = LRU(100)

    async def send_get_default(self, code: MESSAGE_CODES,
                               payload: RLP) -> Promise[RLP]:
        if not self.running:
            logger.warn(
                f"Failed to send {CODE_PAIR[code]} to {self.rckey}"
                " because stopped."
            )
            return None
        promise: Promise[RLP] = Promise()
        if self.version >= 66:
            request_id = uuid.uuid1().int >> 64
            flag = await self.send_message(
                CODE_PAIR[code], [request_id, payload]
            )
        else:
            flag = await self.send_message(CODE_PAIR[code], payload)
        if flag:
            logger.info(f"Send {CODE_PAIR[code]} to {self.rckey}.")
            if self.version >= 66:
                self.promises[request_id] = promise
            else:
                self.promises[code] = promise
            return promise
        else:
            logger.warn(f"Failed to send {CODE_PAIR[code]} to {self.rckey}.")
            return None

    def handle_default(self, code: MESSAGE_CODES, payload: RLP) -> None:
        logger.info(f"receive {code} from {self.rckey}.")
        if self.version >= 66:
            id = int.from_bytes(payload[0], "big", signed=False)
            if id in self.promises:
                self.promises[id].set(payload[1])
            else:
                logger.warn(
                    f"receive {code} from {self.rckey} but no promise."
                )
        else:
            if code in self.promises:
                self.promises[code].set(payload)
            else:
                logger.warn(
                    f"receive {code} from {self.rckey} but no promise."
                )

    async def send_message(self, code: MESSAGE_CODES, data: RLP) -> bool:
        return await self.eth.send_message(code, data)

    async def handle_message(self, code: MESSAGE_CODES, data: RLP) -> None:
        # logger.info(
        #     f"{self.rckey}(version: {self.version}) received {code}."
        # )
        if code == MESSAGE_CODES.TX:
            await self.core.handle_new_tx(self.rckey, data)
        elif code == MESSAGE_CODES.NEW_BLOCK_HASHES:
            await self.core.handle_new_block_hash(self.rckey, data)
        elif code == MESSAGE_CODES.NEW_BLOCK:
            await self.core.handle_new_block(self.rckey, data, False)
        elif code == MESSAGE_CODES.NEW_POOLED_TRANSACTION_HASHES:
            pass
        elif code == MESSAGE_CODES.GET_BLOCK_HEADERS:
            logger.info(f"receive GET_BLOCK_HEADERS from {self.rckey}.")
            if self.version >= 66:
                request_id = data[0]
                headers = await self.core.get_headers(self.rckey, data[1])
                await self.send_message(
                    MESSAGE_CODES.BLOCK_HEADERS, [request_id, headers]
                )
            else:
                headers = await self.core.get_headers(self.rckey, data)
                await self.send_message(MESSAGE_CODES.BLOCK_HEADERS, headers)
        elif code == MESSAGE_CODES.GET_BLOCK_BODIES:
            logger.info(f"receive GET_BLOCK_BODIES from {self.rckey}.")
            if self.version >= 66:
                request_id = data[0]
                bodies = await self.core.get_bodies(self.rckey, data[1])
                await self.send_message(
                    MESSAGE_CODES.BLOCK_BODIES, [request_id, bodies]
                )
            else:
                bodies = await self.core.get_bodies(self.rckey, data)
                await self.send_message(MESSAGE_CODES.BLOCK_BODIES, bodies)
        elif code == [
            MESSAGE_CODES.GET_RECEIPTS,
            MESSAGE_CODES.GET_NODE_DATA,
            MESSAGE_CODES.GET_POOLED_TRANSACTIONS
        ]:
            pass
        elif code in [
            MESSAGE_CODES.BLOCK_HEADERS,
            MESSAGE_CODES.BLOCK_BODIES,
            MESSAGE_CODES.NODE_DATA,
            MESSAGE_CODES.POOLED_TRANSACTIONS,
            MESSAGE_CODES.RECEIPTS
        ]:
            self.handle_default(code, data)

    async def disconnect(self) -> None:
        self.running = False
        if self.rckey in self.core.handlers:
            self.core.handlers.pop(self.rckey)


class EthCore:
    def __init__(self, channel: Queue) -> None:
        self.channel = channel
        self.handlers: dict[str, MyEthHandler] = {}
        self.hash_to_height: dict[bytes, int] = {}
        self.block_header_cache: dict[int, RLP] = OrderedDict()
        self.block_body_cache: dict[int, RLP] = OrderedDict()
        self.last_reciept_block = 0
        self.last_reciept_block_hash = b"\0"

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
            store.peer.write_peers(cache)
            await trio.sleep(opts.PRINT_INTERVAL)

    def choose_one(self, rckey: str) -> str:
        rckeys = list(self.handlers.keys())
        if rckey in rckeys:
            rckeys.remove(rckey)
        if len(rckeys) == 0:
            return None
        return random.choice(rckeys)

    def add_header_cache(self, height: int, cache: RLP) -> None:
        self.block_header_cache[height] = cache
        self.hash_to_height[cache[13]] = height
        while (len(self.block_header_cache) > 100):
            self.block_header_cache.popitem(False)

    def add_body_cache(self, height: int, cache: RLP) -> None:
        self.block_body_cache[height] = cache
        while (len(self.block_body_cache) > 100):
            self.block_body_cache.popitem(False)

    async def send_get_headers(self, rckey: str, payload: RLP) -> list[RLP]:
        promise = await self.handlers[rckey].send_get_default(
            MESSAGE_CODES.BLOCK_HEADERS, payload
        )
        if promise is None:
            return []
        with trio.move_on_after(opts.MSG_TIMEOUT) as cancel_scope:
            await promise.wait()
        if cancel_scope.cancelled_caught and not promise.is_set():
            logger.warn(f"Waiting for headers timeout from {rckey}.")
            return []
        headers = promise.get_result()
        for header in headers:
            self.add_header_cache(int.from_bytes(header[8], "big"), header)
        return headers

    async def get_headers(self, rckey: str, payload: RLP) -> list[RLP]:
        if len(payload[0]) == 32:
            if payload[0] in self.hash_to_height:
                block_height = self.hash_to_height[payload[0]]
            else:
                block_height = -1
        else:
            block_height = int.from_bytes(payload[0], byteorder="big")
        limit = int.from_bytes(payload[1], byteorder="big")
        skip = int.from_bytes(payload[2], byteorder="big")
        reverse = int.from_bytes(payload[3], byteorder="big")
        headers = []
        while limit > 0 and block_height != -1:
            if block_height in self.block_header_cache:
                headers.append(self.block_header_cache[block_height])
            if reverse == 0:
                block_height += skip
            else:
                block_height -= skip
            if block_height > opts.NOW_HEIGHT:
                break
            limit -= 1
        if len(headers) == 0:
            # reciept = self.choose_one(rckey)
            # if reciept is None:
            return []
        # return await self.send_get_headers(reciept, payload)
        return headers

    async def send_get_bodies(self, rckey: str, payload: RLP) -> list[RLP]:
        promise = await self.handlers[rckey].send_get_default(
            MESSAGE_CODES.BLOCK_BODIES, payload
        )
        if promise is None:
            return []
        with trio.move_on_after(opts.MSG_TIMEOUT) as cancel_scope:
            await promise.wait()
        if cancel_scope.cancelled_caught and not promise.is_set():
            logger.warn(f"Waiting for bodies timeout from {rckey}.")
            return []
        bodies = promise.get_result()
        for hash, body in zip(payload, bodies):
            self.add_body_cache(hash, body)
        return bodies

    async def get_bodies(self, rckey: str, payload: RLP) -> list[RLP]:
        blocks = []
        for hash in payload:
            if hash in self.hash_to_height:
                block_height = self.hash_to_height[hash]
                if block_height in self.block_body_cache:
                    blocks.append(self.block_body_cache[block_height])
        if len(blocks) == 0:
            # reciept = self.choose_one(rckey)
            # if reciept is None:
            return []
        # return await self.send_get_bodies(reciept, payload)
        return blocks

    async def handle_new_block_hash(self, rckey: str, payload: RLP) -> None:
        for block in payload:
            hash = block[0]
            number = int.from_bytes(block[1], "big")
            logger.info(f"received new block hash {number}.")
            headers = await self.send_get_headers(rckey, [hash, 1, 0, False])
            if len(headers) == 0:
                logger.warn(f"received empty new headers from {rckey}.")
                return
            bodies = await self.send_get_bodies(rckey, [hash])
            if len(bodies) == 0:
                logger.warn(f"received empty new bodies from {rckey}.")
                return
            await self.handle_new_block(
                rckey,
                [[headers[0], bodies[0][0], bodies[0][1]],
                 int.to_bytes(
                     opts.NOW_TD + int.from_bytes(headers[0][7], "big"),
                     32,
                     "big"
                 )],
                True
            )
            keys = list(self.handlers.keys())
            samples = random.sample(keys, min(5, len(self.handlers)))
            for key in samples:
                if key == rckey:
                    continue
                if key in self.handlers:
                    await self.handlers[key].send_message(
                        MESSAGE_CODES.NEW_BLOCK_HASHES, payload
                    )

    async def waiting_for_receipts(
        self,
        rckey: str,
        block_ts: int,
        receive_ts: int,
        height: int,
        hash: bytes
    ) -> None:
        if height <= self.last_reciept_block:
            return
        if rckey not in self.handlers:
            return
        promise = await self.handlers[rckey].send_get_default(
            MESSAGE_CODES.RECEIPTS, [hash]
        )
        if promise is None:
            return
        with trio.move_on_after(opts.MSG_TIMEOUT) as cancel_scope:
            await promise.wait()
        if height <= self.last_reciept_block:
            return
        if cancel_scope.cancelled_caught and not promise.is_set():
            logger.warn(f"Waiting for receipts timeout from {rckey}.")
            return
        result = promise.get_result()
        if len(result) == 0:
            logger.warn(f"received empty receipts from {rckey}.")
            return
        if len(result) > 1:
            logger.warn(f"received too many receipts from {rckey}.")
            return
        receipts = result[0]
        total_amount0 = 0
        total_amount1 = 0
        flag = False
        for receipt in receipts:
            if isinstance(receipt, bytes):
                if receipt[0] >= 0x80:
                    logger.warn(
                        f"Error on the format of received receipt"
                        f" from {rckey}."
                    )
                    continue
                typed_receipt = rlp.decode(receipt[1:])
                if receipt[0] == 0x01:  # eip-2930
                    logs = typed_receipt[3]
                elif receipt[0] == 0x02:  # eip-1559
                    logs = typed_receipt[3]
                else:
                    logger.warn(
                        f"Error on the type of received typed-receipt"
                        f" from {rckey}."
                    )
                    continue
            else:
                logs = receipt[3]
            for log in logs:
                if log[0] != UNISWAP_V3_ADDRESS:
                    continue
                if log[1][0] != UNISWAP_V3_TOPIC:
                    continue
                amount0 = int.from_bytes(log[2][:32], "big", signed=True)
                amount1 = int.from_bytes(log[2][32:64], "big", signed=True)
                sqrt_price = int.from_bytes(log[2][64:96], "big", signed=True)
                liquidity = int.from_bytes(log[2][96:128], "big", signed=True)
                tick = int.from_bytes(log[2][128:160], "big", signed=True)
                logger.info("Found uniswap log.")
                logger.info(f"Amount0: {amount0}, Amount1: {amount1}")
                logger.info(f"Sqrt price: {sqrt_price}, tick: {tick}")
                total_amount0 += amount0
                total_amount1 += amount1
                flag = True
        if flag:
            balance0, balance1 = simulation.burn(
                195000,
                196620,
                4621219005768122 + 4270283529460521,
                sqrt_price,
                tick
            )
            logger.info(
                f"Total amount({height}): {total_amount0}, {total_amount1}"
            )
            logger.info(f"Balance({height}): {balance0}, {balance1}")
            try:
                self.channel.put_nowait({
                    "type": "uniswap",
                    "block_ts": block_ts,
                    "receive_ts": receive_ts,
                    "hash": hash,
                    "height": height,
                    "balance0": balance0,
                    "balance1": balance1,
                    "amount0": total_amount0,
                    "amount1": total_amount1,
                    "sqrt_price": sqrt_price,
                    "liquidity": liquidity,
                    "tick": tick
                })
            except Exception:
                logger.warn("Failed to put uniswap signal to channel.")
            self.last_reciept_block = height
            self.last_reciept_block_hash = hash

    async def handle_new_block(
        self, rckey: str, payload: RLP, active: bool
    ) -> None:
        new_height = int.from_bytes(payload[0][0][8], "big")
        new_td = int.from_bytes(payload[1], "big")
        new_hash = keccak(rlp.encode(payload[0][0]))
        block_ts = int.from_bytes(payload[0][0][11], "big")
        receive_ts = int(time.time())
        delta_time = receive_ts - block_ts
        logger.info(f"received a block {new_height}(Timeout: {delta_time}s).")
        if rckey in self.handlers:
            self.handlers[rckey].base_loop.start_soon(
                self.waiting_for_receipts,
                rckey,
                block_ts,
                receive_ts,
                new_height,
                new_hash
            )
        if opts.NOW_HEIGHT < new_height:
            opts.NOW_HEIGHT = new_height
            opts.NOW_TD = new_td
            opts.NOW_HASH = new_hash
            store.block.write_latest_block(
                opts.NOW_HEIGHT, opts.NOW_HASH, opts.NOW_TD
            )
            try:
                self.channel.put_nowait({
                    "type": "new_block",
                    "block_ts": block_ts,
                    "receive_ts": receive_ts,
                    "height": new_height,
                    "hash": new_hash
                })
            except Exception:
                logger.warn("Failed to put new block signal to channel.")
            if not active:
                self.add_header_cache(new_height, payload[0][0])
                self.add_body_cache(new_height, payload[0][1:])
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

    async def handle_new_tx(self, rckey: str, payload: RLP) -> None:
        # logger.info(f"received a new tx.")
        keys = list(self.handlers.keys())
        samples = random.sample(keys, min(5, len(self.handlers)))
        for key in samples:
            if key == rckey:
                continue
            if key in self.handlers:
                await self.handlers[key].send_message(
                    MESSAGE_CODES.TX, payload
                )
