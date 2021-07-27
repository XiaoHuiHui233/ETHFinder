from __future__ import annotations
from typing import Coroutine, TypeVar, List
import logging
from logging import FileHandler, Formatter
from collections import OrderedDict
import random

import trio

from rlpx.procotols.eth import EthProcotol, MESSAGE_CODES
from trickmath.position import burn
import config as opts

logger = logging.getLogger("controller")
main_logger = logging.getLogger("main")

fh = FileHandler('./logs/controller.log')
fmt = Formatter("%(asctime)s [%(name)s][%(levelname)s] %(message)s")
fh.setFormatter(fmt)
fh.setLevel(logging.INFO)
logger.addHandler(fh)

RLP = TypeVar("RLP", List[List[bytes]], List[bytes], bytes)

CODE_PAIR = {
    MESSAGE_CODES.GET_BLOCK_HEADERS: MESSAGE_CODES.BLOCK_HEADERS,
    MESSAGE_CODES.GET_BLOCK_BODIES:  MESSAGE_CODES.BLOCK_BODIES,
    MESSAGE_CODES.GET_NODE_DATA: MESSAGE_CODES.NODE_DATA,
    MESSAGE_CODES.GET_RECEIPTS:  MESSAGE_CODES.RECEIPTS,
    MESSAGE_CODES.GET_POOLED_TRANSACTIONS: MESSAGE_CODES.POOLED_TRANSACTIONS
}

class ETHController:
    def __init__(self):
        self.procotols = {}
        self.record = {}
        self.streams = []
        self.hash_to_height = {}
        self.block_header_cache = OrderedDict()
        self.block_body_cache = OrderedDict()

    async def bind(self):
        async with trio.open_nursery() as res_loop:
            self.res_loop = res_loop
            res_loop.start_soon(self.print_loop)

    def append(self, eth: EthProcotol) -> None:
        self.procotols[eth.rckey] = eth

    def remove(self, rckey: str) -> None:
        if rckey in self.procotols:
            self.procotols.pop(rckey)
        if rckey in self.record:
            self.record.pop(rckey)

    async def print_loop(self) -> Coroutine:
        while True:
            main_logger.info(f"Now {len(self.procotols)} procotols in controller.")
            await trio.sleep(10)

    def add_header_cache(self, height: int, cache: RLP) -> None:
        self.block_header_cache[height] = cache
        self.hash_to_height[cache[13]] = height
        while(len(self.block_header_cache) > 100):
            self.block_header_cache.popitem(False)

    def add_body_cache(self, height: int, cache: RLP) -> None:
        self.block_body_cache[height] = cache
        while(len(self.block_body_cache) > 100):
            self.block_body_cache.popitem(False)

    async def handle_receipts(self, payload: RLP) -> Coroutine:
        for receipt in payload:
            for log in receipt[3]:
                if log[0] == bytes.fromhex("8ad599c3a0ff1de082011efddc58f1908eb6e6d8"):
                    # amount0 = int.from_bytes(log[2][:32], byteorder="big", signed=True)
                    # amount1 = int.from_bytes(log[2][32:64], byteorder="big", signed=True)
                    # liquidity = int.from_bytes(log[2][64:96], byteorder="big", signed=True)
                    sqrt_price = int.from_bytes(log[2][96:128], byteorder="big", signed=True)
                    tick = int.from_bytes(log[2][128:160], byteorder="big", signed=True)
                    my_amount0, my_amount1 = burn(
                        184200,
                        207240,
                        309819542158801 + 107844134963126,
                        sqrt_price,
                        tick
                    )
                    main_logger.info(f"balance: {my_amount0}, {my_amount1}")

    async def handle_new_block_hashes(self, payload: RLP, procotol: EthProcotol) -> Coroutine:
        keys = list(self.procotols.keys())
        samples = random.sample(keys, min(5, len(self.procotols)))
        for key in samples:
            if key == procotol.rckey:
                continue
            self.res_loop.start_soon(
                self.procotols[key].send_message,
                MESSAGE_CODES.NEW_BLOCK_HASHES,
                payload
            )
        # temp_block_list = []
        # for block in payload:
        #     block_hash = block[0]
        #     block_height = int.from_bytes(block[1], byteorder='big')
        #     main_logger.info(f"Recieved a block hash {block_height}.")
        #     if opts.NOW_HEIGHT < block_height:
        #         temp_block_list.append(block_hash)
        #     if opts.NOW_HEIGHT == block_height and opts.NOW_HASH != block_hash:
        #         main_logger.warn(f"Found a conflict.")
        # if len(temp_block_list) > 0:
        #     self.res_loop.start_soon(
        #         procotol.send_message,
        #         MESSAGE_CODES.GET_BLOCK_HEADERS,
        #         temp_block_list
        #     )

    async def handle_new_block(self, payload: RLP, procotol: EthProcotol) -> Coroutine:
        keys = list(self.procotols.keys())
        samples = random.sample(keys, min(5, len(self.procotols)))
        for key in samples:
            if key == procotol.rckey:
                continue
            self.res_loop.start_soon(
                self.procotols[key].send_message,
                MESSAGE_CODES.NEW_BLOCK,
                payload
            )
        new_height = int.from_bytes(payload[0][0][8], byteorder='big')
        new_td = int.from_bytes(payload[1], byteorder='big')
        new_hash = payload[0][0][13]
        main_logger.info(f"Recieved a block {new_height}({new_td}).")
        if opts.NOW_HEIGHT < new_height:
            self.add_header_cache(new_height, payload[0][0])
            self.add_body_cache(new_height, payload[0][1:])
            self.res_loop.start_soon(
                procotol.send_message,
                MESSAGE_CODES.GET_RECEIPTS,
                [new_hash]
            )
            opts.NOW_HEIGHT = new_height
            opts.NOW_TD = new_td
            opts.NOW_HASH = new_hash
        elif opts.NOW_HEIGHT == new_height and opts.NOW_HASH != new_hash:
            main_logger.warn(f"Found a block conflict ({new_hash.hex()}).")

    async def wait_for_reply(self, rckey: str) -> Coroutine:
        await trio.sleep(10)
        if rckey in self.record:
            sender_rckey = self.record[rckey][0]
            if sender_rckey in self.procotols:
                code = self.record[rckey][1]
                main_logger.warn(f"No one reply {code} from {sender_rckey} in 10s, reply empty list.")
                await self.procotols[sender_rckey].send_message(
                    CODE_PAIR[code],
                    []
                )
            self.record.pop(rckey)

    async def handle_auto_reply(self, eth: EthProcotol, code: MESSAGE_CODES, payload: RLP) -> Coroutine:
        flag = True
        for key in self.procotols:
            if key in self.record:
                continue
            if key == eth.rckey:
                continue
            main_logger.info(f"{code} from {eth.rckey} was forwarded to {key}.")
            self.res_loop.start_soon(
                self.procotols[key].send_message,
                code,
                payload
            )
            self.record[key] = (eth.rckey, code)
            self.res_loop.start_soon(self.wait_for_reply, key)
            flag = False
            break
        if flag:
            main_logger.warn(f"{code} from {eth.rckey} cannot be forwarded to any other peer, so reply empty list.")
            self.res_loop.start_soon(
                eth.send_message,
                CODE_PAIR[code],
                []
            )

    async def handle_get_headers(self, payload: RLP, procotol: EthProcotol) -> Coroutine:
        if len(payload[0]) == 32:
            if payload[0] in self.hash_to_height:
                block_height = self.hash_to_height[payload[0]]
            else:
                main_logger.warn(f"Hash for start block from {MESSAGE_CODES.GET_BLOCK_HEADERS}({procotol.rckey}) was not in cache.")
                await self.handle_auto_reply(procotol, MESSAGE_CODES.GET_BLOCK_HEADERS, payload)
                return
        else:
            block_height = int.from_bytes(payload[0], byteorder="big")
        limit = int.from_bytes(payload[1], byteorder="big")
        skip = int.from_bytes(payload[2], byteorder="big")
        reverse = int.from_bytes(payload[3], byteorder="big")
        main_logger.info(f"Recieve {MESSAGE_CODES.GET_BLOCK_HEADERS} from {procotol.rckey} ({block_height}, {limit}, {skip}, {reverse}).")
        series = []
        while limit > 0:
            series.append(block_height)
            if reverse == 0:
                block_height += skip
            else:
                block_height -= skip
            if block_height > opts.NOW_HEIGHT:
                break
            limit -= 1
        headers = []
        record = []
        for height in series:
            if height in self.block_header_cache:
                headers.append(self.block_header_cache[height])
                record.append(height)
        if len(headers) != 0:
            main_logger.info(f"Reply: {record}.")
            self.res_loop.start_soon(
                procotol.send_message,
                MESSAGE_CODES.BLOCK_HEADERS,
                headers
            )
        else:
            main_logger.warn(f"No header cache was found.")
            await self.handle_auto_reply(procotol, MESSAGE_CODES.GET_BLOCK_HEADERS, payload)

    async def handle_get_bodies(self, payload: RLP, procotol: EthProcotol) -> Coroutine:
        blocks = []
        record = []
        for hash in payload:
            if hash in self.hash_to_height:
                if self.hash_to_height[hash] in self.block_body_cache:
                    record.append(self.hash_to_height[hash])
                    blocks.append(self.block_body_cache[self.hash_to_height[hash]])
        if len(blocks) != 0:
            main_logger.info(f"Reply for {MESSAGE_CODES.GET_BLOCK_BODIES}({procotol.rckey}): {record}.")
            self.res_loop.start_soon(
                procotol.send_message,
                MESSAGE_CODES.BLOCK_BODIES,
                blocks
            )
        else:
            main_logger.warn(f"No body cache was found.")
            await self.handle_auto_reply(procotol, MESSAGE_CODES.GET_BLOCK_BODIES, payload)

    async def handle_get_receipts(self, payload: RLP, procotol: EthProcotol) -> Coroutine:
        self.res_loop.start_soon(
            procotol.send_message,
            MESSAGE_CODES.RECEIPTS,
            []
        )

    async def handle_reply(self, eth: EthProcotol, code: MESSAGE_CODES, payload: RLP) -> Coroutine:
        if eth.rckey not in self.record:
            return
        sender_rckey, send_code = self.record[eth.rckey]
        if (code == CODE_PAIR[send_code]):
            if sender_rckey in self.procotols:
                main_logger.info(f"{code} from {sender_rckey} was reply by {eth.rckey}.")
                self.res_loop.start_soon(
                    self.procotols[sender_rckey].send_message,
                    code,
                    payload
                )
                self.record.pop(eth.rckey)

    async def handle_message(self, eth: EthProcotol, code: MESSAGE_CODES, payload: RLP) -> Coroutine:
        logger.info(f"{eth.rckey}(version: {eth.version}) recieved {code}.")
        if code == MESSAGE_CODES.TX:
            pass
        elif code == MESSAGE_CODES.NEW_BLOCK_HASHES:
            await self.handle_new_block_hashes(payload, eth)
        elif code == MESSAGE_CODES.NEW_BLOCK:
            await self.handle_new_block(payload, eth)
        elif code == MESSAGE_CODES.NEW_POOLED_TRANSACTION_HASHES:
            pass
        elif code == MESSAGE_CODES.GET_BLOCK_HEADERS:
            await self.handle_get_headers(payload, eth)
        elif code == MESSAGE_CODES.GET_BLOCK_BODIES:
            await self.handle_get_bodies(payload, eth)
        elif code == MESSAGE_CODES.GET_RECEIPTS:
            await self.handle_get_receipts(payload, eth)
        elif code in [MESSAGE_CODES.GET_NODE_DATA,
                    MESSAGE_CODES.GET_POOLED_TRANSACTIONS]:
            await self.handle_auto_reply(eth, code, payload)
        elif code in [MESSAGE_CODES.BLOCK_HEADERS,
                    MESSAGE_CODES.BLOCK_BODIES,
                    MESSAGE_CODES.NODE_DATA,
                    MESSAGE_CODES.POOLED_TRANSACTIONS]:
            await self.handle_reply(eth, code, payload)
        elif code == MESSAGE_CODES.RECEIPTS:
            await self.handle_receipts(payload)

eth_controller = ETHController()

