from __future__ import annotations
from typing import Coroutine, TypeVar, List
import logging
from logging import FileHandler, Formatter

import trio
from trio import SocketStream

from rlpx.procotols.eth import EthProcotol, MESSAGE_CODES
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

    async def bind(self):
        await trio.serve_tcp(self.on_connect, opts.PROD_PORT, host='localhost')
        self.res_loop = trio.open_nursery()

    async def on_connect(self, socket_stream: SocketStream):
        self.streams.append(socket_stream)

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

    async def handle_new_block(self, payload: RLP):
        new_height = int.from_bytes(payload[0][0][8], byteorder='big')
        new_td = int.from_bytes(payload[1], byteorder='big')
        new_hash = payload[0][0][13]
        main_logger.info(f"Recieved a block {new_height}.")
        if opts.NOW_TD < new_td:
            opts.NOW_HEIGHT = new_height
            opts.NOW_TD = new_td
            opts.NOW_HASH = new_hash
        if opts.NOW_HEIGHT == new_height and opts.NOW_HASH != new_hash:
            main_logger.warn(f"Found a conflict.")

    async def handle_message(self, eth: EthProcotol, code: MESSAGE_CODES, payload: RLP) -> Coroutine:
        logger.info(f"{eth.rckey}(version: {eth.version}) recieved {code}.")
        if code in [MESSAGE_CODES.TX,
                    MESSAGE_CODES.NEW_BLOCK_HASHES,
                    MESSAGE_CODES.NEW_BLOCK,
                    MESSAGE_CODES.NEW_POOLED_TRANSACTION_HASHES]:
            if code == MESSAGE_CODES.NEW_BLOCK:
                for key in self.procotols:
                    if key == eth.rckey:
                        continue
                    self.procotols[key].send_message(
                        MESSAGE_CODES.NEW_BLOCK,
                        payload
                    )
                self.res_loop.start_soon(self.handle_new_block, payload)
        elif code in [MESSAGE_CODES.GET_BLOCK_HEADERS,
                    MESSAGE_CODES.GET_BLOCK_BODIES,
                    MESSAGE_CODES.GET_NODE_DATA,
                    MESSAGE_CODES.GET_RECEIPTS,
                    MESSAGE_CODES.GET_POOLED_TRANSACTIONS]:
            for key in self.procotols:
                if key in self.record:
                    continue
                if key == eth.rckey:
                    continue
                await self.procotols[key].send_message(code, payload)
                self.record[key] = (eth.rckey, code)
                await trio.sleep(3)
                if key in self.record:
                    await eth.send_message(
                        CODE_PAIR[code],
                        []
                    )
                    self.record.pop(key)
                break
        elif code in [
                    MESSAGE_CODES.BLOCK_HEADERS,
                    MESSAGE_CODES.BLOCK_BODIES,
                    MESSAGE_CODES.NODE_DATA,
                    MESSAGE_CODES.RECEIPTS,
                    MESSAGE_CODES.POOLED_TRANSACTIONS]:
            if eth.rckey not in self.record:
                return
            sender_rckey, send_code = self.record[eth.rckey]
            if (code == CODE_PAIR[send_code]):
                if sender_rckey in self.procotols:
                    await self.procotols[sender_rckey].send_message(
                        code,
                        payload
                    )
                    self.record.pop(eth.rckey)

eth_controller = ETHController()

