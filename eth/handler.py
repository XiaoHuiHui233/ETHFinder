#!/usr/bin/env python
# -*- codeing:utf-8 -*-
"""A implementation of handler of eth protocol.
"""

__author__ = "XiaoHuiHui"
__version__ = "1.3"

from typing import Union
import logging
from logging import FileHandler, Formatter, StreamHandler
import uuid

from lru import LRU
import trio
from trio import Lock

from rlpx import EthHandler
from rlpx.protocols.eth import MESSAGE_CODES
from utils import RLP, Promise
from . import controller
import config as opts

logger = logging.getLogger("core.eth.handler")
fmt = Formatter("%(asctime)s [%(name)s][%(levelname)s] %(message)s")
fh = FileHandler("./logs/core/eth/handler.log", "w", encoding="utf-8")
sh = StreamHandler()
fh.setFormatter(fmt)
sh.setFormatter(fmt)
fh.setLevel(logging.INFO)
sh.setLevel(logging.INFO)
logger.addHandler(fh)
logger.addHandler(sh)

CODE_PAIR = {
    MESSAGE_CODES.BLOCK_HEADERS: MESSAGE_CODES.GET_BLOCK_HEADERS,
    MESSAGE_CODES.BLOCK_BODIES: MESSAGE_CODES.GET_BLOCK_BODIES,
    MESSAGE_CODES.RECEIPTS: MESSAGE_CODES.GET_RECEIPTS,
    MESSAGE_CODES.NODE_DATA: MESSAGE_CODES.GET_NODE_DATA,
    MESSAGE_CODES.POOLED_TRANSACTIONS: MESSAGE_CODES.GET_POOLED_TRANSACTIONS,
    MESSAGE_CODES.GET_BLOCK_HEADERS: MESSAGE_CODES.BLOCK_HEADERS,
    MESSAGE_CODES.GET_BLOCK_BODIES: MESSAGE_CODES.BLOCK_BODIES,
    MESSAGE_CODES.GET_RECEIPTS: MESSAGE_CODES.RECEIPTS,
    MESSAGE_CODES.GET_NODE_DATA: MESSAGE_CODES.NODE_DATA,
    MESSAGE_CODES.GET_POOLED_TRANSACTIONS: MESSAGE_CODES.POOLED_TRANSACTIONS
}


class MyEthHandler(EthHandler):
    """
    """
    def __init__(self, controller: "controller.EthController") -> None:
        self.running = False
        self.controller = controller

    def after_status(self) -> None:
        self.running = True
        if self.version >= 66:
            self.promises: dict[int, Promise[RLP]] = LRU(100)
        else:
            self.promises: dict[MESSAGE_CODES, Promise[RLP]] = {}
            self.locks: dict[MESSAGE_CODES, Lock] = {}
            for code in CODE_PAIR:
                self.locks[code] = Lock()

    async def disconnect(self) -> None:
        self.running = False
        if self.rckey in self.controller.handlers:
            self.controller.handlers.pop(self.rckey)

    async def send_message(self, code: MESSAGE_CODES, data: RLP) -> bool:
        return await self.eth.send_message(code, data)

    async def handle_message(self, code: MESSAGE_CODES, data: RLP) -> None:
        # logger.info(
        #     f"{self.rckey}(version: {self.version}) received {code}."
        # )
        if code == MESSAGE_CODES.TX:
            await self.controller.handle_new_tx(self.rckey, data)
        elif code == MESSAGE_CODES.NEW_BLOCK_HASHES:
            await self.controller.handle_new_block_hash(self.rckey, data)
        elif code == MESSAGE_CODES.NEW_BLOCK:
            await self.controller.handle_raw_new_block(self.rckey, data)
        elif code == MESSAGE_CODES.NEW_POOLED_TRANSACTION_HASHES:
            await self.controller.handle_new_pooled_tx_hash(self.rckey, data)
        elif code == MESSAGE_CODES.GET_BLOCK_HEADERS:
            logger.info(f"receive GET_BLOCK_HEADERS from {self.rckey}.")
            if self.version >= 66:
                request_id = data[0]
                headers = await self.controller.raw_get_headers(
                    self.rckey, data[1]
                )
                await self.send_message(
                    MESSAGE_CODES.BLOCK_HEADERS, [request_id, headers]
                )
            else:
                headers = await self.controller.raw_get_headers(
                    self.rckey, data
                )
                await self.send_message(MESSAGE_CODES.BLOCK_HEADERS, headers)
        elif code == MESSAGE_CODES.GET_BLOCK_BODIES:
            logger.info(f"receive GET_BLOCK_BODIES from {self.rckey}.")
            if self.version >= 66:
                request_id = data[0]
                bodies = await self.controller.raw_get_bodies(
                    self.rckey, data[1]
                )
                await self.send_message(
                    MESSAGE_CODES.BLOCK_BODIES, [request_id, bodies]
                )
            else:
                bodies = await self.controller.raw_get_bodies(self.rckey, data)
                await self.send_message(MESSAGE_CODES.BLOCK_BODIES, bodies)
        elif code == [
            MESSAGE_CODES.GET_RECEIPTS,
            MESSAGE_CODES.GET_NODE_DATA,
            MESSAGE_CODES.GET_POOLED_TRANSACTIONS
        ]:
            logger.info(f"receive {code} from {self.rckey}.")
            if self.version >= 66:
                request_id = data[0]
                await self.send_message(CODE_PAIR[code], [request_id, []])
            else:
                await self.send_message(CODE_PAIR[code], [])
        elif code in [
            MESSAGE_CODES.BLOCK_HEADERS,
            MESSAGE_CODES.BLOCK_BODIES,
            MESSAGE_CODES.NODE_DATA,
            MESSAGE_CODES.POOLED_TRANSACTIONS,
            MESSAGE_CODES.RECEIPTS
        ]:
            self.handle_default(code, data)

    async def get_default(self, code: MESSAGE_CODES,
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
            if flag:
                logger.info(f"Send {CODE_PAIR[code]} to {self.rckey}(eth66).")
                self.promises[request_id] = promise
            else:
                logger.warn(
                    f"Failed to send {CODE_PAIR[code]} to {self.rckey}(eth66)."
                )
                return None
        else:
            with trio.move_on_after(opts.ETH_LOCK_TIMEOUT) as cancel_scope:
                await self.locks[code].acquire()
            if cancel_scope.cancelled_caught:
                logger.warn(
                    f"Failed to get {CODE_PAIR[code]} lock from {self.rckey}."
                )
                return None
            flag = await self.send_message(CODE_PAIR[code], payload)
            if flag:
                self.promises[code] = promise
                await promise.wait()
            else:
                logger.warn(
                    f"Failed to send {CODE_PAIR[code]} to {self.rckey}."
                )
                return None
            self.locks[code].release()

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

    async def get_headers(
        self,
        startblock: Union[int, str],
        limit: int,
        skip: int,
        reverse: bool
    ) -> list[RLP]:
        promise = await self.get_default(
            MESSAGE_CODES.BLOCK_HEADERS,
            [startblock, limit, skip, 1 if reverse else 0]
        )
        if promise is None:
            return []
        with trio.move_on_after(opts.MSG_TIMEOUT) as cancel_scope:
            await promise.wait()
        if cancel_scope.cancelled_caught and not promise.is_set():
            logger.warn(f"Waiting for headers timeout from {self.rckey}.")
            return []
        return promise.get_result()

    async def get_bodies(self, hashes: list[str]) -> list[RLP]:
        promise = await self.get_default(MESSAGE_CODES.BLOCK_BODIES, hashes)
        if promise is None:
            return []
        with trio.move_on_after(opts.MSG_TIMEOUT) as cancel_scope:
            await promise.wait()
        if cancel_scope.cancelled_caught and not promise.is_set():
            logger.warn(f"Waiting for bodies timeout from {self.rckey}.")
            return []
        return promise.get_result()

    async def get_receipts(self, hashes: list[str]) -> list[RLP]:
        promise = await self.get_default(MESSAGE_CODES.RECEIPTS, hashes)
        if promise is None:
            return []
        with trio.move_on_after(opts.MSG_TIMEOUT) as cancel_scope:
            await promise.wait()
        if cancel_scope.cancelled_caught and not promise.is_set():
            logger.warn(f"Waiting for receipts timeout from {self.rckey}.")
            return []
        return promise.get_result()
