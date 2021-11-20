#!/usr/bin/env python
# -*- codeing:utf-8 -*-
"""A implementation of service of eth protocol.
"""

__author__ = "XiaoHuiHui"
__version__ = "1.1"

from typing import Union
from multiprocessing.connection import Connection
import uuid

import trio
from lru import LRU

from .datatypes.block import Block
from .datatypes.transaction import Transaction
from .datatypes.receipt import Receipt
from utils import Promise

RLP = Union[list[list[list[bytes]]], list[list[bytes]], list[bytes], bytes]


class EthService:
    """
    """
    def __init__(self, name: str, connection: Connection) -> None:
        self.name = name
        self.connection = connection
        self.promises: dict[int, Promise] = LRU(10000)
        self.operators: dict[str, dict[str, callable]] = {
            "post": {
                # low-level
                "headers": None,
                "bodies": None,
                "pooled_txs": None,
                "node_data": None,
                "receipts": None,
                # high-level
                "block": None,
                "blocks": None,
                "block_and_receipts": None,
                "blocks_and_receipts": None
            },
            "handle": {
                # low-level
                "new_block_hash": self.handle_new_block_hash,
                "raw_new_block": self.handle_raw_new_block,
                "new_pooled_tx_hashes": self.handle_new_pooled_tx_hashes,
                "txs": self.handle_txs,
                # high-level
                "new_block": self.handle_new_block,
                "new_block_and_receipts": self.handle_new_block_and_receipts
            }
        }

    async def bind(self) -> None:
        while True:
            if self.connection.poll():
                data = self.connection.recv()
                await self.handle_data(data)
            else:
                trio.sleep(0)

    async def handle_data(self, data: dict) -> None:
        if data["type"] not in self.operators.keys():
            raise ValueError("Invalid type to handle from controller!")
        if data["obj"] not in self.operators[data["type"]].keys():
            raise ValueError(
                f'Invalid obj in type {data["type"]} '
                'to handle from controller!'
            )
        self.operators[data["type"]][data["obj"]](**data["data"])

    async def send_message(self, type: str, data: RLP) -> Promise:
        id = uuid.uuid1().int >> 64
        promise = Promise()
        self.promises[id] = promise
        return promise

    # low-level abilities
    async def handle_new_block_hash(
        self, hashes_and_heights: list[tuple[str, int]]
    ) -> None:
        pass

    async def handle_raw_new_block(self, block: Block, td: int) -> None:
        pass

    async def handle_new_tx(self, txs: list[Transaction]) -> None:
        pass

    async def handle_new_pooled_tx_hashes(
        self, tx_hashes: list[str]
    ) -> None:
        pass

    # high-level abilities
    async def handle_new_block(self, block: Block) -> None:
        pass

    async def handle_new_block_and_receipts(
        self, block: Block, receipts: list[Receipt]
    ) -> None:
        pass
