#!/usr/bin/env python
# -*- codeing:utf-8 -*-
"""A implementation of block header parser of eth protocol.
"""

__author__ = "XiaoHuiHui"

from typing import NamedTuple

import rlp
from eth_hash.auto import keccak

from . import transaction
from .transaction import Transaction


class BlockHeader(NamedTuple):
    parent_hash: bytes
    ommers_hash: bytes
    coinbase: bytes
    state_root: bytes
    txs_root: bytes
    receipts_root: bytes
    bloom: bytes
    difficulty: int
    number: int
    gas_limit: int
    gas_used: int
    time: int
    extradata: bytes
    mix_digest: bytes
    block_nonce: bytes

    @classmethod
    def from_RLP(cls, payload: RLP) -> "BlockHeader":
        return cls(
            payload[0],
            payload[1],
            payload[2],
            payload[3],
            payload[4],
            payload[5],
            payload[6],
            int.from_bytes(payload[7], "big", signed=False),
            int.from_bytes(payload[8], "big", signed=False),
            int.from_bytes(payload[9], "big", signed=False),
            int.from_bytes(payload[10], "big", signed=False),
            int.from_bytes(payload[11], "big", signed=False),
            payload[12],
            payload[13],
            payload[14]
        )

    def to_RLP(self) -> RLP:
        return [
            self.parent_hash,
            self.ommers_hash,
            self.coinbase,
            self.state_root,
            self.txs_root,
            self.receipts_root,
            self.bloom,
            self.difficulty,
            self.number,
            self.gas_limit,
            self.gas_used,
            self.time,
            self.extradata,
            self.mix_digest,
            self.block_nonce
        ]

    def __hash__(self) -> int:
        hash = keccak(rlp.encode(self.to_RLP()))
        return int.from_bytes(hash, "big", signed=False)


class BlockBody(NamedTuple):
    hash: bytes
    transactions: list[Transaction]
    ommers: list[BlockHeader]

    @classmethod
    def from_RLP(cls, hash: bytes, payload: RLP) -> "BlockBody":
        transactions = []
        for data in payload[0]:
            transactions.append(transaction.transaction_from_RLP(data))
        ommers = []
        for data in payload[1]:
            ommers.append(BlockHeader.from_RLP(data))
        return cls(hash, transactions, ommers)

    def to_RLP(self) -> RLP:
        return [[transaction.to_RLP() for transaction in self.transactions],
                [ommer.to_RLP() for ommer in self.ommers]]

    def __hash__(self) -> int:
        return int.from_bytes(self.hash, "big", signed=False)


class Block(NamedTuple):
    header: BlockHeader
    body: BlockBody

    @classmethod
    def from_RLP(cls, payload: RLP) -> None:
        header = BlockHeader.from_RLP(payload[0])
        return cls(
            header,
            BlockBody.from_RLP(
                int.to_bytes(hash(header), 32, "big", signed=False),
                [payload[1], payload[2]]
            )
        )

    def to_RLP(self) -> RLP:
        body = self.body.to_RLP()
        return [self.header.to_RLP(), body[0], body[1]]

    def __hash__(self) -> int:
        return hash(self.header)
