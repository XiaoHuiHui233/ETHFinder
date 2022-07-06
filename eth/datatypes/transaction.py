#!/usr/bin/env python
# -*- codeing:utf-8 -*-
"""A implementation of transaction parser of eth protocol.
"""

__author__ = "XiaoHuiHui"
__version__ = "1.1"

from typing import NamedTuple, Union

import rlp

from utils import RLP


class LegacyTransaction(NamedTuple):
    nonce: int
    gas_price: int
    gas_limit: int
    recipient: bytes
    value: int
    data: bytes
    V: int
    S: int
    R: int

    @classmethod
    def from_RLP(cls, payload: RLP) -> "LegacyTransaction":
        return cls(
            int.from_bytes(payload[0], "big", signed=False),
            int.from_bytes(payload[1], "big", signed=False),
            int.from_bytes(payload[2], "big", signed=False),
            payload[3],
            int.from_bytes(payload[4], "big", signed=False),
            payload[5],
            int.from_bytes(payload[6], "big", signed=False),
            int.from_bytes(payload[7], "big", signed=False),
            int.from_bytes(payload[8], "big", signed=False),
        )

    def to_RLP(self) -> RLP:
        return [
            self.nonce,
            self.gas_price,
            self.gas_limit,
            self.recipient,
            self.value,
            self.data,
            self.V,
            self.S,
            self.R
        ]


class Transaction2930(NamedTuple):
    chain_id: int
    nonce: int
    gas_price: int
    gas_limit: int
    to: bytes
    value: int
    data: bytes
    access_list: list[tuple[bytes, list[bytes]]]
    signature_Y_parity: int
    signature_R: int
    signature_S: int
    type: int = 1


class Transaction1559(NamedTuple):
    chain_id: int
    nonce: int
    max_priority_fee_per_gas: int
    max_fee_per_gas: int
    gas_limit: int
    destination: int
    amount: int
    data: bytes
    access_list: list[tuple[bytes, list[bytes]]]
    signature_Y_parity: int
    signature_R: int
    signature_S: int
    type: int = 2


TypedTransaction = Transaction2718 = Union[Transaction2930, Transaction1559]


def transaction_2718_from_RLP(payload: RLP) -> Transaction2718:
    type_n = payload[0]
    datas = rlp.decode(payload[1:])
    if type_n == 1:
        return Transaction2930.from_RLP(datas)
    elif type_n == 2:
        return Transaction1559.from_RLP(datas)
    else:
        raise ValueError("No supported typed receipt version.")


Transaction = Union[LegacyTransaction, Transaction2718]


def transaction_from_RLP(payload: RLP) -> Transaction:
    if isinstance(payload, list):
        return LegacyTransaction.from_RLP(payload)
    else:
        return transaction_2718_from_RLP(payload)
