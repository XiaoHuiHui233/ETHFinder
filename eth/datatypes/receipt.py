#!/usr/bin/env python
# -*- codeing:utf-8 -*-
"""A implementation of receipt parser of eth protocol.
"""

__author__ = "XiaoHuiHui"
__version__ = "1.1"

from typing import NamedTuple, Union

import rlp

RLP = Union[list[list[list[bytes]]], list[list[bytes]], list[bytes], bytes]


class Log(NamedTuple):
    contract_address: bytes
    topics: list[bytes]
    data: bytes

    @classmethod
    def from_RLP(cls, payload: RLP) -> "Log":
        cls(payload[0], payload[1], payload[2])

    def to_RLP(self) -> RLP:
        return [self.contract_address, self.topics, self.data]


class LegacyReceipt(NamedTuple):
    post_state_or_status: Union[bytes, bool]
    cumulative_gas: int
    bloom: bytes
    logs: list[Log]

    @classmethod
    def from_RLP(cls, payload: RLP) -> "LegacyReceipt":
        return cls(
            True if payload[0] == bytes(1) else
            False if payload[0] == bytes(0) else payload[0],
            int.from_bytes(payload[1], "big", signed=False),
            payload[2], [Log.from_RLP(data) for data in payload[3]]
        )

    def to_RLP(self) -> RLP:
        return [
            1 if self.post_state_or_status is True else 0 if
            self.post_state_or_status is False else self.post_state_or_status,
            self.cumulative_gas,
            self.bloom, [log.to_RLP() for log in self.logs]
        ]


class Receipt2930(NamedTuple):
    status: bool
    cumulative_gas_used: int
    logs_bloom: bytes
    logs: list[Log]
    type: int = 1

    @classmethod
    def from_RLP(cls, payload: RLP) -> "Receipt2930":
        return cls(
            payload[0] != bytes(0),
            int.from_bytes(payload[1], "big", signed=False),
            payload[2],
            [Log.from_RLP(data) for data in payload[3]],
        )

    def to_RLP(self) -> RLP:
        return [
            1 if self.status else 0,
            self.cumulative_gas,
            self.logs_bloom, [log.to_RLP() for log in self.logs]
        ]


class Receipt1559(NamedTuple):
    status: bool
    cumulative_gas_used: int
    logs_bloom: bytes
    logs: list[Log]
    type: int = 2

    @classmethod
    def from_RLP(cls, payload: RLP) -> "Receipt2930":
        return cls(
            payload[0] != bytes(0),
            int.from_bytes(payload[1], "big", signed=False),
            payload[2],
            [Log.from_RLP(data) for data in payload[3]],
        )

    def to_RLP(self) -> RLP:
        return [
            1 if self.status else 0,
            self.cumulative_gas,
            self.logs_bloom, [log.to_RLP() for log in self.logs]
        ]


Receipt2718 = TypedReceipt = Union[Receipt2930, Receipt1559]


def receipt_2718_from_RLP(payload: RLP) -> Receipt2718:
    type_n = payload[0]
    datas = rlp.decode(payload[1:])
    if type_n == 1:
        return Receipt2930.from_RLP(datas)
    elif type_n == 2:
        return Receipt1559.from_RLP(datas)
    else:
        raise ValueError("No supported typed receipt version.")


Receipt = Union[LegacyReceipt, Receipt2718]


def receipt_from_RLP(payload: RLP) -> Receipt:
    if isinstance(payload, list):
        return LegacyReceipt.from_RLP(payload)
    else:
        return receipt_2718_from_RLP(payload)
