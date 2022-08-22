#!/usr/bin/env python
# -*- codeing:utf-8 -*-
"""
"""

__author__ = "XiaoHuiHui"

import ipaddress
from ipaddress import IPv4Address, IPv6Address
from typing import NamedTuple

from eth_keys.datatypes import PublicKey

from enr.datatypes import ENR

IPAddress = IPv4Address | IPv6Address


class Addr(NamedTuple):
    """A addr tuple of a peer in a p2p network."""
    address: IPAddress
    udp_port: int

    def __str__(self) -> str:
        if self.address.version == 4:
            return f"{str(self.address)}:{self.udp_port}"
        else:
            return f"[{str(self.address)}]:{self.udp_port}"

    def to_RLP(self) -> list[int]:
        if self.address.version not in (4, 6):
            raise ValueError("Unsupported ip address version.")
        return [int(self.address), self.udp_port, 0]

    @classmethod
    def from_RLP(cls, payload: list[bytes]) -> "Addr":
        return cls(
            ipaddress.ip_address(
                int.from_bytes(payload[0], "big", signed=False)
            ),
            int.from_bytes(payload[1], "big", signed=False)
        )


class Peer(NamedTuple):
    """A infomation tuple of a peer in a p2p network."""

    address: IPAddress
    udp_port: int
    tcp_port: int

    def __str__(self) -> str:
        if self.address.version == 4:
            return f"{str(self.address)}:{self.udp_port}"
        else:
            return f"[{str(self.address)}]:{self.udp_port}"

    def to_RLP(self) -> list[int]:
        if self.address.version not in (4, 6):
            raise ValueError("Unsupported ip address version.")
        return [int(self.address), self.udp_port, self.tcp_port]

    @classmethod
    def from_RLP(cls, payload: list[bytes]) -> "Peer":
        return cls(
            ipaddress.ip_address(
                int.from_bytes(payload[0], "big", signed=False)
            ),
            int.from_bytes(payload[1], "big", signed=False),
            int.from_bytes(payload[2], "big", signed=False)
        )

    @classmethod
    def from_ENR(cls, enr: ENR) -> "Peer":
        assert enr.content["ip"] is not None
        assert enr.content["udp"] is not None
        assert enr.content["tcp"] is not None
        return cls(
            enr.content["ip"],
            enr.content["udp"],
            enr.content["tcp"]
        )


class Node(NamedTuple):
    """A infomation tuple of a peer with id in a p2p network."""

    address: IPAddress
    udp_port: int
    tcp_port: int
    id: PublicKey

    def __str__(self) -> str:
        id_str = self.id.to_bytes().hex()[:7]
        if self.address.version == 4:
            return f"{id_str}({str(self.address)}:{self.udp_port})"
        else:
            return f"{id_str}([{str(self.address)}]:{self.udp_port})"

    def to_RLP(self) -> list[int | bytes]:
        if self.address.version not in (4, 6):
            raise ValueError("Unsupported ip address version.")
        return [
            int(self.address),
            self.udp_port,
            self.tcp_port,
            self.id.to_bytes()
        ]

    @classmethod
    def from_RLP(cls, payload: list[bytes]) -> "Node":
        return cls(
            ipaddress.ip_address(
                int.from_bytes(payload[0], "big", signed=False)
            ),
            int.from_bytes(payload[1], "big", signed=False),
            int.from_bytes(payload[2], "big", signed=False),
            PublicKey(payload[3])
        )
