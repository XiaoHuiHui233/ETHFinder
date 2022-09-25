#!/usr/bin/env python
# -*- codeing:utf-8 -*-
"""
"""

__author__ = "XiaoHuiHui"

from asyncio import StreamReader, StreamWriter
from enum import Enum
from ipaddress import IPv4Address, IPv6Address
from typing import NamedTuple, Optional

from eth_keys.datatypes import PrivateKey, PublicKey

IPAddress = IPv4Address | IPv6Address


class Addr(NamedTuple):
    """A addr tuple of a peer in a p2p network."""
    address: IPAddress
    tcp_port: int

    def __str__(self) -> str:
        if self.address.version == 4:
            return f"{str(self.address)}:{self.tcp_port}"
        else:
            return f"[{str(self.address)}]:{self.tcp_port}"


class PeerParams(NamedTuple):
    addr: Addr
    private_key: PrivateKey
    remote_id: Optional[PublicKey]
    reader: StreamReader
    writer: StreamWriter


class DC_REASONS(Enum):
    DC_REQUESTED = 0x00
    NETWORK_ERROR = 0x01
    PROTOCOL_ERROR = 0x02
    USELESS_PEER = 0x03
    TOO_MANY_PEERS = 0x04
    ALREADY_CONNECTED = 0x05
    INCOMPATIBLE_VERSION = 0x06
    INVALID_IDENTITY = 0x07
    CLIENT_QUITTING = 0x08
    UNEXPECTED_IDENTITY = 0x09
    SAME_IDENTITY = 0x0a
    TIMEOUT = 0x0b
    SUBPROTOCOL_ERROR = 0x10


class Capability(NamedTuple):
    name: str
    version: int
    length: int

    def __str__(self) -> str:
        return f"{self.name}, {self.version}, {self.length}"

    def to_RLP(self) -> list[str | int]:
        return [self.name, self.version]
