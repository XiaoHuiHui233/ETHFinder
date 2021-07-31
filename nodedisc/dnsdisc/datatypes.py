#!/usr/bin/env python
# -*- codeing:utf-8 -*-

"""The realization of the data structure of the DNS discovery protocol.
"""

__author__ = "XiaoHuiHui"
__version__ = "1.4"

from typing import Union
import ipaddress

IPAddress = Union[ipaddress.IPv4Address, ipaddress.IPv6Address]
RLP = Union[list[list[bytes]], list[bytes], bytes]


class PeerNetworkInfo:
    """A class represents the network address and port of a peer in a
    peer-to-peer network.
    """

    def __init__(self, address: IPAddress,
            udp_port: int, tcp_port: int) -> None:
        self.address = address
        self.udp_port = udp_port
        if (udp_port > 65535 or udp_port <= 0):
            raise ValueError(f"Invalid UDP port: {udp_port}")
        self.tcp_port = tcp_port
        if (tcp_port > 65535 or tcp_port < 0):
            raise ValueError(f"Invalid TCP port: {tcp_port}")

    def __hash__(self) -> int:
        return hash(self.address) ^ \
        hash(self.udp_port) ^ \
        hash(self.tcp_port)
    
    def __eq__(self, other) -> bool:
        if not isinstance(other, PeerNetworkInfo):
            return False
        return (
            self.address == other.address
            and self.tcp_port == other.tcp_port
            and self.udp_port == other.udp_port
        )

    def __ne__(self, other) -> bool:
        if not isinstance(other, PeerNetworkInfo):
            return True
        return (self.address != other.address
            or self.tcp_port != other.tcp_port
            or self.udp_port != other.udp_port)