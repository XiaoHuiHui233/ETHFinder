#!/usr/bin/env python
# -*- codeing:utf-8 -*-

"""
"""

__author__ = "XiaoHuiHui"
__version__ = "2.3"

import ipaddress
from typing import Union
from abc import ABCMeta, abstractmethod

from dnsdisc import PeerNetworkInfo

IPAddress = Union[ipaddress.IPv4Address, ipaddress.IPv6Address]
RLP = Union[list[list[bytes]], list[bytes], bytes]


class PeerInfo:
    """A class representing the peer in a peer-to-peer network."""

    def __init__(
            self, address: IPAddress, udp_port: int, tcp_port: int) -> None:
        self.address = address
        self.udp_port = udp_port
        self.tcp_port = tcp_port

    def __hash__(self) -> int:
        return hash(self.address) ^ \
        hash(self.udp_port) ^ \
        hash(self.tcp_port)
    
    def __eq__(self, other) -> bool:
        if not isinstance(other, PeerInfo):
            return False
        return (
            self.address == other.address
            and self.tcp_port == other.tcp_port
            and self.udp_port == other.udp_port
        )

    def __ne__(self, other) -> bool:
        if not isinstance(other, PeerInfo):
            return True
        return (self.address != other.address
            or self.tcp_port != other.tcp_port
            or self.udp_port != other.udp_port)

    def to_RLP(self) -> RLP:
        if self.address.version == 4:
            return [
                int.to_bytes(int(self.address), 4, "big", signed=False),
                int.to_bytes(self.udp_port, 2, "big", signed=False),
                int.to_bytes(self.tcp_port, 2, "big", signed=False)
            ]
        elif self.address.version == 6:
            return [
                int.to_bytes(int(self.address), 16, "big", signed=False),
                int.to_bytes(self.udp_port, 2, "big", signed=False),
                int.to_bytes(self.tcp_port, 2, "big", signed=False)
            ]
        else:
            raise ValueError("Bad ip address version.")

    @classmethod
    def remake(cls, raw_peer: PeerNetworkInfo) -> "PeerInfo":
        """Use dnsdisc class PeerNetworkInfo object and id to construct
        a new object.

        :param PeerNetworkInfo raw_peer: The peer network object.
        :return PeerInfo: The peer info object.
        """
        return cls(raw_peer.address, raw_peer.udp_port, raw_peer.tcp_port)
    
    @classmethod
    def decode(cls, payload: RLP) -> "PeerInfo":
        return cls(
            ipaddress.ip_address(payload[0]),
            int.from_bytes(payload[1], "big"),
            int.from_bytes(payload[2], "big")
        )


class Message(metaclass=ABCMeta):
    """The base abstract class of the communication packet of the
    Node Discovery Protocol.
    """

    @abstractmethod
    def to_bytes(self) -> bytes:
        """Each subclass should implement this function to convert
        its own information into bytes.

        :return bytes: A bytes stream.
        """
        return NotImplemented


