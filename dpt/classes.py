#!/usr/bin/env python
# -*- codeing:utf-8 -*-

"""
"""

__author__ = "XiaoHuiHui"
__version__ = "2.1"

import ipaddress
from ipaddress import IPv4Address, IPv6Address
from typing import TypeVar, List, Any

from eth_keys.datatypes import PublicKey

IPAddress = TypeVar("IPAddress", IPv4Address, IPv6Address)
RLP = TypeVar("RLP", List[List[bytes]], List[bytes], bytes)


class PeerNetworkInfo:
    """A class represents the network address and port of a peer in a
    peer-to-peer network.
    """

    @classmethod
    def format(cls, address: bytes,
            udp_port: bytes, tcp_port: bytes) -> "PeerNetworkInfo":
        """Construct a peer network object through the byte stream and
        verify its legitimacy.

        :param bytes address: Byte stream expression of ip address.
        :param bytes udp_port: Byte stream expression of UDP port.
        :param bytes tcp_port: Byte stream expression of TCP port.
        :return PeerNetworkInfo: Peer network object.
        """
        address = ipaddress.ip_address(address)
        udp_port = int.from_bytes(udp_port, byteorder="big")
        if (udp_port >> 16 > 0
            or udp_port <= 0):
            raise ValueError(f"Invalid UDP port: {udp_port}")
        tcp_port = int.from_bytes(tcp_port, byteorder="big")
        if (tcp_port >> 16 > 0):
            raise ValueError(f"Invalid TCP port: {tcp_port}")
        return cls(address, udp_port, tcp_port)
    
    @classmethod
    def decode(cls, payload: RLP) -> "PeerNetworkInfo":
        """Parse peer network objects from RLP expressions.

        :param RLP payload: RLP expression.
        :return PeerNetworkInfo: Peer network object.
        """
        if len(payload) < 3:
            raise ValueError(
                f"The length of RLP is not enough to generate a peer."
            )
        return cls.format(payload[0], payload[1], payload[2])

    def __init__(self, address: IPAddress,
            udp_port: int, tcp_port: int) -> None:
        self.address = address
        self.udp_port = udp_port
        self.tcp_port = tcp_port
    
    def __repr__(self) -> str:
        return "-"
    
    def __eq__(self, other: Any) -> bool:
        if not isinstance(other, PeerNetworkInfo):
            return False
        return (
            self.address == other.address
            and self.tcp_port == other.tcp_port
            and self.udp_port == other.udp_port
        )

    def __ne__(self, other: Any) -> bool:
        if not isinstance(other, PeerNetworkInfo):
            return True
        return (self.address != other.address
            or self.tcp_port != other.tcp_port
            or self.udp_port != other.udp_port) 

    def encode(self) -> List[bytes]:
        """Converted the peer network object into a bytes list, easy to
        use RLP expression.

        :return List[bytes]: The bytes list.
        """
        return [
            int(self.address),
            self.udp_port,
            self.tcp_port
        ]


class PeerInfo(PeerNetworkInfo):
    """A class representing the peer in a peer-to-peer network."""

    def __init__(
            self, id: PublicKey, address: IPAddress, udp_port: int,
            tcp_port: int) -> None:
        super().__init__(address, udp_port, tcp_port)
        self.id = id
    
    def __repr__(self) -> str:
        return f"{self.id.to_bytes().hex()[:7]}"

    @classmethod
    def format(cls, id: bytes, address: bytes,
            udp_port: bytes, tcp_port: bytes) -> "PeerInfo":
        """Construct a peer network object through the byte stream and
        verify its legitimacy.

        :param bytes address: Byte stream expression of ip address.
        :param bytes udp_port: Byte stream expression of UDP port.
        :param bytes tcp_port: Byte stream expression of TCP port.
        :return PeerNetworkInfo: Peer network object.
        """
        id = PublicKey(id)
        address = ipaddress.ip_address(address)
        udp_port = int.from_bytes(udp_port, byteorder="big")
        if (udp_port >> 16 > 0
            or udp_port <= 0):
            raise ValueError(f"Invalid UDP port: {udp_port}")
        tcp_port = int.from_bytes(tcp_port, byteorder="big")
        if (tcp_port >> 16 > 0):
            raise ValueError(f"Invalid TCP port: {tcp_port}")
        return cls(id, address, udp_port, tcp_port)

    @classmethod
    def remake(cls, raw_peer: PeerNetworkInfo, id: PublicKey) -> "PeerInfo":
        """Use the base class PeerNetworkInfo object and id to
        construct a new object.

        :param PeerNetworkInfo raw_peer: The base object.
        :param PublicKey id: The id of the peer.
        :return PeerInfo: New object.
        """
        return cls(id, raw_peer.address, raw_peer.udp_port, raw_peer.tcp_port)
    
    def encode(self) -> List[bytes]:
        """Converted the peer network object into a bytes list, easy to
        use RLP expression.

        :return List[bytes]: The bytes list.
        """
        return [
            int(self.address),
            self.udp_port,
            self.tcp_port,
            self.id.to_bytes()
        ]


    @classmethod
    def decode(cls, payload: RLP) -> "PeerInfo":
        """Parse peer objects from RLP expressions.

        :param RLP payload: RLP expression.
        :return PeerInfo: Peer  object.
        """
        if len(payload) < 4:
            raise ValueError(
                f"The length of RLP is not enough to generate a peer."
            )
        return cls.format(payload[3], payload[0], payload[1], payload[2])


