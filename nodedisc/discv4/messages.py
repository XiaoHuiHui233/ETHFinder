#!/usr/bin/env python
# -*- codeing:utf-8 -*-
"""A implementation of message encapsulation module of node discovery
protocol v4.

Node discovery messages are sent as UDP datagrams. The maximum size of
any packet is 1280 bytes.

packet = packet-header || packet-data

Every packet starts with a header:

packet-header = hash || signature || packet-type
hash = keccak256(signature || packet-type || packet-data)
signature = sign(packet-type || packet-data)

The hash exists to make the packet format recognizable when running
multiple protocols on the same UDP port. It serves no other purpose.

Every packet is signed by the node's identity key. The signature is
encoded as a byte array of length 65 as the concatenation of the
signature values r, s and the 'recovery id' v.

The packet-type is a single byte defining the type of message. Valid
packet types are listed below. Data after the header is specific to the
packet type and is encoded as an RLP list. Implementations should ignore
any additional elements in the packet-data list as well as any extra
data after the list.

See: https://github.com/ethereum/devp2p/blob/master/discv4.md

Note: The two types of packets ENRRequest and ENRResponse in EIP-868
are not implemented here.

See: https://eips.ethereum.org/EIPS/eip-868
"""

__author__ = "XiaoHuiHui"

import typing
from datetime import datetime
from typing import NamedTuple, Optional
from eth_keys.datatypes import PublicKey

from enr.datatypes import ENR

from ..datatypes import Addr, Node, Peer


class PingMessage(NamedTuple):
    """The encapsulation of ping packet of the Node Discovery Protocol
    v4 specification.

    packet-data = [version, from, to, expiration, enr-seq ...]
    version = 4
    from = [sender-ip, sender-udp-port, sender-tcp-port]
    to = [recipient-ip, recipient-udp-port, 0]

    The expiration field is an absolute UNIX time stamp. Packets
    containing a time stamp that lies in the past are expired may not be
    processed.

    The enr-seq field is the current ENR sequence number of the sender.
    This field is optional.

    See: https://github.com/ethereum/devp2p/blob/master/discv4.md
    """

    version: int
    from_peer: Peer
    to_peer: Addr
    expiration: int
    enr_seq: Optional[int]

    TYPE = 0x01

    def __repr__(self) -> str:
        return "ping-packet v4"

    def to_RLP(self) -> list[int | list[int]]:
        """Converted the ping-packet into a bytes list, easy to use RLP
        expression.

        :return RLP: A list of bytes conforming to the recursive length
            prefix specification.
        """
        r = [
            self.version,
            self.from_peer.to_RLP(),
            self.to_peer.to_RLP(),
            self.expiration
        ]
        if self.enr_seq is not None:
            r.append(self.enr_seq)
        return r

    @classmethod
    def from_RLP(cls, payload: list[bytes | list[bytes]]) -> "PingMessage":
        """Decode bytes stream to ping packet and verify.

        :param RLP payload: The RLP bytes stream.
        :return PingMessage: An object of ping-packet.
        """
        if len(payload) < 4:
            raise ValueError(
                "The elements in RLP is not enough to generate a ping message."
            )
        expiration = int.from_bytes(
            typing.cast(bytes, payload[3]), "big", signed=False
        )
        if datetime.utcnow().timestamp() > expiration:
            raise ValueError("The received ping packet has expired.")
        version = int.from_bytes(
            typing.cast(bytes, payload[0]), "big", signed=False
        )
        # EIP-8: Similarly, implementations of the RLPx Discovery Protocol
        # should not validate the version number of the ping packet, ignore
        # any additional list elements in any packet, and ignore any data
        # after the first RLP value in any packet. Discovery packets with
        # unknown packet type should be discarded silently. The maximum size
        # of any discovery packet is still 1280 bytes.
        # if version != 0x04:
        #     raise ValueError(
        #         f"Ping message version {version} is unsupported."
        #     )
        return cls(
            version,
            Peer.from_RLP(typing.cast(list[bytes], payload[1])),
            Addr.from_RLP(typing.cast(list[bytes], payload[2])),
            expiration,
            int.from_bytes(typing.cast(bytes, payload[4]), "big")
            if len(payload) >= 5 else None
        )


class PongMessage(NamedTuple):
    """The encapsulation of pong packet of the Node Discovery Protocol
    v4 specification.

    packet-data = [to, ping-hash, expiration, enr-seq, ...]

    Pong is the reply to ping.

    ping-hash should be equal to hash of the corresponding ping packet.
    Implementations should ignore unsolicited pong packets that do not
    contain the hash of the most recent ping packet.

    The enr-seq field is the current ENR sequence number of the sender.
    This field is optional.
    """
    to_peer: Addr
    ping_hash: bytes
    expiration: int
    enr_seq: Optional[int]

    TYPE = 0x02

    def __repr__(self) -> str:
        return "pong-packet v4"

    def to_RLP(self) -> list[bytes | int | list[int]]:
        """Converted the pong-packet into a bytes list, easy to use RLP
        expression.

        :return RLP: A list of bytes conforming to the recursive length
            prefix specification.
        """
        to = self.to_peer.to_RLP()
        r = [
            to,
            self.ping_hash,
            self.expiration,
        ]
        if self.enr_seq is not None:
            r.append(self.enr_seq)
        return r

    @classmethod
    def from_RLP(cls, payload: list[bytes | list[bytes]]) -> "PongMessage":
        """Decode bytes stream to pong packet and verify.

        :param RLP payload: The RLP bytes stream.
        :return PongMessage: An object of pong-packet.
        """
        if len(payload) < 3:
            raise ValueError(
                "The elements in RLP is not enough to generate a pong message."
            )
        expiration = int.from_bytes(
            typing.cast(bytes, payload[2]), byteorder="big"
        )
        if datetime.utcnow().timestamp() > expiration:
            raise ValueError("The received pong packet has expired.")
        return cls(
            Addr.from_RLP(typing.cast(list[bytes], payload[0])),
            typing.cast(bytes, payload[1]),
            expiration,
            int.from_bytes(typing.cast(bytes, payload[3]), "big")
            if len(payload) >= 4 else None
        )


class FindNodeMessage(NamedTuple):
    """The encapsulation of findnode packet of the Node Discovery
    Protocol v4 specification.

    packet-data = [target, expiration, ...]

    A FindNode packet requests information about nodes close to target.
    The target is a 65-byte secp256k1 public key. When FindNode is
    received, the recipient should reply with Neighbors packets
    containing the closest 16 nodes to target found in its local table.
    """

    target: PublicKey
    expiration: int

    TYPE = 0x03

    def __repr__(self) -> str:
        return "findneighbours-packet v4"

    def to_RLP(self) -> list[bytes | int]:
        """Converted the findneighbour-packet into a bytes list, easy to
        use RLP expression.

        :return RLP: A list of bytes conforming to the recursive length
            prefix specification.
        """
        return [self.target.to_bytes(), self.expiration]

    @classmethod
    def from_RLP(cls, payload: list[bytes]) -> "FindNodeMessage":
        """Decode bytes stream to findneighbours packet and verify.

        :param RLP payload: The RLP bytes stream.
        :return FindNeighboursMessage: An object of
            findneighbours-packet.
        """
        if len(payload) < 2:
            raise ValueError(
                "The length of RLP is not enough to generate a findneighbours"
                " message."
            )
        expiration = int.from_bytes(payload[1], byteorder="big")
        if datetime.utcnow().timestamp() > expiration:
            raise ValueError("The received findneighbours packet has expired.")
        return cls(PublicKey(payload[0]), expiration)


class NeighboursMessage(NamedTuple):
    """The encapsulation of neighbours packet of the Node Discovery
    Protocol v4 specification.

    packet-data = [nodes, expiration, ...]
    nodes = [[ip, udp-port, tcp-port, node-id], ...]

    Neighbors is the reply to FindNode.
    """

    nodes: list[Node]
    expiration: int

    TYPE = 0x04

    def __repr__(self) -> str:
        return "neighbours-packet v4"

    def to_RLP(self) -> list[int | list[list[int | bytes]]]:
        """Converted the neighbour-packet into a bytes list, easy to
        use RLP expression.

        :return RLP: A list of bytes conforming to the recursive length
            prefix specification.
        """
        return [[node.to_RLP() for node in self.nodes], self.expiration]

    @classmethod
    def from_RLP(
        cls, payload: list[bytes | list[list[bytes]]]
    ) -> "NeighboursMessage":
        """Decode bytes stream to neighbours packet and verify.

        :param RLP payload: The RLP bytes stream.
        :return NeighboursMessage: An object of neighbours-packet.
        """
        if len(payload) < 2:
            raise ValueError(
                "The length of RLP is not enough to generate a neighbours"
                " message."
            )
        expiration = int.from_bytes(
            typing.cast(bytes, payload[1]), byteorder="big"
        )
        if datetime.utcnow().timestamp() > expiration:
            raise ValueError("The received neighbours packet has expired.")
        return cls([
            Node.from_RLP(data)
            for data in typing.cast(list[list[bytes]], payload[0])
        ],
                   expiration)


class ENRRequestMessage(NamedTuple):
    """The encapsulation of enr request packet of the Node Discovery
    Protocol v4 specification.

    packet-data = [expiration]

    When a packet of this type is received, the node should reply with
    an ENRResponse packet containing the current version of its node
    record.
    """

    expiration: int

    TYPE = 0x05

    def __repr__(self) -> str:
        return "enrrequest-packet v4"

    def to_RLP(self) -> list[int]:
        """Converted the enrrequest-packet into a bytes list, easy to
        use RLP expression.

        :return RLP: A list of bytes conforming to the recursive length
            prefix specification.
        """
        return [self.expiration]

    @classmethod
    def from_RLP(cls, payload: list[bytes]) -> "ENRRequestMessage":
        """Decode bytes stream to enrrequest packet and verify.

        :param RLP payload: The RLP bytes stream.
        :return ENRRequestMessage: An object of enrrequest-packet.
        """
        if len(payload) < 1:
            raise ValueError(
                "The length of RLP is not enough to generate a enrrequest"
                " message."
            )
        expiration = int.from_bytes(payload[0], byteorder="big")
        if datetime.utcnow().timestamp() > expiration:
            raise ValueError("The received enrrequest packet has expired.")
        return cls(expiration)


class ENRResponseMessage(NamedTuple):
    """The encapsulation of enr response packet of the Node Discovery
    Protocol v4 specification.

    packet-data = [request-hash, ENR]

    This packet is the response to ENRRequest.

    request-hash is the hash of the entire ENRRequest packet being
        replied to.
    ENR is the node record.

    The recipient of the packet should verify that the node record is
    signed by the public key which signed the response packet.
    """
    request_hash: bytes
    enr: ENR

    TYPE = 0x06

    def __repr__(self) -> str:
        return "enrresponse-packet v4"

    def to_RLP(self) -> list[bytes | list[int | bytes | str]]:
        """Converted the enrresponse-packet into a bytes list, easy to
        use RLP expression.

        :return RLP: A list of bytes conforming to the recursive length
            prefix specification.
        """
        return [self.request_hash, self.enr.to_RLP()]

    @classmethod
    def from_RLP(
        cls, payload: list[bytes | list[bytes]]
    ) -> "ENRResponseMessage":
        """Decode bytes stream to enrresponse packet and verify.

        :param RLP payload: The RLP bytes stream.
        :return NeighboursMessage: An object of enrresponse-packet.
        """
        if len(payload) < 2:
            raise ValueError(
                "The length of RLP is not enough to generate a"
                " enrresponse message."
            )
        if len(payload[1]) > 300:
            raise ValueError(
                "ENR data should be not large than 300 bytes."
            )
        return cls(
            typing.cast(bytes, payload[0]),
            ENR.from_RLP(typing.cast(list[bytes], payload[1]))
        )
