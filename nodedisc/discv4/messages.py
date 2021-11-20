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
__version__ = "2.1"

import time
from ipaddress import IPv4Address, IPv6Address
from typing import Union
from abc import abstractmethod

import rlp
from eth_keys import KeyAPI
from eth_keys.datatypes import PrivateKey, PublicKey, Signature
from eth_hash.auto import keccak

from ..datatypes import Message, PeerInfo

IPAddress = Union[IPv4Address, IPv6Address]
RLP = Union[list[list[bytes]], list[bytes], bytes]


def timestamp() -> bytes:
    """Converts integer UNIX timestamp to bytes.

    :return bytes: UNIX timestamp converted to bytes.
    """
    return int(time.time()) + 60


class MessageV4(Message):
    """The base abstract class of the communication packet of the
    Node Discovery Protocol v4.
    """
    def __init__(self, private_key: PrivateKey, type_id: int) -> None:
        self.private_key = private_key
        self.type_id = type_id

    def to_bytes(self) -> bytes:
        """Encapsulate the communication packet according to the
        specification in Node Discovery Protocol v4.

        Node discovery messages are sent as UDP datagrams. The maximum
        size of any packet is 1280 bytes.

        packet = packet-header || packet-data

        Every packet starts with a header:

        packet-header = hash || signature || packet-type
        hash = keccak256(signature || packet-type || packet-data)
        signature = sign(packet-type || packet-data)

        The hash exists to make the packet format recognizable when
        running multiple protocols on the same UDP port. It serves no
        other purpose.

        Every packet is signed by the node's identity key. The signature
        is encoded as a byte array of length 65 as the concatenation of
        the signature values r, s and the 'recovery id' v.

        The packet-type is a single byte defining the type of message.
        Valid packet types are listed below. Data after the header is
        specific to the packet type and is encoded as an RLP list.
        Implementations should ignore any additional elements in the
        packet-data list as well as any extra data after the list.

        See: https://github.com/ethereum/devp2p/blob/master/discv4.md
        """
        packet_data = rlp.encode(self.to_RLP())
        packet_type = int.to_bytes(self.type_id, byteorder="big", length=1)
        sig = KeyAPI().ecdsa_sign(
            keccak(b"".join((packet_type, packet_data))), self.private_key
        ).to_bytes()
        hash = keccak(b"".join((sig, packet_type, packet_data)))
        return b"".join((hash, sig, packet_type, packet_data))

    @abstractmethod
    def to_RLP(self) -> RLP:
        """Each subclass should implement this function to convert
        its own information into RLP.

        :return RLP: A recursive length prefix.
        """
        return NotImplemented

    @classmethod
    def unpack(cls, datas: bytes) -> tuple[bytes, "MessageV4", PublicKey]:
        """Analyze the received packet according to the packet format.

        The format of bytes stream as following:

        [0, 32) represents data hash.
        [32, 96) represents signature.
        96 represents recoveryId.
        97 represents packet type.
        [98, length) represents packet data.

        :param bytes datas: The bytes stream of recieved packet.
        :return bytes: The hash bytes.
        :return Message: The packet.
        :return PublicKey: The public key from sender.
        """
        if len(datas) < 98:
            raise ValueError("Packet size is not large enough.")
        new_hash_bytes = keccak(datas[32:])
        raw_hash_bytes = datas[:32]
        type_id = datas[97]
        if raw_hash_bytes != new_hash_bytes:
            raise ValueError("Packet hash verification failed.")
        packet_data = datas[98:]
        msg = MessageV4.MESSAGES[type_id - 1].decode(
            rlp.decode(packet_data, strict=False)
        )
        sig_hash = keccak(datas[97:])
        signature = Signature(datas[32:97])
        public_key = KeyAPI().ecdsa_recover(sig_hash, signature)
        return raw_hash_bytes, msg, public_key


class PingMessage(MessageV4):
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
    VERSION = 0x04

    def __init__(
        self,
        private_key: PrivateKey,
        from_peer: PeerInfo,
        to_peer: PeerInfo,
        enr_seq: int = 1
    ) -> None:
        super().__init__(private_key, 0x01)
        self.from_peer = from_peer
        self.to_peer = to_peer
        self.enr_seq = enr_seq

    def __repr__(self) -> str:
        return "ping-packet v4"

    def to_RLP(self) -> RLP:
        """Converted the ping-packet into a bytes list, easy to use RLP
        expression.

        :return RLP: A list of bytes conforming to the recursive length
            prefix specification.
        """
        return [
            PingMessage.VERSION,
            self.from_peer.to_RLP(),
            self.to_peer.to_RLP(),
            timestamp(),  # int.to_bytes(self.enr_seq, 8, "big", signed=False)
        ]

    @classmethod
    def decode(cls, payload: RLP) -> "PingMessage":
        """Decode bytes stream to ping packet and verify.

        :param RLP payload: The RLP bytes stream.
        :return PingMessage: An object of ping-packet.
        """
        if len(payload) < 4:
            raise ValueError(
                "The elements in RLP is not enough to generate a ping message."
            )
        expiration = int.from_bytes(payload[3], byteorder="big")
        if time.time() > expiration:
            raise ValueError("The received ping packet has expired.")
        version = int.from_bytes(payload[0], byteorder="big")
        if version != PingMessage.VERSION:
            raise ValueError(f"Ping message version {version} is unsupported.")
        if len(payload) >= 5:
            return cls(
                None,
                PeerInfo.decode(payload[1]),
                PeerInfo.decode(payload[2]),
                int.from_bytes(payload[4], "big")
            )
        else:
            return cls(
                None, PeerInfo.decode(payload[1]), PeerInfo.decode(payload[2])
            )


class PongMessage(MessageV4):
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
    def __init__(
        self,
        private_key: PrivateKey,
        to_peer: PeerInfo,
        ping_hash: bytes,
        enr_seq: int = 0
    ) -> None:
        super().__init__(private_key, 0x02)
        self.to_peer = to_peer
        self.ping_hash = ping_hash
        self.enr_seq = enr_seq

    def __repr__(self) -> str:
        return "pong-packet v4"

    def to_RLP(self) -> RLP:
        """Converted the pong-packet into a bytes list, easy to use RLP
        expression.

        :return RLP: A list of bytes conforming to the recursive length
            prefix specification.
        """
        return [
            self.to_peer.to_RLP(),
            self.ping_hash,
            timestamp(),  # int.to_bytes(self.enr_seq, 8, "big", signed=False)
        ]

    @classmethod
    def decode(cls, payload: RLP) -> "PongMessage":
        """Decode bytes stream to pong packet and verify.

        :param RLP payload: The RLP bytes stream.
        :return PongMessage: An object of pong-packet.
        """
        if len(payload) < 3:
            raise ValueError(
                "The elements in RLP is not enough to generate a pong message."
            )
        expiration = int.from_bytes(payload[2], byteorder="big")
        if time.time() > expiration:
            raise ValueError("The received pong packet has expired.")
        if len(payload) >= 4:
            return cls(
                None,
                PeerInfo.decode(payload[0]),
                payload[1],
                int.from_bytes(payload[3], "big")
            )
        else:
            return cls(None, PeerInfo.decode(payload[0]), payload[1])


class FindNeighboursMessage(MessageV4):
    """The encapsulation of findneighbours packet of the Node Discovery
    Protocol v4 specification.

    packet-data = [target, expiration, ...]

    A FindNode packet requests information about nodes close to target.
    The target is a 65-byte secp256k1 public key. When FindNode is
    received, the recipient should reply with Neighbors packets
    containing the closest 16 nodes to target found in its local table.
    """
    def __init__(self, private_key: PrivateKey, target: PublicKey) -> None:
        super().__init__(private_key, 0x03)
        self.target = target

    def __repr__(self) -> str:
        return "findneighbours-packet v4"

    def to_RLP(self) -> RLP:
        """Converted the findneighbour-packet into a bytes list, easy to
        use RLP expression.

        :return RLP: A list of bytes conforming to the recursive length
            prefix specification.
        """
        return [self.target.to_bytes(), timestamp()]

    @classmethod
    def decode(cls, payload: RLP) -> "FindNeighboursMessage":
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
        if time.time() > expiration:
            raise ValueError("The received findneighbours packet has expired.")
        return cls(None, PublicKey(payload[0]))


class NeighboursMessage(MessageV4):
    """The encapsulation of neighbours packet of the Node Discovery
    Protocol v4 specification.

    packet-data = [nodes, expiration, ...]
    nodes = [[ip, udp-port, tcp-port, node-id], ...]

    Neighbors is the reply to FindNode.
    """
    def __init__(self, private_key: PrivateKey, nodes: list[PeerInfo]) -> None:
        super().__init__(private_key, 0x04)
        self.nodes = nodes

    def __repr__(self) -> str:
        return "neighbours-packet v4"

    def to_RLP(self) -> RLP:
        """Converted the neighbour-packet into a bytes list, easy to
        use RLP expression.

        :return RLP: A list of bytes conforming to the recursive length
            prefix specification.
        """
        return [[peer.to_RLP() for peer in self.nodes], timestamp()]

    @classmethod
    def decode(cls, payload: RLP) -> "NeighboursMessage":
        """Decode bytes stream to neighbours packet and verify.

        :param RLP payload: The RLP bytes stream.
        :return NeighboursMessage: An object of neighbours-packet.
        """
        if len(payload) < 2:
            raise ValueError(
                "The length of RLP is not enough to generate a neighbours"
                " message."
            )
        expiration = int.from_bytes(payload[1], byteorder="big")
        if time.time() > expiration:
            raise ValueError("The received neighbours packet has expired.")
        return cls(None, [PeerInfo.decode(data) for data in payload[0]])


class ENRRequestMessage(MessageV4):
    """The encapsulation of enr request packet of the Node Discovery
    Protocol v4 specification.

    packet-data = [expiration]

    When a packet of this type is received, the node should reply with
    an ENRResponse packet containing the current version of its node
    record.
    """
    def __init__(self, private_key: PrivateKey) -> None:
        super().__init__(private_key, 0x05)

    def __repr__(self) -> str:
        return "enrrequest-packet v4"

    def to_RLP(self) -> RLP:
        """Converted the enrrequest-packet into a bytes list, easy to
        use RLP expression.

        :return RLP: A list of bytes conforming to the recursive length
            prefix specification.
        """
        return [timestamp()]

    @classmethod
    def decode(cls, payload: RLP) -> "ENRRequestMessage":
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
        if time.time() > expiration:
            raise ValueError("The received enrrequest packet has expired.")
        return cls(None)


class ENRResponseMessage(MessageV4):
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
    def __init__(
        self, private_key: PrivateKey, request_hash: bytes, enr: bytes
    ) -> None:
        super().__init__(private_key, 0x06)
        self.request_hash = request_hash
        self.enr = enr

    def __repr__(self) -> str:
        return "enrresponse-packet v4"

    def to_RLP(self) -> RLP:
        """Converted the enrresponse-packet into a bytes list, easy to
        use RLP expression.

        :return RLP: A list of bytes conforming to the recursive length
            prefix specification.
        """
        return [self.request_hash, self.enr]

    @classmethod
    def decode(cls, payload: RLP) -> "ENRResponseMessage":
        """Decode bytes stream to enrresponse packet and verify.

        :param RLP payload: The RLP bytes stream.
        :return NeighboursMessage: An object of enrresponse-packet.
        """
        if len(payload) < 2:
            raise ValueError(
                "The length of RLP is not enough to generate a"
                " enrresponse message."
            )
        return cls(None, payload[0], payload[1])


MessageV4.MESSAGES = [
    PingMessage,
    PongMessage,
    FindNeighboursMessage,
    NeighboursMessage,
    ENRRequestMessage,
    ENRResponseMessage
]
