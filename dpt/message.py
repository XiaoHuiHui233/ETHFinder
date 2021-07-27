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
__version__ = "1.10"

import time
import logging
from logging import FileHandler, Formatter
from typing import ClassVar, List, TypeVar, Tuple, Type
from abc import ABCMeta, abstractmethod

import rlp
from rlp.exceptions import DecodingError
from eth_keys import KeyAPI
from eth_keys.datatypes import PrivateKey, PublicKey, Signature
from eth_keys.exceptions import BadSignature
from eth_hash.auto import keccak
from eth_utils import ValidationError

from dpt.classes import PeerNetworkInfo, PeerInfo

RLP = TypeVar("RLP", List[List[bytes]], List[bytes], bytes)

logger = logging.getLogger("dpt.discv4")
fh = FileHandler("./logs/dpt.log")
fmt = Formatter("%(asctime)s [%(name)s][%(levelname)s] %(message)s")
fh.setFormatter(fmt)
fh.setLevel(logging.INFO)
logger.addHandler(fh)


def timestamp() -> bytes:
    """Converts integer UNIX timestamp to bytes.

    :return bytes: UNIX timestamp converted to bytes.
    """
    return int(time.time()) + 60


class DecodeFormatError(Exception):
    """An error indicating that the decoding failed and there is a
    format problem.
    """
    pass


class Message(metaclass=ABCMeta):
    """The base abstract class of the communication packet of the
    Node Discovery Protocol v4 specification.

    See: https://github.com/ethereum/devp2p/blob/master/discv4.md
    """

    MY_SONS: ClassVar[List[Type["Message"]]] = []

    def __init__(self, type_id: int) -> None:
        self.type_id = type_id

    @abstractmethod
    def encode(self) -> RLP:
        """Each subclass of this class should implement this function to
        convert its own information into bytes list which will be
        encoded by the rlp specification.

        :return RLP: A list of bytes conforming to the recursive length
            prefix specification.
        """
        return NotImplemented
    
    def pack(self, private_key: PrivateKey) -> bytes:
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

        :param PrivateKey private_key: Private key.
        """
        packet_data = rlp.encode(self.encode())
        packet_type = int.to_bytes(self.type_id, byteorder="big", length=1)
        sig = KeyAPI().ecdsa_sign(
            keccak(b"".join((packet_type, packet_data))), private_key
        ).to_bytes()
        hash = keccak(b"".join((sig, packet_type, packet_data)))
        return b"".join((hash, sig, packet_type, packet_data))
    
    @classmethod
    def unpack(cls, datas: bytes) -> Tuple[bytes, "Message", PublicKey]:
        """Analyze the received packet according to the packet format.

        Format of bytes stream as following:

        [0, 32) represents data hash.
        [32, 96) represents signature.
        96 represents recoveryId.
        97 represents packet type.
        [98, length) represents packet data.

        :param bytes datas: The bytes stream of recieved packet.
        :return bytes: The hash bytes.
        :return Message: The packet.
        :return PublicKey: The public key from sender.
        :raise DecodeFormatError: If occerred an error when decoding.
        """
        if len(datas) < 98:
            raise DecodeFormatError(
                "Occerred an error because recieved packet is not long enough."
            )
        new_hash_bytes = keccak(datas[32:])
        raw_hash_bytes = datas[:32]
        type_id = datas[97]
        if raw_hash_bytes != new_hash_bytes:
            raise DecodeFormatError(
                f"Hash verification failed on type {type_id}: "
                f"{raw_hash_bytes.hex()[:7]} / {new_hash_bytes.hex()[:7]}"
            )
        packet_data = datas[98:]
        try:
            msg = Message.MY_SONS[type_id - 1].decode(rlp.decode(packet_data, strict=False))
        except DecodingError as err:
            raise DecodeFormatError(
                "Occerred an error when rlp decoding. "
                f"Detail: {err}"
            )
        except ValueError as err:
            raise DecodeFormatError(
                "Occerred an error when message decoding. "
                f"Detail: {err}"
            )
        sig_hash = keccak(datas[97:])
        signature = Signature(datas[32: 97])
        try:
            public_key = KeyAPI().ecdsa_recover(sig_hash, signature)
        except ValidationError as err:
            raise DecodeFormatError(
                "Occerred an error when recovering public key. "
                f"Detail: {err}"
            )
        except BadSignature as err:
            raise DecodeFormatError(
                "Occerred an error when recovering public key. "
                f"Detail: {err}"
            )
        return raw_hash_bytes, msg, public_key


class PingMessage(Message):
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
    This field is optional. So we did not implement it.

    See: https://github.com/ethereum/devp2p/blob/master/discv4.md
    """

    VERSION = 0x04

    def __init__(self, from_peer: PeerNetworkInfo,
            to_peer: PeerNetworkInfo) -> None:
        super().__init__(0x01)
        self.from_peer = from_peer
        self.to_peer = to_peer

    def __repr__(self) -> str:
        return "ping-packet"
    
    def encode(self) -> RLP:
        """Converted the ping-packet into a bytes list, easy to use RLP
        expression.

        :return RLP: A list of bytes conforming to the recursive length
            prefix specification.
        """
        from_bytes = self.from_peer.encode()[:3]
        to_bytes = self.to_peer.encode()[:3]
        return [PingMessage.VERSION, from_bytes, to_bytes, timestamp()]
    
    @classmethod
    def decode(cls, payload: RLP) -> "PingMessage":
        """Decode bytes stream to ping packet and verify.

        :param RLP payload: The RLP bytes stream.
        :return PingMessage: An object of ping-packet.
        :raise DecodeFormatError: If occerred an error when decoding.
        """
        if len(payload) < 4:
            raise DecodeFormatError(
                "The length of RLP is not enough to generate a ping message."
            )
        expiration = int.from_bytes(payload[3], byteorder="big")
        if time.time() > expiration:
            raise DecodeFormatError("The received ping packet has expired.")
        version = int.from_bytes(payload[0], byteorder="big")
        if version != PingMessage.VERSION:
            raise DecodeFormatError(
                f"Recieved ping packet version: {version}. But we expect "
                f"{PingMessage.VERSION}."
            )
        return cls(
            PeerNetworkInfo.decode(payload[1]),
            PeerNetworkInfo.decode(payload[2])
        )


class PongMessage(Message):
    """The encapsulation of pong packet of the Node Discovery Protocol
    v4 specification.

    packet-data = [to, ping-hash, expiration, enr-seq, ...]
    
    Pong is the reply to ping.

    ping-hash should be equal to hash of the corresponding ping packet.
    Implementations should ignore unsolicited pong packets that do not
    contain the hash of the most recent ping packet.

    The enr-seq field is the current ENR sequence number of the sender.
    This field is optional. So we did not implement it.
    """

    def __init__(self, to: PeerNetworkInfo, ping_hash: bytes) -> None:
        super().__init__(0x02)
        self.to = to
        self.ping_hash = ping_hash

    def __repr__(self) -> str:
        return "pong-packet"

    def encode(self) -> RLP:
        """Converted the pong-packet into a bytes list, easy to use RLP
        expression.

        :return RLP: A list of bytes conforming to the recursive length
            prefix specification.
        """
        to_bytes = self.to.encode()[:3]
        return [to_bytes, self.ping_hash, timestamp()]
    
    @classmethod
    def decode(cls, payload: RLP) -> "PongMessage":
        """Decode bytes stream to pong packet and verify.

        :param RLP payload: The RLP bytes stream.
        :return PongMessage: An object of pong-packet.
        :raise DecodeFormatError: If occerred an error when decoding.
        """
        if len(payload) < 3:
            raise DecodeFormatError(
                "The length of RLP is not enough to generate a pong message."
            )
        expiration = int.from_bytes(payload[2], byteorder="big")
        if time.time() > expiration:
            raise DecodeFormatError(f"The received pong packet has expired.")
        return cls(
            PeerNetworkInfo.decode(payload[0]),
            payload[1]
        )


class FindNeighboursMessage(Message):
    """The encapsulation of findneighbours packet of the Node Discovery
    Protocol v4 specification.

    packet-data = [target, expiration, ...]

    A FindNode packet requests information about nodes close to target.
    The target is a 65-byte secp256k1 public key. When FindNode is
    received, the recipient should reply with Neighbors packets
    containing the closest 16 nodes to target found in its local table.
    """

    def __init__(self, target: PublicKey) -> None:
        super().__init__(0x03)
        self.target = target
    
    def __repr__(self) -> str:
        return "findneighbours-packet"
    
    def encode(self) -> RLP:
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
        :raise DecodeFormatError: If occerred an error when decoding.
        """
        if len(payload) < 2:
            raise DecodeFormatError(
                "The length of RLP is not enough to generate a findneighbours"
                " message."
            )
        expiration = int.from_bytes(payload[1], byteorder="big")
        if time.time() > expiration:
            raise DecodeFormatError(
                "The received findneighbours packet has expired."
            )
        return cls(PublicKey(payload[0]))


class NeighboursMessage(Message):
    """The encapsulation of neighbours packet of the Node Discovery
    Protocol v4 specification.

    packet-data = [nodes, expiration, ...]
    nodes = [[ip, udp-port, tcp-port, node-id], ...]

    Neighbors is the reply to FindNode.
    """

    def __init__(self, peers: List[PeerInfo]) -> None:
        super().__init__(0x04)
        self.peers = peers

    def __repr__(self) -> str:
        return "neighbours-packet"
    
    def encode(self) -> RLP:
        """Converted the neighbour-packet into a bytes list, easy to
        use RLP expression.

        :return RLP: A list of bytes conforming to the recursive length
            prefix specification.
        """
        return [[peer.encode() for peer in self.peers], timestamp()]
    
    @classmethod
    def decode(cls, payload: RLP) -> "NeighboursMessage":
        """Decode bytes stream to neighbours packet and verify.

        :param RLP payload: The RLP bytes stream.
        :return NeighboursMessage: An object of neighbours-packet.
        :raise DecodeFormatError: If occerred an error when decoding.
        """
        if len(payload) < 2:
            raise DecodeFormatError(
                "The length of RLP is not enough to generate a neighbours"
                " message."
            )
        expiration = int.from_bytes(payload[1], byteorder="big")
        if time.time() > expiration:
            raise DecodeFormatError(
                "The received neighbours packet has expired."
            )
        return cls(
            [PeerInfo.decode(payload) for payload in payload[0]]
        )


Message.MY_SONS = [
    PingMessage,
    PongMessage,
    FindNeighboursMessage,
    NeighboursMessage,
    # ENRRequestMessage,
    # ENRResponseMessage
]