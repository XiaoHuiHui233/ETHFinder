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

import abc
import asyncio
import logging
import traceback
import typing
from abc import ABCMeta
from datetime import datetime
from typing import Optional

import rlp
from enr.datatypes import ENR
from eth_hash.auto import keccak
from eth_keys.datatypes import PrivateKey, PublicKey, Signature
from eth_keys.main import KeyAPI
from lru import LRU

from ..datatypes import Addr, Node, Peer
from ..server import Controller
from ..utils import Promise
from .messages import (ENRRequestMessage, ENRResponseMessage, FindNodeMessage,
                       NeighboursMessage, PingMessage, PongMessage)

logger = logging.getLogger("nodedisc.discv4")

TIMEOUT = 5

T1 = PingMessage | PongMessage | FindNodeMessage
T2 = NeighboursMessage | ENRRequestMessage | ENRResponseMessage
T = T1 | T2

MESSAGES = [
    PingMessage,
    PongMessage,
    FindNodeMessage,
    NeighboursMessage,
    ENRRequestMessage,
    ENRResponseMessage
]


def now() -> int:
    return int(datetime.utcnow().timestamp())


def pack(data: T, prikey: PrivateKey) -> bytes:
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
    packet_data: bytes = rlp.encode(data.to_RLP())  # type: ignore
    packet_type = int.to_bytes(data.TYPE, byteorder="big", length=1)
    sig = KeyAPI().ecdsa_sign(
        keccak(b"".join((packet_type, packet_data))), prikey
    ).to_bytes()
    hash = keccak(b"".join((sig, packet_type, packet_data)))
    return b"".join((hash, sig, packet_type, packet_data))


def unpack(datas: bytes) -> tuple[bytes, T, PublicKey]:
    """Analyze the received packet according to the packet format.

    The format of bytes stream as following:

    [0, 32) represents data hash.
    [32, 96) represents signature.
    96 represents recoveryId.
    97 represents packet type.
    [98, length) represents packet data.

    :param bytes datas: The bytes stream of received packet.
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
    msg = MESSAGES[type_id - 1].from_RLP(  # type: ignore
        rlp.decode(packet_data, strict=False)  # type: ignore
    )
    sig_hash = keccak(datas[97:])
    signature = Signature(datas[32:97])
    public_key = KeyAPI().ecdsa_recover(sig_hash, signature)
    return raw_hash_bytes, msg, public_key


class ListenerV4(metaclass=ABCMeta):
    @abc.abstractmethod
    def on_node(self, node: Node, enr_seq: Optional[int]) -> None:
        raise NotImplementedError()

    @abc.abstractmethod
    def on_reply(self, id: PublicKey, addr: Addr) -> None:
        raise NotImplementedError()

    @abc.abstractmethod
    def get_nodes(self, target: PublicKey) -> list[Node]:
        raise NotImplementedError()

    @abc.abstractmethod
    def on_nodes(self, nodes: list[Node]) -> None:
        raise NotImplementedError()

    @abc.abstractmethod
    def on_enr(self, id: PublicKey, enr: ENR) -> None:
        raise NotImplementedError()

    @abc.abstractmethod
    def on_timeout(self, id: PublicKey) -> None:
        raise NotImplementedError()


class ControllerV4(Controller):
    """
    """
    def __init__(
        self,
        private_key: PrivateKey,
        me: ENR
    ) -> None:
        self.private_key = private_key
        self.me = me
        self.listeners: list[ListenerV4] = []
        self.enr_requests: dict[int, PublicKey] = LRU(10000)
        self.pinging: dict[Addr, bool] = LRU(10000)
        self.pings: dict[int, Addr] = LRU(10000)
        self.ping_events: dict[int, Promise[bool]] = LRU(10000)
        self.last_meets: dict[PublicKey, int] = LRU(10000)
        self.ban_list: dict[Addr, int] = LRU(10000)

    def register_listener(self, listener: ListenerV4) -> None:
        self.listeners.append(listener)

    def ban(self, addr: Addr) -> None:
        self.ban_list[addr] = now()

    def has_banned(self, addr: Addr) -> bool:
        if addr in self.ban_list:
            last_time = self.ban_list[addr]
            if now() - last_time > 600:
                self.ban_list.pop(addr)
        return addr in self.ban_list

    def timeout(self, id: PublicKey, addr: Addr) -> None:
        self.ban(addr)
        for listener in self.listeners:
            listener.on_timeout(id)

    def send(self, msg: T, addr: Addr) -> bytes:
        logger.debug(f"Send {msg} to {addr}.")
        data = pack(msg, self.private_key)
        self.server.send(data, addr)
        return data[:32]

    def check_endpoint_proof(self, id: PublicKey) -> bool:
        return id in self.last_meets and now() - self.last_meets[id] <= 43200

    async def wait_endpoint_proof(self, id: PublicKey, remote: Addr) -> bool:
        if self.check_endpoint_proof(id):
            return True
        if remote in self.pinging:
            await asyncio.sleep(TIMEOUT)
            return self.check_endpoint_proof(id)
        promise = await self.waitable_ping(remote)
        if promise is None:
            return False
        return await promise.wait_and_get()

    def update_endpoint_proof(self, id: PublicKey) -> None:
        self.last_meets[id] = now()

    async def ping_timeout(self, hash: int, addr: Addr) -> None:
        await asyncio.sleep(TIMEOUT)
        if hash not in self.pings:
            return
        assert hash in self.ping_events
        assert addr in self.pinging
        if not self.ping_events[hash].is_set():
            self.ping_events[hash].set(False)
        self.pings.pop(hash)
        self.ping_events.pop(hash)
        self.pinging.pop(addr)

    async def waitable_ping(self, addr: Addr) -> Optional[Promise[bool]]:
        if self.has_banned(addr):
            return None
        msg = PingMessage(
            0x04, Peer.from_ENR(self.me), addr, now()+60, self.me.seq
        )
        msg_hash = self.send(msg, addr)
        h = hash((msg_hash, addr))
        self.pings[h] = addr
        self.ping_events[h] = promise = Promise[bool]()
        self.pinging[addr] = True
        asyncio.create_task(self.ping_timeout(h, addr))
        return promise

    def ping(self, addr: Addr) -> None:
        """Send a ping message packet to the designated peer.

        After sending the Ping packet, wait for the pong packet to be
        received. If it is not received over time, it will be processed
        along this function.

        This function is related to the handler function, mainly through
        self.requests to record the ping packet that has been sent. If a
        pong packet is received, the record will be deleted to confirm
        that the pong packet has been received during the timeout
        process.
        """
        if self.has_banned(addr):
            return
        if addr in self.pinging:
            return
        asyncio.create_task(self.waitable_ping(addr))

    def pong(self, ping_hash: bytes, addr: Addr) -> None:
        if self.has_banned(addr):
            return
        msg = PongMessage(addr, ping_hash, now()+60, self.me.seq)
        self.send(msg, addr)

    async def waitable_find_node(
        self, target: PublicKey, id: PublicKey, addr: Addr
    ) -> None:
        if self.has_banned(addr):
            return None
        if await self.wait_endpoint_proof(id, addr):
            msg = FindNodeMessage(target, now()+60)
            self.send(msg, addr)
        else:
            self.timeout(id, addr)

    def find_node(
        self, target: PublicKey, id: PublicKey, addr: Addr
    ) -> None:
        """Send a findneighbours message packet to the designated peer.
        """
        if self.has_banned(addr):
            return
        asyncio.create_task(
            self.waitable_find_node(target, id, addr)
        )

    def neighbours(self, nodes: list[Node], addr: Addr) -> None:
        """Send a neighbours message packet to the designated peer.
        """
        if self.has_banned(addr):
            return
        msg = NeighboursMessage(nodes, now()+60)
        self.send(msg, addr)

    async def waitable_enr_request(self, id: PublicKey, addr: Addr) -> None:
        if self.has_banned(addr):
            return None
        if await self.wait_endpoint_proof(id, addr):
            msg = ENRRequestMessage(now()+60)
            msg_hash = self.send(msg, addr)
            h = hash((msg_hash, addr))
            self.enr_requests[h] = id
        else:
            self.timeout(id, addr)

    def enr_request(self, id: PublicKey, addr: Addr) -> None:
        if self.has_banned(addr):
            return
        asyncio.create_task(self.waitable_enr_request(id, addr))

    def enr_response(self, req_hash: bytes, addr: Addr) -> None:
        if self.has_banned(addr):
            return
        msg = ENRResponseMessage(req_hash, self.me)
        self.send(msg, addr)

    def on_ping(
        self, hash: bytes, msg: PingMessage, id: PublicKey, addr: Addr
    ) -> None:
        remote = msg.from_peer
        if remote.address != addr.address or remote.udp_port != addr.udp_port:
            logger.warning(
                "The address recorded doesn't match actual address. "
                f"Recorded: {remote}, Actual: {addr}."
            )
            return
        self.pong(hash, addr)
        if not self.check_endpoint_proof(id):
            self.ping(addr)
        node = Node(remote.address, remote.udp_port, remote.tcp_port, id)
        for listener in self.listeners:
            try:
                listener.on_node(node, msg.enr_seq)
            except Exception:
                logger.error(
                    f"Error on calling on_node to listener.\n"
                    f"Detail: {traceback.format_exc()}"
                )

    def on_pong(self, msg: PongMessage, id: PublicKey, addr: Addr) -> None:
        h = hash((msg.ping_hash, addr))
        if h not in self.pings:
            logger.warning(
                f"received a pong packet from {addr}, but no corresponding "
                "ping packet."
            )
            return
        remote = self.pings.pop(h)
        assert remote in self.pinging
        self.pinging.pop(remote)
        assert h in self.ping_events
        flag = True
        if self.ping_events[h].is_set():
            logger.warning(f"The pong of {addr} is timeout, drop it.")
            flag = False
        else:
            if remote != addr:
                logger.warning(
                    "The address recorded doesn't match actual address. "
                    f"Recorded: {remote}, Actual: {addr}."
                )
                flag = False
            self.ping_events[h].set(remote == addr)
            self.ping_events.pop(h)
        if flag:
            self.update_endpoint_proof(id)
            for listener in self.listeners:
                try:
                    listener.on_reply(id, addr)
                except Exception:
                    logger.error(
                        f"Error on calling on_reply to listener.\n"
                        f"Detail: {traceback.format_exc()}"
                    )

    def on_find(self, msg: FindNodeMessage, id: PublicKey, addr: Addr) -> None:
        if not self.check_endpoint_proof(id):
            logger.warning(
                f"The peer {addr}(Id:{id.to_bytes().hex()[:7]}) "
                "doesn't have endpoint proof but call findnode."
            )
            return
        result: list[Node] = []
        for listener in self.listeners:
            try:
                result += listener.get_nodes(msg.target)
            except Exception:
                logger.error(
                    f"Error on calling get_nodes to listener.\n"
                    f"Detail: {traceback.format_exc()}"
                )
        self.neighbours(result[:16], addr)

    def on_node(self, msg: NeighboursMessage) -> None:
        for listener in self.listeners:
            try:
                listener.on_nodes(msg.nodes)
            except Exception:
                logger.error(
                    f"Error on calling on_nodes to listener.\n"
                    f"Detail: {traceback.format_exc()}"
                )

    def on_enr_req(self, hash: bytes, id: PublicKey, addr: Addr) -> None:
        if not self.check_endpoint_proof(id):
            logger.warning(
                f"The peer {addr}(Id:{id.to_bytes().hex()[:7]}) "
                "doesn't have endpoint proof but call enr_req."
            )
            return
        self.enr_response(hash, addr)

    def on_enr(self, msg: ENRResponseMessage, addr: Addr) -> None:
        h = hash((msg.request_hash, addr))
        if h not in self.enr_requests:
            logger.warning(
                f"received a enrresponse packet from {addr}, "
                "but no corresponding enrrequest packet."
            )
            return
        id = self.enr_requests.pop(h)
        for listener in self.listeners:
            try:
                listener.on_enr(id, msg.enr)
            except Exception:
                logger.error(
                    f"Error on calling on_enr to listener.\n"
                    f"Detail: {traceback.format_exc()}"
                )

    def on_message(self, data: bytes, addr: Addr) -> None:
        """Decode the received UDP packets and classify them for
        processing.

        When a ping packet is received, the recipient should reply with a
        Pong packet. It may also consider the sender for addition into the
        local table. Implementations should ignore any mismatches in
        version.

        If no communication with the sender has occurred within the last
        12h, a ping should be sent in addition to pong in order to receive
        an endpoint proof.

        To guard against traffic amplification attacks, Neighbors replies
        should only be sent if the sender of FindNode has been verified by
        the endpoint proof procedure.

        See: https://github.com/ethereum/devp2p/blob/master/discv4.md
        """
        if self.has_banned(addr):
            return
        try:
            hash, msg, pubkey = unpack(data)
        except Exception:
            logger.error(
                f"Error on parsing a packet from {addr}.\n"
                f"Details: {traceback.format_exc()}"
            )
            self.ban(addr)
            return
        logger.debug(
            f"Received {msg} from {addr}"
            f"(peerId: {pubkey.to_bytes().hex()[:7]})"
        )
        match msg.TYPE:
            case 0x01:
                msg = typing.cast(PingMessage, msg)
                self.on_ping(hash, msg, pubkey, addr)
            case 0x02:
                msg = typing.cast(PongMessage, msg)
                self.on_pong(msg, pubkey, addr)
            case 0x03:
                msg = typing.cast(FindNodeMessage, msg)
                self.on_find(msg, pubkey, addr)
            case 0x04:
                msg = typing.cast(NeighboursMessage, msg)
                self.on_node(msg)
            case 0x05:
                msg = typing.cast(ENRRequestMessage, msg)
                self.on_enr_req(hash, pubkey, addr)
            case 0x06:
                msg = typing.cast(ENRResponseMessage, msg)
                self.on_enr(msg, addr)
