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

import traceback
import time
import logging
import ipaddress
from abc import ABCMeta, abstractmethod

from eth_keys.datatypes import PrivateKey, PublicKey
import trio
from trio import Nursery, Event
from lru import LRU

from ..server import Controller
from ..datatypes import PeerInfo
from .messages import MessageV4, PingMessage, PongMessage
from .messages import FindNeighboursMessage, NeighboursMessage
from .messages import ENRRequestMessage, ENRResponseMessage

logger = logging.getLogger("nodedisc.discv4")
fh = logging.FileHandler("./logs/nodedisc/discv4.log")
fmt = logging.Formatter("%(asctime)s [%(name)s][%(levelname)s] %(message)s")
fh.setFormatter(fmt)
fh.setLevel(logging.INFO)
logger.addHandler(fh)


class ListenerV4(metaclass=ABCMeta):
    """
    """
    async def bind(self, controller: "ControllerV4") -> None:
        self.controller = controller

    @abstractmethod
    async def on_ping_timeout(self, peer: PeerInfo) -> None:
        return NotImplemented

    @abstractmethod
    async def on_pong(self, peer: PeerInfo, id: PublicKey) -> None:
        return NotImplemented
    
    @abstractmethod
    async def on_find_neighbours(self, target: PublicKey) -> None:
        return NotImplemented
    
    @abstractmethod
    async def on_neighbours(self, nodes: list[PeerInfo]) -> None:
        return NotImplemented
    
    @abstractmethod
    async def on_enrresponse(self, enr: bytes) -> None:
        return NotImplemented


class ControllerV4(Controller):
    """
    """
    def __init__(self, base_loop: Nursery, private_key: PrivateKey,
            my_peer: PeerInfo, enr_seq: int, enr: bytes,
            ping_timeout: float) -> None:
        super().__init__(base_loop)
        self.private_key = private_key
        self.my_peer = my_peer
        self.enr_seq = enr_seq
        self.enr = enr
        self.ping_timeout = ping_timeout
        self.listeners: list[ListenerV4] = []
        self.requests: dict[bytes, tuple[PeerInfo, Event]] = {}
        self.last_pong: dict[str, float] = LRU(10000)

    def register_listener(self, listener: ListenerV4) -> None:
        listener.bind(self)

    async def waiting_for_pong(self, ping_hash: bytes) -> None:
        async with trio.move_on_after(self.ping_timeout) as cancel_scope:
            await self.requests[ping_hash][1].wait()
        if cancel_scope.cancelled_caught:
            if self.requests[ping_hash][1].is_set():
                return
            for listener in self.listeners:
                listener.on_ping_timeout(self.requests[ping_hash][0])
            self.requests.pop(ping_hash)

    async def ping(self, peer: PeerInfo) -> None:
        """Send a ping message packet to the designated peer.

        After sending the Ping packet, wait for the pong packet to be
        received. If it is not received over time, it will be processed
        along this function.

        This function is related to the handler function, mainly through
        self.requests to record the ping packet that has been sent. If a
        pong packet is received, the record will be deleted to confirm
        that the pong packet has been received during the timeout
        process.

        :param PeerInfo peer: The designated peer network node.
        """
        msg = PingMessage(self.private_key, self.my_peer, peer)
        bytes_data = msg.to_bytes()
        bytes_hash = bytes_data[:32]
        # Ensure no ping packet sending in a second.
        if bytes_hash in self.requests:
            return
        await self.server.send(peer, bytes_data)
        event = Event()
        self.requests[bytes_hash] = (peer, event)
        self.base_loop.start_soon(self.waiting_for_pong, bytes_hash)
        

    async def find_neighbours(self, peer: PeerInfo, target: PublicKey) -> None:
        """Send a findneighbours message packet to the designated peer.

        :param PeerInfo peer: The designated peer network node.
        :param PublicKey target: The central node id.
        """
        msg = FindNeighboursMessage(self.private_key, target)
        await self.send(peer, msg.to_bytes())

    async def neighbours(self, peer: PeerInfo, nodes: list[PeerInfo]) -> None:
        """Send a neighbours message packet to the designated peer.

        :param PeerInfo peer: The designated peer network node.
        :param list[PeerInfo] nodes: The neighbour peers.
        """
        msg = NeighboursMessage(self.private_key, nodes)
        await self.send(peer, msg.to_bytes())

    async def enr_request(self, peer: PeerInfo) -> None:
        msg = ENRRequestMessage(self.private_key)
        await self.send(peer, msg.to_bytes())

    async def on_message(self, data: bytes, address: tuple[str, int]) -> None:
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

        :param bytes data: Recieved bytes stream.
        :param address Tuple[str, int]: IP address and port.
        """
        ip, port = address
        rckey = f"{ip}:{port}"
        try:
            bytes_hash, msg, public_key = MessageV4.unpack(data)
        except:
            logger.warning(
                "Recieved a packet but couldn't parse successfully. "
                f"From {ip}: {port}. Details: {traceback.format_exc()}"
            )
            return
        logger.info(
            f"Received {msg} from {ip}:{port} (peerId: "
            f"{public_key.to_bytes().hex()[:7]})"
        )
        # handle message
        if isinstance(msg, PingMessage):
            remote = PeerInfo(
                ipaddress.ip_address(ip),
                port,
                msg.from_peer.tcp_port
            )
            await self.server.send(
                remote,
                PongMessage(
                    self.private_key,
                    remote,
                    bytes_hash,
                    self.enr_seq
                ).to_bytes()
            )
            for listener in self.listeners:
                self.base_loop.start_soon(
                    listener.on_pong,
                    remote,
                    public_key
                )
        elif isinstance(msg, PongMessage):
            if msg.ping_hash in self.requests:
                self.requests[msg.ping_hash][1].set()
                self.last_pong[rckey] = time.monotonic() 
                for listener in self.listeners:
                    self.base_loop.start_soon(
                        listener.on_pong,
                        self.requests[msg.ping_hash][0],
                        public_key
                    )
                self.requests.pop(msg.ping_hash)
            else:
                logger.warning(
                    f"Recieved a pong packet from {rckey}, "
                    "but no corresponding ping packet."
                )
        elif isinstance(msg, FindNeighboursMessage):
            if (rckey in self.last_pong 
                and time.monotonic() - self.last_pong[rckey] > 43200):
                return
            for listener in self.listeners:
                self.base_loop.start_soon(
                    listener.on_find_neighbours,
                    msg.target
                )
        elif isinstance(msg, NeighboursMessage):
            for listener in self.listeners:
                self.base_loop.start_soon(
                    listener.on_neighbours,
                    msg.nodes
                )
        elif isinstance(msg, ENRRequestMessage):
            if (rckey in self.last_pong 
                and time.monotonic() - self.last_pong[rckey] > 43200):
                return
            await self.server.send(
                PeerInfo(
                    ipaddress.ip_address(ip),
                    port,
                    0
                ),
                ENRResponseMessage(
                    self.private_key,
                    bytes_hash,
                    self.enr
                ).to_bytes()
            )
        elif isinstance(msg, ENRResponseMessage):
            for listener in self.listeners:
                self.base_loop.start_soon(
                    listener.on_enrresponse,
                    msg.enr
                )