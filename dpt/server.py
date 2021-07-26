#!/usr/bin/env python
# -*- codeing:utf-8 -*-

"""Use coroutine UDP socket to realize the network communication part of
Node Discovery Protocol v4.

See: https://github.com/ethereum/devp2p/blob/master/discv4.md
"""

__author__ = "XiaoHuiHui"
__version__ = "1.8"

import ipaddress
import time
import logging
from logging import FileHandler, Formatter
from ipaddress import IPv4Address, IPv6Address
from typing import Tuple, TypeVar, Coroutine, List, Dict
from abc import ABCMeta, abstractmethod

import trio
from trio import socket
from lru import LRU
from eth_keys.datatypes import PrivateKey, PublicKey

import config as opts
from dpt.message import Message, PingMessage, PongMessage
from dpt.message import FindNeighboursMessage, NeighboursMessage
from dpt.message import DecodeFormatError
from dpt.classes import PeerNetworkInfo, PeerInfo

BUFF_SIZE = 1280

IPAddress = TypeVar("IPAddress", IPv4Address, IPv6Address)

logger = logging.getLogger("dpt.discv4")
fh = FileHandler("./logs/dpt.log")
fmt = Formatter("%(asctime)s [%(name)s][%(levelname)s] %(message)s")
fh.setFormatter(fmt)
fh.setLevel(logging.INFO)
logger.addHandler(fh)

class ServerListener(metaclass=ABCMeta):
    """
    """

    @abstractmethod
    async def on_recieved_ping(self, peer: PeerInfo) -> Coroutine:
        return NotImplemented

    @abstractmethod
    def on_ping_timeout(self, peer: PeerNetworkInfo) -> None:
        return NotImplemented
    
    @abstractmethod
    async def on_recieved_pong(self, peer: PeerInfo) -> Coroutine:
        return NotImplemented
    
    @abstractmethod
    def on_recieved_findneighbours(self, id: PublicKey) -> List[PeerInfo]:
        return NotImplemented
    
    @abstractmethod
    async def on_recieved_neighbours(self, peers: List[PeerInfo]) -> Coroutine:
        return NotImplemented


class ServerIsDeadError(Exception):
    """An error indicating that the socket has been closed."""
    pass


class Server:
    """A UDP socket peer implemented based on the network communication
    defined by the Node Discovery Protocol v4.

    See: https://github.com/ethereum/devp2p/blob/master/discv4.md
    """

    def __init__(self, private_key: PrivateKey,
            listener: ServerListener) -> None:
        self.private_key = private_key
        self.listener = listener
        self.server = None
        self.requests: Dict[bytes, PeerNetworkInfo] = {}
        self.timer: Dict[bytes, int] = {}
        self.last_pong = LRU(1000)

    def __del__(self) -> None:
        if self.server:
            self.server = None
    
    async def bind(self) -> Coroutine:
        """Bind local listening ip and port to UDP socket."""
        self.server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        await self.server.bind(
            (str(opts.SERVER_ENDPOINT.address), opts.SERVER_ENDPOINT.udp_port)
        )
        logger.info(
            f"Server on bind {opts.SERVER_ENDPOINT.address}:"
            f"{opts.SERVER_ENDPOINT.udp_port}"
        )
    
    async def recv_loop(self) -> Coroutine:
        """Receiving the information obtained by the UDP listening port
        in a cyclic blocking mode.

        Thanks to trio, we can use asynchronous coroutines to achieve
        this, which greatly improves efficiency.
        """
        async with trio.open_nursery() as recv_loop:
            while self.server is not None:
                data, address = await self.server.recvfrom(BUFF_SIZE)
                recv_loop.start_soon(self.handle, data, address)
    
    def is_alive(self) -> None:
        """Check if the socket is still alive, and raise an exception if
        it is not alive.

        :raise ServerIsDeadError: If the socket is not alive.
        """
        if self.server is None:
            raise ServerIsDeadError("Server has been already destroyed.")

    async def send(self, peer: PeerNetworkInfo, msg: Message) -> Coroutine:
        """Send a message packet to the designated peer network node.

        :param PeerNetworkInfo peer: The designated peer network node.
        :param Message data: The message packet.
        :return bytes: The hash bytes of this msg.
        """
        bytes = msg.pack(self.private_key)
        hash = bytes[:32]
        if hash in self.requests:
            logger.warning(
                "There is already a ping packet having same timestamp in "
                "request list."
            )
            return hash
        self.is_alive()
        logger.debug(
            f"Send packet type {msg} to "
            f"{peer.address}:{peer.udp_port} (peerId: {peer})"
        )
        await self.server.sendto(bytes, (str(peer.address), peer.udp_port))
        return hash

    async def ping(self, peer: PeerNetworkInfo) -> Coroutine:
        """Send a ping message packet to the designated peer.

        After sending the Ping packet, wait for the pong packet to be
        received. If it is not received over time, it will be processed
        along this function.

        This function is related to the handler function, mainly through
        self.requests to record the ping packet that has been sent. If a
        pong packet is received, the record will be deleted to confirm
        that the pong packet has been received during the timeout
        process.

        :param PeerNetworkInfo peer: The designated peer network node.
        """
        msg = PingMessage(opts.SERVER_ENDPOINT, peer)
        ping_hash = await self.send(peer, msg)
        if ping_hash in self.requests:
            return
        self.requests[ping_hash] = peer
        self.timer[ping_hash] = time.monotonic()
        await trio.sleep(opts.SERVER_TIMEOUT)
        if ping_hash in self.requests:
            self.listener.on_ping_timeout(self.requests[ping_hash])
            self.timer.pop(ping_hash)
            self.requests.pop(ping_hash)
        

    async def findneighbours(self, peer: PeerNetworkInfo,
            id: PublicKey) -> Coroutine:
        """Send a findneighbours message packet to the designated peer.

        :param PeerNetworkInfo peer: The designated peer network node.
        :param PublicKey id: The central node id.
        """
        await self.send(peer, FindNeighboursMessage(id))

    async def handle(self, data: bytes,
            address: Tuple[str, int]) -> Coroutine:
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
            ping_hash, msg, public_key = Message.unpack(data)
        except DecodeFormatError as err:
            logger.warning(
                "Recieved a packet but couldn't parse successfully. "
                f"From {ip}: {port}. Details: {err}"
            )
            return
        logger.debug(
            f"Received {msg} from {ip}:{port} (peerId: "
            f"{public_key.to_bytes().hex()[:7]})"
        )
        if isinstance(msg, PingMessage):
            remote = PeerInfo(
                public_key,
                ipaddress.ip_address(ip),
                port,
                msg.from_peer.tcp_port
            )
            new_msg = PongMessage(remote, ping_hash)
            await self.send(remote, new_msg)
            await self.listener.on_recieved_ping(remote)
        elif isinstance(msg, PongMessage):
            if msg.ping_hash in self.requests:
                self.last_pong[public_key] = time.monotonic()
                ping = self.last_pong[public_key] - self.timer[msg.ping_hash]
                peer = PeerInfo.remake(
                    self.requests[msg.ping_hash],
                    public_key
                )
                logger.debug(
                    f"Connect to {rckey}(peer id: {peer}) in {ping}s. "
                    "Add it to DHT."
                )
                self.requests.pop(msg.ping_hash)
                self.timer.pop(msg.ping_hash)
                await self.listener.on_recieved_pong(peer)
            else:
                logger.warning(
                    f"Recieved a pong packet from {rckey}, "
                    "but no corresponding ping packet."
                )
        elif isinstance(msg, FindNeighboursMessage):
            if (public_key in self.last_pong 
                and time.monotonic() - self.last_pong[public_key] > 43200):
                return
            remote = PeerInfo(public_key, ipaddress.ip_address(ip), port, 0)
            cloest_peers = \
                self.listener.on_recieved_findneighbours(msg.target)
            await self.send(remote,NeighboursMessage(cloest_peers))
        elif isinstance(msg, NeighboursMessage):
                await self.listener.on_recieved_neighbours(msg.peers)