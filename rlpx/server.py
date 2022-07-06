#!/usr/bin/env python
# -*- codeing:utf-8 -*-
"""A implementation of TCP sockets.
"""

__author__ = "XiaoHuiHui"
__version__ = "1.1"

import abc
from abc import ABCMeta
from ipaddress import IPv4Address, IPv6Address
from typing import Union
import logging
from logging import FileHandler, Formatter
import traceback
import time

import trio
from trio import SocketStream
from eth_keys.datatypes import PrivateKey, PublicKey
from lru import LRU

from .peer import Peer
import utils
from utils import IPAddress

logger = logging.getLogger("rlpx.server")
fh = FileHandler("./logs/rlpx/server.log", "w", encoding="utf-8")
fmt = Formatter("%(asctime)s [%(name)s][%(levelname)s] %(message)s")
fh.setFormatter(fmt)
fh.setLevel(logging.WARN)
logger.addHandler(fh)


class TCPListener(metaclass=ABCMeta):
    """
    """
    @abc.abstractmethod
    def on_peer(self, peer: Peer) -> None:
        return NotImplemented


class TCPServer:
    """
    """
    def __init__(
        self,
        private_key: PrivateKey,
        max_peer: int,
        EIP8: bool,
        waiting_timeout: int,
        lock_timeout: int
    ) -> None:
        self.private_key = private_key
        self.max_peer = max_peer
        self.EIP8 = EIP8
        self.waiting_timeout = waiting_timeout
        self.lock_timeout = lock_timeout
        self.peers: dict[str, Peer] = {}
        self.banlist: dict[str, float] = LRU(25000)
        self.listeners: list[TCPListener] = []

    def __len__(self) -> int:
        return len(self.peers)

    def is_full(self) -> bool:
        return len(self.peers) >= self.max_peer

    def register_listener(self, listener: TCPListener) -> None:
        self.listeners.append(listener)

    async def bind(self, address: str, port: int) -> None:
        logger.info(f"TCP server on bind {address}:{port}.")
        async with trio.open_nursery() as server_loop:
            self.server_loop = server_loop
            await trio.serve_tcp(
                self.on_connect,
                port,
                host=address,
                handler_nursery=server_loop
            )

    async def connect_to(self, address: IPAddress, port: int) -> SocketStream:
        logger.info(f"Connecting to {address}:{port}.")
        try:
            return await trio.open_tcp_stream(str(address), port)
        except Exception:
            logger.warn(
                f"Error connecting to {address}:{port}.\n"
                f"Detail: {traceback.format_exc()}"
            )
            return None

    async def active_connect(
        self, address: IPAddress, port: int, remote_id: PublicKey
    ) -> None:
        socket_stream = await self.connect_to(address, port)
        if socket_stream is None:
            logger.warn(f"{address}:{port} is unreachable.")
            return
        logger.info(f"Active connect to {address}:{port}.")
        self.server_loop.start_soon(self.on_connect, socket_stream, remote_id)

    async def on_connect(
        self,
        socket_stream: SocketStream,
        remote_id: PublicKey = None
    ) -> None:
        if socket_stream is None:
            return
        rckey = "-"
        try:
            rckey = utils.get_socket_rckey(socket_stream)
            if rckey in self.peers:
                logger.warn(f"Peer {rckey} is already in peers list.")
                await utils.unsafe_close(socket_stream)
                return
            if self.is_full():
                logger.warn(f"Peer list is already full, Refuse {rckey}.")
                await utils.unsafe_close(socket_stream)
                return
            if rckey in self.banlist:
                if time.monotonic() - self.banlist[rckey] < 30:
                    logger.warn(f"Peer {rckey} has been banned.")
                    await utils.unsafe_close(socket_stream)
                    return
                else:
                    del self.banlist[rckey]
            await self.generate_peer(
                socket_stream, remote_id is not None, remote_id
            )
        except Exception:
            logger.warn(
                f"Error on connect to {rckey}.\n"
                f"Detail: {traceback.format_exc()}"
            )

    async def generate_peer(
        self, socket_stream: SocketStream, active: bool, remote_id: PublicKey
    ) -> None:
        peer = Peer(
            self.private_key,
            remote_id,
            socket_stream,
            self.EIP8,
            self.waiting_timeout,
            self.lock_timeout
        )
        self.peers[peer.rckey] = peer
        for listener in self.listeners:
            try:
                listener.on_peer(peer)
            except Exception:
                logger.error(
                    f"Error when calling on_peer to listener.\n"
                    f"Detail: {traceback.format_exc()}"
                )
        logger.info(f"Activate peer {peer.rckey}.")
        await peer.bind(active)
        logger.info(f"Disconnected from peer {peer.rckey}.")
        self.peers.pop(peer.rckey)
        self.ban_peer(peer.rckey)

    def ban_peer(self, rckey: str) -> None:
        self.banlist[rckey] = time.monotonic()
