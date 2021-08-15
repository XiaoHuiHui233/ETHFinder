#!/usr/bin/env python
# -*- codeing:utf-8 -*-

"""A implementation of core controller of RLPx protocol.
"""

__author__ = "XiaoHuiHui"
__version__ = "1.1"

from ipaddress import IPv4Address, IPv6Address
from typing import Union
import logging
from logging import Formatter, FileHandler, StreamHandler
from multiprocessing import Queue

import trio

from rlpx import Peer, TCPListener, TCPServer, P2p, P2pListener
import config as opts

logger = logging.getLogger("core.rlpx")
fmt = Formatter("%(asctime)s [%(name)s][%(levelname)s] %(message)s")
fh = FileHandler("./logs/core/rlpx.log", "w", encoding="utf-8")
sh = StreamHandler()
fh.setFormatter(fmt)
sh.setFormatter(fmt)
fh.setLevel(logging.INFO)
sh.setLevel(logging.INFO)
logger.addHandler(fh)
logger.addHandler(sh)

IPAddress = Union[IPv4Address, IPv6Address]


class MyTCPListener(TCPListener):
    """
    """
    def __init__(self, core: "RLPxCore") -> None:
        self.core = core

    def on_peer(self, peer: Peer) -> None:
        p2p = P2p(
            opts.RLPX_PROTOCOL_VERSION,
            opts.RLPX_PROTOCOL_LENGTH,
            opts.CLIENT_ID,
            opts.MY_PEER.tcp_port,
            opts.REMOTE_ID_FILTER,
            opts.RLPX_PING_INTERVAL,
            opts.RLPX_PING_TIMEOUT,
            opts.RLPX_HELLO_TIMEOUT
        )
        for listener in self.core.p2p_listeners:
            p2p.register_listener(listener)
        peer.register_handler(p2p)

class RLPxCore:
    """
    """
    def __init__(self, channel: Queue) -> None:
        self.server = TCPServer(
            opts.PRIVATE_KEY,
            opts.MAX_PEERS,
            opts.EIP8,
            opts.RLPX_TIMEOUT,
            opts.RLPX_LOCK_TIMEOUT
        )
        self.server.register_listener(MyTCPListener(self))
        self.channel = channel
        self.p2p_listeners: list[P2pListener] = []
    
    def p2p_register_listener(self, listener: P2pListener) -> None:
        self.p2p_listeners.append(listener)

    async def bind(self) -> None:
        async with trio.open_nursery() as rlpx_loop:
            self.rlpx_loop = rlpx_loop
            rlpx_loop.start_soon(
                self.server.bind,
                "0.0.0.0",
                opts.MY_PEER.tcp_port
            )
            while True:
                await trio.sleep(opts.REFILL_INTERVALL)
                await self.refill()

    async def refill(self) -> None:
        logger.info(
            f"Connection refill. "
            f"Peers: {len(self.server)}, "
            f"Queue size: {self.channel.qsize()}."
        )
        while len(self.server) < opts.MAX_PEERS:
            try:
                id, peer = self.channel.get_nowait()
            except Exception:
                break
            self.rlpx_loop.start_soon(
                self.server.active_connect,
                peer.address,
                peer.tcp_port,
                id
            )
        