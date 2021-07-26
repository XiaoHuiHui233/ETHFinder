#!/usr/bin/env python
# -*- codeing:utf-8 -*-

"""A implementation of The RLPx Transport Protocol.

RLPx based on TCP sockets. We use trio async scocket to implement it.

See: https://github.com/ethereum/devp2p/blob/master/rlpx.md
"""

__author__ = "XiaoHuiHui"
__version__ = "1.1"

import logging
from logging import FileHandler, Formatter
from typing import Coroutine, Dict, List

from lru import LRU
import trio
from trio import Nursery, SocketStream
from eth_keys import KeyAPI
from eth_keys.datatypes import PrivateKey, PublicKey

import config as opts
from rlpx.peer import Peer
from dpt.dpt import DPT, DPTListener
from dpt.classes import PeerInfo
from rlpx.procotols.p2p import DISCONNECT_REASONS

BUFF_SIZE = 1024

logger = logging.getLogger("rlpx")
main_logger = logging.getLogger("main")
fh = FileHandler('./logs/rlpx.log')
fmt = Formatter("%(asctime)s [%(name)s][%(levelname)s] %(message)s")
fh.setFormatter(fmt)
fh.setLevel(logging.INFO)
logger.addHandler(fh)


class MyDPTListener(DPTListener):
    """
    """

    def __init__(self, rlpx: "RLPx") -> None:
        self.rlpx = rlpx

    async def on_add_peer(self, peer: PeerInfo) -> Coroutine:
        await self.rlpx.on_add_peer(peer)
        
    
    def on_remove_peer(self, peer_id: PublicKey) -> None:
        self.rlpx.on_remove_peer(peer_id)


class ServerIsDeadError(Exception):
    """An error indicating that the socket has been closed."""
    pass

class RLPx:
    """
    """

    def __init__(self, private_key: PrivateKey, dpt: DPT,
            base_loop: Nursery) -> None:
        self.private_key = private_key
        self.base_loop = base_loop
        self.id = KeyAPI().private_key_to_public_key(private_key)
        self.dpt: DPT = dpt
        dpt.register("RLPx", MyDPTListener(self))
        self.peers: Dict[PublicKey, Peer] = {}
        self.peers_queue: List[PeerInfo] = []
        self.peers_lru = LRU(25000)
        self.refill_switch = True
    
    def __del__(self) -> None:
        self.refill_switch = False

    async def connect_to(self, peer: PeerInfo) -> Coroutine:
        if peer.id in self.peers:
            logger.warning(f"Peer {peer} is already connected.")
            return
        if len(self.peers) >= opts.MAX_PEERS:
            self.peers_queue.append(peer)
            return
        logger.info(
            f"Connecting to {peer.address}:{peer.tcp_port} (id: {peer})."
        )
        try:
            socket_stream = \
                await trio.open_tcp_stream(str(peer.address), peer.tcp_port)
        except OSError as err:
            logger.warning(
                f"Error connecting to {peer.address}:{peer.tcp_port} "
                f"(id: {peer}). Detail: {err}"
            )
            return
        await self.on_connect(socket_stream, peer)

    async def on_connect(self, socket_stream: SocketStream,
            peer_info: PeerInfo = None) -> Coroutine:
        peer = None
        rckey = ""
        async with trio.open_nursery() as peer_loop:
            try:
                peer = Peer(
                    self.id,
                    peer_info.id,
                    socket_stream,
                    self.private_key,
                    self.after_connected,
                    peer_loop
                )
                rckey = peer.rckey
                if peer_info is not None:
                    peer_loop.start_soon(peer.send_auth)
                peer_loop.start_soon(peer.timeout_check)
                await peer.recv_loop()
                from controller import eth_controller
                eth_controller.remove(rckey)
                if peer.remote_id is not None \
                    and peer.remote_id in self.peers:
                    self.peers.pop(peer.remote_id)
                if peer.base_protocol.disconnect_reason == DISCONNECT_REASONS.TOO_MANY_PEERS:
                    self.peers_queue.append(peer_info)
            except OSError as err:
                logger.error(
                    f"Occerred OSError, detail: {err}."
                )
        if peer is not None:
            self.dpt.ban_peer(peer.remote_id)
        logger.info(f"Disconnect from {rckey}.")
    
    async def after_connected(self, peer: Peer) -> Coroutine:
        msg = f"Handshake with {peer.rckey} was successful."
        if peer.ecies_session.got_EIP8_auth:
            msg += " (peer eip8 auth)"
        if peer.ecies_session.got_EIP8_ack:
            msg += " (peer eip8 ack)"
        logger.info(msg)
        if peer.remote_id is None \
            and len(self.peers) == opts.MAX_PEERS:
            await peer.base_protocol.send_disconnect(
                DISCONNECT_REASONS.TOO_MANY_PEERS
            )
        elif peer.remote_id is not None:
            if peer.remote_id == self.id:
                await peer.base_protocol.send_disconnect(
                    DISCONNECT_REASONS.SAME_IDENTITY
                )
            elif peer.remote_id in self.peers:
                await peer.base_protocol.send_disconnect(
                    DISCONNECT_REASONS.ALREADY_CONNECTED
                )
        self.peers[peer.remote_id] = peer

    async def on_add_peer(self, peer: PeerInfo) -> Coroutine:
        if peer.id in self.peers_lru:
            if self.peers_lru[peer.id]:
                return
        self.peers_lru[peer.id] = True
        if len(self.peers) < opts.MAX_PEERS:
            await self.connect_to(peer)
        else:
            self.peers_queue.append(peer)
    
    def on_remove_peer(self, peer_id: PublicKey) -> None:
        for d in self.peers_queue:
            if d.id == peer_id:
                self.peers_queue.remove(d)
    
    async def refill_loop(self) -> Coroutine:
        async with trio.open_nursery() as refill_loop:
            while self.refill_switch:
                await trio.sleep(opts.REFILL_INTERVALL)
                refill_loop.start_soon(self.refill)

    async def refill(self) -> Coroutine:
        main_logger.info(
            f"Connection refill. "
            f"Peers: {len(self.peers)}, "
            f"Queue size: {len(self.peers_queue)}."
        )
        index = min(len(self.peers_queue), opts.MAX_PEERS - len(self.peers))
        wait_for_connect = self.peers_queue[:index]
        self.peers_queue = self.peers_queue[index:]
        for item in wait_for_connect:
            self.base_loop.start_soon(
                self.connect_to,
                item
            )

    async def bind(self) -> Coroutine:
        host = str(opts.SERVER_ENDPOINT.address)
        port = opts.SERVER_ENDPOINT.tcp_port
        logger.info(f"RLPx on bind {host}:{port}.")
        await trio.serve_tcp(self.on_connect, port, host=host)
        
