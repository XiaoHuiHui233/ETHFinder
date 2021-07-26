#!/usr/bin/env python
# -*- codeing:utf-8 -*-

"""A implementation of Distributed Peer Table.

A dynamic peer-to-peer network node routing table implemented using
distributed hash table algorithm and node discovery protocol.

See: https://github.com/ethereum/devp2p/blob/master/discv4.md
"""

__author__ = "XiaoHuiHui"
__version__ = "1.10"

import secrets
import math
import logging
from logging import FileHandler, Formatter
from typing import List, Coroutine, Dict
from abc import ABCMeta, abstractmethod

import trio
from trio import NurseryManager
from lru import LRU
from eth_keys import KeyAPI
from eth_keys.datatypes import PrivateKey, PublicKey

from dpt.classes import PeerNetworkInfo, PeerInfo
from dpt.kbucket import KBucket
from dpt.server import Server, ServerListener
import config as opts

DIFF_TIME = 0.2

logger = logging.getLogger("dpt")
main_logger = logging.getLogger("main")
fh = FileHandler("./logs/dpt.log")
fmt = Formatter("%(asctime)s [%(name)s][%(levelname)s] %(message)s")
fh.setFormatter(fmt)
fh.setLevel(logging.INFO)
logger.addHandler(fh)


class MyServerListener(ServerListener):
    """
    """

    def __init__(self, dpt: "DPT") -> None:
        self.dpt = dpt

    async def on_recieved_ping(self, peer: PeerInfo) -> Coroutine:
        if peer.id not in self.dpt.kbucket:
            await self.dpt.add_peer(peer)

    def on_ping_timeout(self, peer: PeerNetworkInfo) -> None:
        if isinstance(peer, PeerInfo):
            self.dpt.remove_peer(peer.id)
    
    async def on_recieved_pong(self, peer: PeerInfo) -> Coroutine:
        await self.dpt.on_peer(peer)
    
    def on_recieved_findneighbours(self, id: PublicKey) -> List[PeerInfo]:
        return self.dpt.get_closest_peers(id)
    
    async def on_recieved_neighbours(self, peers: List[PeerInfo]) -> Coroutine:
        await self.dpt.add_peers(peers)


class DPTListener(metaclass=ABCMeta):
    """
    """

    @abstractmethod
    async def on_add_peer(self, peer: PeerInfo) -> Coroutine:
        return NotImplemented
    
    @abstractmethod
    def on_remove_peer(self, peer_id: PublicKey) -> None:
        return NotImplemented


class DPT:
    """A class represents distributed peer table."""

    def __init__(self, private_key: PrivateKey,
            base_loop: NurseryManager) -> None:
        self.private_key = private_key
        self.base_loop = base_loop
        self.id = KeyAPI().private_key_to_public_key(private_key)
        logger.info(f"DPT running with node key: {self.id}")
        # 10k should be enough (each peer obj can has 3 keys)
        self.banlist = LRU(10000)
        self.kbucket = KBucket(self.id)
        self.server = Server(private_key, MyServerListener(self))
        self.refresh_switch = True
        self.listeners: Dict[str, DPTListener] = {}

    def __del__(self) -> None:
        self.refresh_switch = False
    
    def register(self, name: str, listener: DPTListener) -> None:
        self.listeners[name] = listener
    
    def unregister(self, name: str) -> bool:
        if name in self.listeners:
            self.listeners.pop(name)
            return True
        return False

    async def refresh_loop(self) -> Coroutine:
        """Refresh periodically, if the number of nodes is less than the
        upper limit, get more neighbor nodes from known nodes. Refresh
        the DNS resolution node and send ping packets to all known
        nodes. Nodes that do not reply to the pong packet in time will
        be deleted.
        """
        cnt = 0
        async with trio.open_nursery() as refresh_loop:
            while self.refresh_switch:
                if cnt == 0:
                    refresh_loop.start_soon(self.refresh_alive_check)
                cnt += 1
                cnt %= 6
                await trio.sleep(opts.REFRESH_INTERVAL)
                refresh_loop.start_soon(self.refresh)
    
    async def refresh(self) -> Coroutine:
        """Part of the refresh task is to monitor whether the number of
        nodes reaches the upper limit, and if not, get 30% of the
        neighboring nodes of the nodes randomly.
        """
        peers = self.get_peers()
        main_logger.info(f"Start refreshing. Now {len(self.kbucket)} peers in table.")
        if len(self.kbucket) < opts.MAX_DPT_PEERS:
            inc = math.floor(min(opts.MAX_DPT_PEERS / 3, len(self.kbucket)))
            for peer in peers[:inc]:
                await self.server.findneighbours(
                    peer,
                    PublicKey(secrets.token_bytes(64))
                )
                await trio.sleep(DIFF_TIME)
    
    async def refresh_alive_check(self) -> Coroutine:
        """Part of the refresh task is to send ping packets to all nodes
        to make sure they are still alive.
        """
        main_logger.info(f"Start alive check.")
        async with trio.open_nursery() as ping_loop:
            for peer in self.get_peers():
                ping_loop.start_soon(self.server.ping, peer)
                await trio.sleep(DIFF_TIME)

    async def add_peer(self, peer: PeerNetworkInfo) -> Coroutine:
        """Try to add a peer to the DPT first time or again.

        Note: This function does not ensure that the peer must be added
        to the DPT. On the contrary, this function will not even try to
        put it. This function will only try to send a ping packet to the
        peer. If the peer responds to the pong packet within the
        specified delay, it will call on_peer to actually put it into
        the DPT.

        See: on_peer(self, peer: PeerNetworkInfo) -> Coroutine

        :param PeerNetworkInfo peer: Peer to add.
        """
        if isinstance(peer, PeerInfo):
            if peer.id in self.banlist:
                if self.banlist[peer.id]:
                    return
            if peer.id == self.id:
                return
        await self.server.ping(peer)
    
    async def add_peers(self, peers: List[PeerNetworkInfo]) -> Coroutine:
        """Try to add a batch of peers to the DPT first time or again.

        This function is the same as function add_peer.
        
        See: add_peer(self, peer: PeerNetworkInfo) -> Coroutine
        
        :param List[PeerNetworkInfo] peers: A list of peers to add.
        """
        for peer in peers:
            self.base_loop.start_soon(self.add_peer, peer)
            await trio.sleep(DIFF_TIME)
    
    async def on_peer(self, peer: PeerInfo) -> Coroutine:
        """Actually add a peer. By default, it will do so after
        receiving the pong packet.

        When a certain sub-table of the DHT table is full, adding an
        element will replace the least used element and delete it. This
        function is used to resend the ping packet to the replaced peer
        to determine whether it is still alive.
        
        Whenever a new node N₁ is encountered, it can be inserted into
        the corresponding bucket. If the bucket contains less than k
        entries N₁ can simply be added as the first entry. If the bucket
        already contains k entries, the least recently seen node in the
        bucket, N₂, needs to be revalidated by sending a Ping packet. If
        no reply is received from N₂ it is considered dead, removed and
        N₁ added to the front of the bucket.

        :param PeerInfo peer: The peer to be added.
        """
        if peer.id == self.id:
            return
        if peer.id in self.banlist:
            return
        if len(self.kbucket) < opts.MAX_DPT_PEERS:
            self.base_loop.start_soon(
                self.server.findneighbours,
                peer,
                PublicKey(secrets.token_bytes(64))
            )
        if peer.id in self.kbucket:
            return
        if peer.tcp_port == 0:
            self.ban_peer(peer.id)
            return
        self.kbucket.add(peer)
        for name in self.listeners:
            self.base_loop.start_soon(
                self.listeners[name].on_add_peer,
                peer
            )
    
    def ban_peer(self, peer_id: PublicKey) -> None:
        """Add a peer to the banned list.

        :param PublicKey peer_id: The public key of the peer to be
            banned。
        """
        logger.info(f"Peer id {peer_id.to_bytes().hex()[:7]} was banned.")
        self.banlist[peer_id] = True
        self.remove_peer(peer_id)
    
    def get_closest_peers(self, id: PublicKey) -> List[PeerInfo]:
        """Get the ids of the peers closest to the given id.

        :param PublicKey id: The given id.
        :return List[PeerInfo]: A list of peers closest to the given id.
        """
        return self.kbucket.closest(id)
    
    def get_peer(self, peer_id: PublicKey) -> PeerInfo:
        """Obtain the peer object from the DHT by the given id.

        :param PublicKey peer_id: The given id.
        """
        return self.kbucket.get(peer_id)

    def get_peers(self) -> List[PeerInfo]:
        """Get all of peers from the DHT.

        :return List[PeerInfo]: A list of peers.
        """
        return self.kbucket.get_all()

    def remove_peer(self, peer_id: PublicKey) -> None:
        """Remove a peer by the given id.
        
        :param PublicKey peer_id: The given id.
        """
        if peer_id in self.kbucket:
            self.kbucket.remove(peer_id)
            for name in self.listeners:
                self.listeners[name].on_remove_peer(peer_id)

    