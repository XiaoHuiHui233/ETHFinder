#!/usr/bin/env python
# -*- codeing:utf-8 -*-

"""A implementation of Distributed Peer Table.

A dynamic peer-to-peer network node routing table implemented using
distributed hash table algorithm and node discovery protocol.

See: https://github.com/ethereum/devp2p/blob/master/discv4.md
"""

__author__ = "XiaoHuiHui"
__version__ = "2.1"

import logging
from logging import FileHandler, Formatter
import time
from abc import ABCMeta, abstractmethod
import traceback

from lru import LRU
from eth_keys.datatypes import PrivateKey, PublicKey
from eth_hash.auto import keccak

from .datatypes import PeerInfo
from .kbucket import KademliaRoutingTable

DIFF_TIME = 0.2

logger = logging.getLogger("nodedisc.dpt")
fh = FileHandler("./logs/nodedisc/dpt.log", "w", encoding="utf-8")
fmt = Formatter("%(asctime)s [%(name)s][%(levelname)s] %(message)s")
fh.setFormatter(fmt)
fh.setLevel(logging.WARN)
logger.addHandler(fh)


class DPTListener(metaclass=ABCMeta):
    """
    """
    @abstractmethod
    def on_add_peer(self, id: PublicKey, peer: PeerInfo) -> None:
        return NotImplemented
    
    @abstractmethod
    def on_remove_peer(self, id: PublicKey, peer: PeerInfo) -> None:
        return NotImplemented
    

class DPT:
    """A class represents distributed peer table."""

    def __init__(self, private_key: PrivateKey, bucket_nodes: int,
            num_buckets: int, max_closest: int) -> None:
        self.private_key = private_key
        self.id = private_key.public_key
        self.max_closest = max_closest
        logger.info(f"DPT running with node key: {self.id}")
        self.kbucket = KademliaRoutingTable(
            keccak(self.id.to_bytes()),
            bucket_nodes,
            num_buckets
        )
        self.peers: dict[bytes, tuple[PublicKey, PeerInfo]] = {}
        self.banlist: dict[PublicKey, float] = LRU(10000)
        self.listeners: list[DPTListener] = []

    def __len__(self) -> int:
        return len(self.peers)

    def __contains__(self, peer_id: PublicKey) -> bool:
        id_hash = keccak(peer_id.to_bytes())
        if id_hash in self.kbucket:
            if id_hash in self.peers:
                return True
            else:
                self.kbucket.remove(id_hash)
                logger.warn(
                    f"{peer_id} was not in peers dict, "
                    "but in kbucket!"
                )
        elif id_hash in self.peers:
                self.peers.pop(id_hash)
                logger.warn(
                    f"{peer_id} was not in kbucket, "
                    "but in peers dict!"
                )
        return False

    def register_listener(self, listener: DPTListener) -> None:
        self.listeners.append(listener)
    
    def add_peer(self, peer: PeerInfo, id: PublicKey) -> None:
        """Add a peer to the DHT.

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
        :return PeerInfo: Peer was kicked or None.
        """
        if id == self.id:
            logger.warn(f"You can't add self into DHT.")
            return
        if id in self.banlist:
            if time.monotonic() - self.banlist[id] < 300:
                logger.warn(
                    f"Peer id {id.to_bytes().hex()[:7]} is in ban list."
                )
                return
            else:
                del self.banlist[id]
        if peer.tcp_port == 0:
            logger.warn(f"Peer id {id.to_bytes().hex()[:7]} has no tcp port.")
            return
        id_hash = keccak(id.to_bytes())
        if id_hash in self.kbucket:
            logger.warn(f"Peer id {id.to_bytes().hex()[:7]} is in DHT.")
            return
        logger.info(f"Peer id {id.to_bytes().hex()[:7]} was added to DHT.")
        old = self.kbucket.update(id_hash)
        self.peers[id_hash] = (id, peer)
        for listener in self.listeners:
            try:
                listener.on_add_peer(id, peer)
            except Exception:
                logger.error(
                    f"Error on calling on_add_peer to listener.\n"
                    f"Detail: {traceback.format_exc()}"
                )
        if old is None:
            return None
        else:
            id, old_peer = self.peers[old]
            self.remove_peer(id)
            return old_peer

    def remove_peer(self, peer_id: PublicKey) -> None:
        """Remove a peer by the given id.
        
        :param PublicKey peer_id: The given id.
        """
        if peer_id == self.id:
            logger.warn(f"You can't remove self from DHT.")
            return
        id_hash = keccak(peer_id.to_bytes())
        if id_hash in self.kbucket:
            self.kbucket.remove(id_hash)
            if id_hash in self.peers:
                logger.info(
                    f"Peer id {peer_id.to_bytes().hex()[:7]} "
                    "was removed from DHT."
                )
                for listener in self.listeners:
                    try:
                        listener.on_remove_peer(
                            self.peers[id_hash][0],
                            self.peers[id_hash][1]
                        )
                    except Exception:
                        logger.error(
                            f"Error on calling on_remove_peer to listener.\n"
                            f"Detail: {traceback.format_exc()}"
                        )
                self.peers.pop(id_hash)
            else:
                logger.warn(
                    f"{peer_id.to_bytes().hex()[:7]} was not in kbucket, "
                    "but in peers dict!"
                )
        elif id_hash in self.peers:
            self.peers.pop(id_hash)
            logger.warn(
                f"{peer_id.to_bytes().hex()[:7]} was not in peers dict, "
                "but in kbucket!"
            )
    
    def ban_peer(self, peer_id: PublicKey) -> None:
        """Add a peer to the banned list.

        :param PublicKey peer_id: The public key of the peer to be
            banned.
        """
        if peer_id == self.id:
            logger.warn(f"You can't ban self peer from DHT.")
            return
        logger.info(f"Peer id {peer_id.to_bytes().hex()[:7]} was banned.")
        self.banlist[peer_id] = time.monotonic()
        self.remove_peer(peer_id)

    def get_peer(self, peer_id: PublicKey) -> PeerInfo:
        """Obtain the peer object from the DHT by the given id.

        :param PublicKey peer_id: The given id.
        """
        id_hash = keccak(peer_id.to_bytes())
        if id_hash in self.peers:
            return self.peers[id_hash][1]
        return None

    def get_peers(self) -> list[PeerInfo]:
        """Get all of peers from the DHT.

        :return list[PeerInfo]: A list of peers.
        """
        return [self.peers[i][1] for i in self.kbucket.list_all_random()]
    
    def get_closest_peers(self, id: PublicKey) -> list[PeerInfo]:
        """Get the ids of the peers closest to the given id.

        :param PublicKey id: The given id.
        :return list[PeerInfo]: A list of peers closest to the given id.
        """
        id_hash = keccak(id.to_bytes())
        all_around = [
            self.peers[i][1] for i in self.kbucket.list_nodes_around(id_hash)
        ]
        return all_around[:min(len(all_around), self.max_closest)]

    