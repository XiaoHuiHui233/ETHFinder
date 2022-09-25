#!/usr/bin/env python
# -*- codeing:utf-8 -*-
"""A implementation of Distributed Peer Table.

A dynamic peer-to-peer network node routing table implemented using
distributed hash table algorithm and node discovery protocol.

See: https://github.com/ethereum/devp2p/blob/master/discv4.md
"""

__author__ = "XiaoHuiHui"

import logging
from datetime import datetime
from typing import NamedTuple, Optional

from eth_hash.auto import keccak
from eth_keys.datatypes import PrivateKey, PublicKey

from .datatypes import Node
from .kbucket import KademliaRoutingTable

logger = logging.getLogger("nodedisc.dpt")


def now() -> int:
    return int(datetime.utcnow().timestamp())


class KBucketParams(NamedTuple):
    bucket_nodes: int
    num_buckets: int


class DPT:
    """A class represents distributed peer table."""
    def __init__(self, private_key: PrivateKey, params: KBucketParams) -> None:
        self.private_key = private_key
        self.id = private_key.public_key
        logger.info(f"DPT running with node key: 0x{self.id.to_bytes().hex()}")
        self.kbucket = KademliaRoutingTable(
            keccak(self.id.to_bytes()),
            *params
        )
        self.nodes: dict[bytes, Node] = {}

    def __len__(self) -> int:
        return len(self.nodes)

    def __contains__(self, id: PublicKey) -> bool:
        id_bytes = id.to_bytes()
        id_hash = keccak(id_bytes)
        assert (
            (id_hash in self.kbucket and id_hash in self.nodes) or
            (id_hash not in self.kbucket and id_hash not in self.nodes)
        ), f"Incnsistency: {id_bytes.hex()[:7]}"
        return id_hash in self.nodes

    def add(self, node: Node) -> Optional[Node]:
        """Add a node to the DHT.

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
        """
        assert node.id != self.id, "Can't add self to DHT."
        id_bytes = node.id.to_bytes()
        id_hash = keccak(id_bytes)
        if id_hash in self.nodes:
            assert(
                id_hash in self.kbucket
            ), f"Incnsistency: {id_bytes.hex()[:7]}"
            logger.warning(f"Node {node} is in DHT.")
            return
        logger.debug(f"Node {node} was added to DHT.")
        old_id_hash = self.kbucket.update(id_hash)
        self.nodes[id_hash] = node
        if old_id_hash is not None:
            self.kbucket.remove(old_id_hash)
            old_node = self.nodes.pop(old_id_hash)
            return old_node

    def remove(self, id: PublicKey) -> Optional[Node]:
        """Remove a node by the given id.

        :param PublicKey id: The given id.
        """
        if id == self.id:
            logger.warning("You can't remove self from DHT.")
            return
        id_bytes = id.to_bytes()
        id_hash = keccak(id_bytes)
        id_str = id_bytes.hex()[:7]
        if id_hash in self.nodes:
            assert(
                id_hash in self.kbucket
            ), f"Incnsistency: {id_bytes.hex()[:7]}"
            self.kbucket.remove(id_hash)
            return self.nodes.pop(id_hash)
        else:
            assert(
                id_hash not in self.kbucket
            ), f"Incnsistency: {id_bytes.hex()[:7]}"
            logger.warning(f"Peer id {id_str} is not in DHT.")

    def all(self, limit: int = -1) -> list[Node]:
        """Get all of peers from the DHT.

        :return list[PeerInfo]: A list of peers.
        """
        r = list(self.nodes.values())
        return r[:min(len(r), limit)]

    def shuffle_all(self, limit: int = -1) -> list[Node]:
        r = [self.nodes[i] for i in self.kbucket.list_all_random()]
        return r[:min(len(r), limit)]

    def closest(self, id: PublicKey, limit: int = -1) -> list[Node]:
        """Get the ids of the peers closest to the given id.

        :param PublicKey id: The given id.
        :return list[PeerInfo]: A list of peers closest to the given id.
        """
        id_hash = keccak(id.to_bytes())
        r = [self.nodes[i] for i in self.kbucket.list_nodes_around(id_hash)]
        return r[:min(len(r), limit)]
