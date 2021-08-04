#!/usr/bin/env python
# -*- codeing:utf-8 -*-

"""A implementation of Distributed Peer Table.  

Participants in the Discovery Protocol are expected to maintain a node
record (ENR) containing up-to-date information. All records must use the
"v4" identity scheme. Other nodes may request the local record at any
time by sending an ENRRequest packet.  

To resolve the current record of any node public key, perform a Kademlia
lookup using FindNode packets. When the node is found, send ENRRequest
to it and return the record from the response.  

See: https://github.com/ethereum/devp2p/blob/master/discv4.md  

"""

__author__ = "XiaoHuiHui"
__version__ = "2.1"

from collections import deque
import itertools
import random
import functools
import logging
from logging import FileHandler, Formatter

logger = logging.getLogger("nodedisc.kbucket")
fh = FileHandler("./logs/nodedisc/kbucket.log")
fmt = Formatter("%(asctime)s [%(name)s][%(levelname)s] %(message)s")
fh.setFormatter(fmt)
fh.setLevel(logging.INFO)
logger.addHandler(fh)


def compute_distance(left_node_id: bytes, right_node_id: bytes) -> int:
    """Calculate the bitwise XOR between two peers to indicate the
    distance.

    :param bytes left_node_id: Left operand.
    :param byess right_node_id: Right operand.
    :return int: Distance.
    """
    left_int = int.from_bytes(left_node_id, byteorder="big")
    right_int = int.from_bytes(right_node_id, byteorder="big")
    return left_int ^ right_int


def compute_log_distance(left_node_id: bytes, right_node_id: bytes) -> int:
    """Calculate the logarithmic distance. The logarithmic distance
    refers to the number of bits where the highest different bits of two
    public key bytes in binary.
    
    Binary can be understood as a logarithm with base two. So we call
    this the logarithmic distance.

    :param bytes left_node_id: Left operand.
    :param byess right_node_id: Right operand.
    :return int: Distance.
    :raise ValueError: If left is equal to right.
    """
    if left_node_id == right_node_id:
        raise ValueError(
            "Cannot compute log distance between identical nodes."
        )
    distance = compute_distance(left_node_id, right_node_id)
    return distance.bit_length()


class KademliaRoutingTable:
    """A Kademlia routing table implementation class."""

    def __init__(self, center_node_id: bytes, bucket_size: int,
            num_buckets: int) -> None:
        self.center_node_id = center_node_id
        self.bucket_size = bucket_size
        self.buckets: list[deque] = [
            deque(maxlen=bucket_size) \
            for _ in range(num_buckets)
        ]
        self.replacement_caches: list[deque] = [
            deque() \
            for _ in range(num_buckets)
        ]
        self.bucket_update_order = deque()

    def __contains__(self, node_id: bytes) -> bool:
        _, bucket, replacement_cache = \
            self.get_index_bucket_and_replacement_cache(node_id)
        return node_id in bucket or node_id in replacement_cache

    def get_index_bucket_and_replacement_cache(self,
            node_id: bytes) -> tuple[int, deque, deque]:
        """The logarithmic distance between the peer id and the central
        peer id is used to indicate which bucket the peer corresponding
        to a given peer id should be stored in. Returns the index of
        the bucket.

        Because the peer ids are all randomly generated 32-bit hashes.
        Therefore, calculating the logarithmic distance with the node
        id of the random hash can be approximately evenly distributed to
        the joined buckets. It is not difficult to prove that the
        logarithmic distance of two 32-bit random hashes obeys the
        average distribution.

        :param bytes node_id: The given peer id.
        :return int: The bucket index.
        :return Deque: The bucket object.
        :return Deque: The replacement cache object.
        """
        index = compute_log_distance(self.center_node_id, node_id) - 1
        bucket = self.buckets[index]
        replacement_cache = self.replacement_caches[index]
        return index, bucket, replacement_cache

    def update(self, node_id: bytes) -> bytes:
        """Insert a node into the routing table or move it to the top if
        already present.
        
        If the bucket is already full, the node id will be added to the
        replacement cache and the oldest node is returned as an eviction
        candidate. Otherwise, the return value is `None`.

        :param bytes node_id: The id of the node to be added.
        :return bytes: Replaced node id if exists.
        """
        if node_id == self.center_node_id:
            raise ValueError("Cannot insert center node into routing table.")
        bucket_index, bucket, replacement_cache = \
            self.get_index_bucket_and_replacement_cache(node_id)
        is_bucket_full = len(bucket) >= self.bucket_size
        is_node_in_bucket = node_id in bucket
        if not is_node_in_bucket and not is_bucket_full:
            logger.info(
                f"Adding {node_id.hex()[:7]} to bucket {bucket_index}."
            )
            self.update_bucket_unchecked(node_id)
            eviction_candidate = None
        elif is_node_in_bucket:
            logger.info(
                f"Updating {node_id.hex()[:7]} in bucket {bucket_index}."
            )
            self.update_bucket_unchecked(node_id)
            eviction_candidate = None
        elif not is_node_in_bucket and is_bucket_full:
            if node_id not in replacement_cache:
                logger.info(
                    f"Adding {node_id.hex()[:7]} to replacement cache of "
                    f"bucket {bucket_index}."
                )
            else:
                logger.info(
                    f"Updating {node_id.hex()[:7]} in replacement cache of "
                    f"bucket {bucket_index}."
                    )
                replacement_cache.remove(node_id)
            replacement_cache.appendleft(node_id)
            eviction_candidate = bucket[-1]
        return eviction_candidate

    def update_bucket_unchecked(self, node_id: bytes) -> None:
        """Add or update assuming the node is either present already or
        the bucket is not full.

        :param bytes node_id: The id of the node to be added.
        """
        bucket_index, bucket, replacement_cache = \
            self.get_index_bucket_and_replacement_cache(node_id)
        for container in (bucket, replacement_cache):
            try:
                container.remove(node_id)
            except ValueError:
                pass
        bucket.appendleft(node_id)
        try:
            self.bucket_update_order.remove(bucket_index)
        except ValueError:
            pass
        self.bucket_update_order.appendleft(bucket_index)

    def remove(self, node_id: bytes) -> None:
        """Remove a node from the routing table if it is present.

        If possible, the node will be replaced with the newest entry in
        the replacement cache.

        :param bytes node_id: The id of the node to be removed.
        """
        bucket_index, bucket, replacement_cache = \
            self.get_index_bucket_and_replacement_cache(node_id)
        in_bucket = node_id in bucket
        in_replacement_cache = node_id in replacement_cache
        if in_bucket:
            bucket.remove(node_id)
            if len(replacement_cache) > 0:
                replacement_node_id = replacement_cache.popleft()
                logger.info(
                    f"Replacing {node_id.hex()[:7]} from bucket {bucket_index}"
                    f" with {replacement_node_id.hex()[:7]} from replacement "
                    "cache."
                )
                bucket.append(replacement_node_id)
            else:
                logger.info(
                    f"Removing {node_id.hex()[:7]} from bucket {bucket_index} "
                    "without replacement."
                )
        if in_replacement_cache:
            logger.info(
                f"Removing {node_id.hex()[:7]} from replacement cache of "
                f"bucket {bucket_index}."
            )
            replacement_cache.remove(node_id)
        if not in_bucket and not in_replacement_cache:
            logger.info(
                f"Not removing {node_id.hex()[:7]} as it is neither present in"
                " the bucket nor the replacement cache."
            )
        # bucket_update_order should only contain non-empty buckets,
        # so remove it if necessary
        if len(bucket) == 0:
            try:
                self.bucket_update_order.remove(bucket_index)
            except ValueError:
                pass

    def get_nodes_at_log_distance(self, log_distance: int) -> list[bytes]:
        """Get all nodes in the routing table at the given log distance
        to the center.

        :param int log_distance: The given log distance.
        :return list[bytes]: All nodes in the bucket and cache.
        :raise ValueError: If given distance is illegal.
        """
        if log_distance <= 0:
            raise ValueError(
                f"Log distance must be positive, got {log_distance}."
            )
        elif log_distance > len(self.buckets):
            raise ValueError(
                "Log distance must not be greater than "
                f"{len(self.buckets)}, got {log_distance}."
            )
        return list(self.buckets[log_distance - 1])
    
    @property
    def is_empty(self) -> bool:
        """Determine whether the KHT is empty.

        :return bool: Whether the KHT is empty.
        """
        return all(len(bucket) == 0 for bucket in self.buckets)

    def get_least_recently_updated_log_distance(self) -> int:
        """Get the log distance whose corresponding bucket was updated
        least recently.

        Only non-empty buckets are considered.
        
        :return int: The log distance.
        :raise ValueError: If all buckets are empty.
        """
        try:
            bucket_index = self.bucket_update_order[-1]
        except IndexError:
            raise ValueError("Routing table is empty")
        else:
            return bucket_index + 1

    def list_nodes_around(self, reference_node_id: bytes) -> list[bytes]:
        """Iterate over all nodes in the routing table ordered by
        distance to a given reference.

        :param bytes reference_node_id: The given reference.
        :return list[bytes]: All nodes in the routing table.
        """
        all_node_ids = itertools.chain(*self.buckets)
        distance_to_reference = functools.partial(
            compute_distance,
            reference_node_id
        )
        sorted_node_ids = sorted(all_node_ids, key=distance_to_reference)
        return sorted_node_ids

    def list_all_random(self) -> list[bytes]:
        """Iterate over all nodes in the table (including ones in the
        replacement cache) in a random order.

        :return list[bytes]: All nodes in the table.
        """
        # Create a new list with all available nodes as buckets can 
        # mutate while we're iterating.
        # This shouldn't use a significant amount of memory as the new
        # list will keep just references to the existing NodeID
        # instances.
        node_ids = list(
            itertools.chain(*self.buckets, *self.replacement_caches)
        )
        random.shuffle(node_ids)
        return node_ids