#!/usr/bin/env python
# -*- codeing:utf-8 -*-
"""A implementation of cache of eth protocol.
"""

__author__ = "XiaoHuiHui"
__version__ = "1.1"

from typing import Union
from collections import OrderedDict

import config as opts

RLP = Union[list[list[list[bytes]]], list[list[bytes]], list[bytes], bytes]


class EthCache:
    def __init__(self) -> None:
        self.hash_to_height: dict[bytes, int] = {}
        self.block_header_cache: dict[int, RLP] = OrderedDict()
        self.block_body_cache: dict[int, RLP] = OrderedDict()

    def add_header_cache(self, height: int, cache: RLP) -> None:
        self.block_header_cache[height] = cache
        self.hash_to_height[cache[13]] = height
        while (len(self.block_header_cache) > opts.CACHE_SIZE):
            self.block_header_cache.popitem(False)

    def add_body_cache(self, height: int, cache: RLP) -> None:
        self.block_body_cache[height] = cache
        while (len(self.block_body_cache) > opts.CACHE_SIZE):
            self.block_body_cache.popitem(False)

    def add_cache(self, height: int, block: RLP) -> None:
        self.add_header_cache(height, block[0])
        self.add_body_cache(height, [block[1], block[2]])

    def get_headers(
        self,
        startblock: Union[int, str],
        limit: int,
        skip: int,
        reverse: bool
    ) -> RLP:
        if startblock in self.hash_to_height:
            startblock = self.hash_to_height[startblock]
        else:
            return []
        headers = []
        while limit > 0:
            if startblock in self.block_header_cache:
                headers.append(self.block_header_cache[startblock])
            if reverse:
                startblock -= skip
            else:
                startblock += skip
            if startblock > opts.NOW_HEIGHT:
                break
            limit -= 1
        return headers

    def get_bodies(self, hashes: list[str]) -> RLP:
        blocks = []
        for hash in hashes:
            if hash in self.hash_to_height:
                block_height = self.hash_to_height[hash]
                if block_height in self.block_body_cache:
                    blocks.append(self.block_body_cache[block_height])
        return blocks
