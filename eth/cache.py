#!/usr/bin/env python
# -*- codeing:utf-8 -*-
"""A implementation of cache of eth protocol.
"""

__author__ = "XiaoHuiHui"

from collections import OrderedDict

from .datatypes.block import Block


class EthCache:
    def __init__(self, limit: int) -> None:
        self.cnt = 0
        self.limit = limit
        self.cache_block: OrderedDict[int, Block] = OrderedDict()
