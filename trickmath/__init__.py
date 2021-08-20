#!/usr/bin/env python
# -*- codeing:utf-8 -*-

"""
"""

__author__ = "XiaoHuiHui"
__version__ = "1.1"

import os

if not os.path.exists("./logs/trickmath"):
    os.makedirs("./logs/trickmath")

from .position import burn

def calc_burn(sqrt_price: int, tick: int) -> int:
    return burn(
        195000,
        196620,
        4621219005768122 + 4270283529460521,
        sqrt_price,
        tick
    )

__all__ = ["calc_burn"]