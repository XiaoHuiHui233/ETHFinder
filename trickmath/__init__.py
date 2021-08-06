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

__all__ = ["burn"]