#!/usr/bin/env python
# -*- codeing:utf-8 -*-

"""A simple implementation of Ethereum Improvement Proposals EIP-1459.

EIP-1459: A scheme for authenticated, updateable Ethereum node lists
retrievable via DNS.

See: https://github.com/ethereum/EIPs/blob/master/EIPS/eip-1459.md
"""

__author__ = "XiaoHuiHui"
__version__ = "1.4"

import os

if not os.path.exists("./logs/dnsdisc"):
    os.makedirs("./logs/dnsdisc")

from . import dns
from . import enr
from .datatypes import PeerNetworkInfo

__all__ = ["dns", "enr", "PeerNetworkInfo"]