#!/usr/bin/env python
# -*- codeing:utf-8 -*-
"""A simple implementation of Ethereum Improvement Proposals EIP-1459.

EIP-1459: A scheme for authenticated, updateable Ethereum node lists
retrievable via DNS.

See: https://github.com/ethereum/EIPs/blob/master/EIPS/eip-1459.md
"""

__author__ = "XiaoHuiHui"
__version__ = "1.8"

import logging

from dnsdisc import resolver

fh = logging.FileHandler("./logs/dnsdisc.log", "w", encoding="utf-8")
fmt = logging.Formatter("%(asctime)s [%(name)s][%(levelname)s] %(message)s")
fh.setFormatter(fmt)
fh.setLevel(logging.WARN)

logger = logging.getLogger("dnsdisc")
logger.addHandler(fh)

__all__ = ["resolver"]
