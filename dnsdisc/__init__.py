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
from logging import FileHandler, Formatter, StreamHandler

from dnsdisc import resolver

DEBUG = False

sh = StreamHandler()
fh = FileHandler("./logs/dnsdisc.log", "w", encoding="utf-8")
fmt = Formatter("%(asctime)s [%(name)s][%(levelname)s] %(message)s")
sh.setFormatter(fmt)
fh.setFormatter(fmt)
sh.setLevel(logging.DEBUG if DEBUG else logging.INFO)
fh.setLevel(logging.DEBUG if DEBUG else logging.INFO)

loggers = [
    logging.getLogger("dnsdisc")
]

for logger in loggers:
    logger.addHandler(fh)
    logger.addHandler(sh)

__all__ = ["resolver"]
