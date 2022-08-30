#!/usr/bin/env python
# -*- codeing:utf-8 -*-
"""A implementation of The RLPx Transport Protocol.

The RLPx transport protocol, a TCP-based transport protocol used for
communication among Ethereum nodes. The protocol carries encrypted
messages belonging to one or more 'capabilities' which are negotiated
during connection establishment. RLPx is named after the RLP
serialization format. The name is not an acronym and has no particular
meaning.

See: https://github.com/ethereum/devp2p/blob/master/rlpx.md
"""

__author__ = "XiaoHuiHui"
__version__ = "3.0"

import logging
from logging import FileHandler, Formatter, StreamHandler

from .main import RLPx

DEBUG = False

sh = StreamHandler()
fh = FileHandler("./logs/rlpx.log", "w", encoding="utf-8")
fmt = Formatter("%(asctime)s [%(name)s][%(levelname)s] %(message)s")
sh.setFormatter(fmt)
fh.setFormatter(fmt)
sh.setLevel(logging.DEBUG if DEBUG else logging.INFO)
fh.setLevel(logging.DEBUG if DEBUG else logging.INFO)

loggers = [
    logging.getLogger("rlpx.ipc"),
    logging.getLogger("rlpx.main"),
    logging.getLogger("rlpx.peer.p2p"),
    logging.getLogger("rlpx.peer.peer"),
    logging.getLogger("rlpx.protocols.eth"),
    logging.getLogger("rlpx.server"),
]

for logger in loggers:
    logger.addHandler(sh)
    logger.addHandler(fh)

__all__ = ["RLPx"]
