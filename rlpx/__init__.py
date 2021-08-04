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
__version__ = "2.1"

import os

if not os.path.exists("./logs"):
    os.makedirs("./logs")