#!/usr/bin/env python
# -*- codeing:utf-8 -*-

"""A implementation of Node Discovery Protocol v4.

Node Discovery protocol version 4, a Kademlia-like DHT that stores
information about Ethereum nodes. The Kademlia structure was chosen
because it is an efficient way to organize a distributed index of nodes
and yields a topology of low diameter.

See: https://github.com/ethereum/devp2p/blob/master/discv4.md
"""

__author__ = "XiaoHuiHui"
__version__ = "1.2"