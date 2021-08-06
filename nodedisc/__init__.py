#!/usr/bin/env python
# -*- codeing:utf-8 -*-

"""A implementation of Node Discovery Protocol.

Node Discovery is a system for finding other participants in a
peer-to-peer network. The system can be used by any node, for any
purpose, at no cost other than running the network protocol and storing
a limited number of other nodes' records. Any node can be used as an
entry point into the network.

The system's design is loosely inspired by the Kademlia DHT, but unlike
most DHTs no arbitrary keys and values are stored. Instead, the DHT
stores and relays 'node records', which are signed documents providing
information about nodes in the network. Node Discovery acts as a
database of all live nodes in the network and performs three basic
functions:

    Sampling the set of all live participants: by walking the DHT, the
    network can be enumerated.

    Searching for participants providing a certain service: Node
    Discovery v5 includes a scalable facility for registering 'topic
    advertisements'. These advertisements can be queried and nodes
    advertising a topic found.

    Authoritative resolution of node records: if a node's ID is known,
    the most recent version of its record can be retrieved.

See: https://github.com/ethereum/devp2p/blob/master/discv4.md
See: https://github.com/ethereum/devp2p/blob/master/discv5/discv5.md
"""

__author__ = "XiaoHuiHui"
__version__ = "2.1"

import os

if not os.path.exists("./logs/nodedisc"):
    os.makedirs("./logs/nodedisc")

from .dpt import DPT, DPTListener
from .server import UDPServer, Controller
from .discv4.controller import ControllerV4, ListenerV4
from .datatypes import PeerInfo

__all__ = [
    "DPT",
    "DPTListener",
    "UDPServer",
    "Controller",
    "ControllerV4",
    "ListenerV4",
    "PeerInfo"
]