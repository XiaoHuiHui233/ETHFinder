#!/usr/bin/env python
# -*- codeing:utf-8 -*-

"""
"""

__author__ = "XiaoHuiHui"
__version__ = "1.1"

from multiprocessing import Process, Queue
import logging

import trio
from eth_keys.datatypes import PublicKey

from core import NodeDiscCore, RLPxCore, EthCore
from nodedisc import DPTListener, PeerInfo
from rlpx import P2pListener, Protocol, Eth

logging.basicConfig(
    format="%(asctime)s [%(name)s][%(levelname)s] %(message)s",
    level=logging.INFO,
    handlers=[
        # StreamHandler(),
        # FileHandler("./server.log", "w")
    ]
)

class RLPxDPTListener(DPTListener):
    """
    """
    def __init__(self, queue: Queue) -> None:
        self.queue = queue

    def on_add_peer(self, id: PublicKey, peer: PeerInfo) -> None:
        try:
            self.queue.put_nowait((id, peer))
        except:
            pass
        
    def on_remove_peer(self, id: PublicKey, peer: PeerInfo) -> None:
        pass


class MyP2pListener(P2pListener):
    """
    """
    def __init__(self, core: EthCore) -> None:
        self.core = core

    def on_protocols(self, protocols: list[Protocol]) -> None:
        for protocol in protocols:
            if isinstance(protocol, Eth):
                self.core.on_eth(protocol)


queue = Queue(10000)

def program1(queue: Queue) -> None:
    node_core = NodeDiscCore()
    node_core.dpt_register_listener(RLPxDPTListener(queue))
    trio.run(node_core.bind)

async def program2() -> None:
    rlpx_core = RLPxCore(queue)
    eth_core = EthCore()
    rlpx_core.p2p_register_listener(MyP2pListener(eth_core))
    async with trio.open_nursery() as base_loop:
        base_loop.start_soon(rlpx_core.bind)
        base_loop.start_soon(eth_core.bind)


if __name__ == "__main__":
    p1 = Process(target=program1, args=(queue,))
    p1.start()
    trio.run(program2)
    p1.terminate()