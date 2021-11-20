#!/usr/bin/env python
# -*- codeing:utf-8 -*-
"""
"""

__author__ = "XiaoHuiHui"
__version__ = "1.1"

from multiprocessing import Process, Queue
import logging
import time

import trio
from eth_keys.datatypes import PublicKey

from core.nodedisc import NodeDiscCore
from core.rlpx import RLPxCore
from core.eth import EthCore
from core.service import StoreService, start_web_service
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
    def __init__(self, channel: Queue) -> None:
        self.channel = channel

    def on_add_peer(self, id: PublicKey, peer: PeerInfo) -> None:
        try:
            self.channel.put_nowait((id, peer))
        except Exception:
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


nodedisc_rlpx_channel = Queue(10000)
eth_web_channel = Queue(10000)


def program1(channel: Queue) -> None:
    node_core = NodeDiscCore()
    node_core.dpt_register_listener(RLPxDPTListener(channel))
    trio.run(node_core.bind)


async def async_program2(channel1: Queue, channel2: Queue) -> None:
    rlpx_core = RLPxCore(channel1)
    eth_core = EthCore(channel2)
    rlpx_core.p2p_register_listener(MyP2pListener(eth_core))
    async with trio.open_nursery() as base_loop:
        base_loop.start_soon(rlpx_core.bind)
        base_loop.start_soon(eth_core.bind)


def program2(channel1: Queue, channel2: Queue) -> None:
    trio.run(async_program2, channel1, channel2)


async def async_program3(channel: Queue) -> None:
    store_service = StoreService(channel)
    async with trio.open_nursery() as base_loop:
        base_loop.start_soon(store_service.bind)
        base_loop.start_soon(start_web_service)


def program3(channel: Queue) -> None:
    trio.run(async_program3, channel)


if __name__ == "__main__":
    p1 = Process(target=program1, args=(nodedisc_rlpx_channel, ))
    p1.start()
    p2 = Process(
        target=program2, args=(nodedisc_rlpx_channel, eth_web_channel)
    )
    p2.start()
    p3 = Process(target=program3, args=(eth_web_channel, ))
    p3.start()
    try:
        while True:
            if not p1.is_alive():
                p2.terminate()
                p3.terminate()
                break
            if not p2.is_alive():
                p1.terminate()
                p3.terminate()
                break
            if not p3.is_alive():
                p1.terminate()
                p2.terminate()
                break
            time.sleep(1)
    except KeyboardInterrupt:
        p1.terminate()
        p2.terminate()
        p3.terminate()
