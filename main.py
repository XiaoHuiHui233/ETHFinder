#!/usr/bin/env python
# -*- codeing:utf-8 -*-

"""
"""

__author__ = "XiaoHuiHui"
__version__ = "1.1"

import ipaddress
import logging
from logging import FileHandler, Formatter, StreamHandler

import trio
from parse import parse
from eth_keys.datatypes import PublicKey

from dpt.dpt import DPT
import config as opts
from dpt.classes import PeerInfo
from rlpx.rlpx import RLPx

logging.basicConfig(
    format="%(asctime)s [%(name)s][%(levelname)s] %(message)s",
    level=logging.INFO,
    handlers=[
        # StreamHandler(),
        # FileHandler("./server.log", "w")
    ]
)
logger = logging.getLogger("main")
fmt = Formatter("%(asctime)s [%(name)s][%(levelname)s] %(message)s")
fh = FileHandler("./logs/server.log", "w")
sh = StreamHandler()
fh.setFormatter(fmt)
sh.setFormatter(fmt)
fh.setLevel(logging.INFO)
sh.setLevel(logging.INFO)
logger.addHandler(fh)
logger.addHandler(sh)


async def main():
    async with trio.open_nursery() as base_loop:
        dpt = DPT(opts.PRIVATE_KEY, base_loop)
        rlpx = RLPx(opts.PRIVATE_KEY, dpt, base_loop)
        await dpt.server.bind()
        base_loop.start_soon(rlpx.bind)
        base_loop.start_soon(dpt.server.recv_loop)
        base_loop.start_soon(dpt.refresh_loop)
        base_loop.start_soon(rlpx.refill_loop)
        for boot_node in opts.BOOTNODES:
            id, ip, port = parse("enode://{}@{}:{}", boot_node)
            peer = PeerInfo(
                PublicKey(bytes.fromhex(id)),
                ipaddress.ip_address(ip),
                int(port),
                int(port)
            )
            base_loop.start_soon(dpt.add_peer, peer)
        from controller import eth_controller
        await eth_controller.bind()

trio.run(main)