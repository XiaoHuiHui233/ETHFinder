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
from dpt.classes import PeerNetworkInfo, PeerInfo
from dpt.dnsdisc import dns
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
fh = FileHandler("./server.log", "w")
sh = StreamHandler()
fh.setFormatter(fmt)
sh.setFormatter(fmt)
fh.setLevel(logging.INFO)
sh.setLevel(logging.INFO)
logger.addHandler(fh)
logger.addHandler(sh)

ls = [
    "104.236.90.200:30303",
    "116.202.134.159:30303",
    "128.199.255.38:30303",
    "134.209.33.143:30303",
    "134.209.94.9:30303",
    "135.148.55.25:30303",
    "135.181.118.112:30303",
    "135.181.178.46:30303",
    "135.181.221.94:30303",
    "148.251.155.59:30303",
    "148.251.235.183:30303",
    "148.251.81.250:30303",
    "149.28.93.113:30303",
    "157.90.90.29:30303",
    "159.65.127.53:30303",
    "162.55.4.245:30303",
    "164.90.212.211:30303",
    "185.183.15.13:30303",
    "222.128.13.29:30303",
    "3.89.250.111:30303",
    "34.89.249.173:30303",
    "45.48.168.16:30303",
    "46.101.182.163:30303",
    "46.183.217.208:30303",
    "47.108.245.123:30303",
    "47.252.12.199:30303",
    "51.210.118.26:30303",
    "51.89.40.114:30303",
    "54.36.127.197:30304",
    "54.38.92.154:30303",
    "66.222.189.77:30303",
    "78.111.99.226:30310",
    "83.163.69.214:30303",
    "85.214.152.123:30301",
    "87.123.40.80:30303",
    "92.34.148.130:30303",
    "95.216.21.176:30304"
]


async def main():
    async with trio.open_nursery() as base_loop:
        dpt = DPT(opts.PRIVATE_KEY, base_loop)
        rlpx = RLPx(opts.PRIVATE_KEY, dpt, base_loop)
        await dpt.server.bind()
        base_loop.start_soon(rlpx.bind)
        base_loop.start_soon(dpt.server.recv_loop)
        base_loop.start_soon(dpt.refresh_loop)
        base_loop.start_soon(rlpx.refill_loop)
        dns_peers = dns.get_peers(opts.DNS_NETWORKS)
        logger.info(f"Adding {len(dns_peers)} from DNS tree.")
        base_loop.start_soon(dpt.add_peers, dns_peers)
        for boot_node in opts.BOOTNODES:
            id, ip, port = parse("enode://{}@{}:{}", boot_node)
            peer = PeerInfo(
                PublicKey(bytes.fromhex(id)),
                ipaddress.ip_address(ip),
                int(port),
                int(port)
            )
            base_loop.start_soon(dpt.add_peer, peer)
        for ss in ls:
            sss = ss.split(":")
            address = sss[0]
            port = sss[1]
            peer = PeerNetworkInfo(
                ipaddress.ip_address(address),
                int(port),
                int(port)
            )
            base_loop.start_soon(dpt.add_peer, peer)
        from controller import eth_controller
        await eth_controller.bind()
        base_loop.start_soon(eth_controller.print_loop)

trio.run(main)