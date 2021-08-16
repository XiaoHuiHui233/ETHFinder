#!/usr/bin/env python
# -*- codeing:utf-8 -*-

"""A implementation of core controller of node discovery protocol.
"""

__author__ = "XiaoHuiHui"
__version__ = "1.1"

import ipaddress
import logging
from logging import Formatter, FileHandler, StreamHandler
import secrets

import trio
from eth_keys.datatypes import PublicKey
from parse import parse

from nodedisc import DPT, DPTListener, UDPServer, ControllerV4, ListenerV4
from nodedisc import PeerInfo
from dnsdisc import dns
import config as opts
from store import peer as peer_store

logger = logging.getLogger("core.nodedisc")
fmt = Formatter("%(asctime)s [%(name)s][%(levelname)s] %(message)s")
fh = FileHandler("./logs/core/nodedisc.log", "w", encoding="utf-8")
sh = StreamHandler()
fh.setFormatter(fmt)
sh.setFormatter(fmt)
fh.setLevel(logging.INFO)
sh.setLevel(logging.INFO)
logger.addHandler(fh)
logger.addHandler(sh)


class MyListenerV4(ListenerV4):
    """
    """
    def __init__(self, dpt: DPT) -> None:
        self.dpt = dpt
        self.rckey_to_id: dict[str, PublicKey] = {}

    async def on_ping_timeout(self, peer: PeerInfo) -> None:
        rckey = f"{peer.address}:{peer.udp_port}"
        if rckey in self.rckey_to_id:
            self.dpt.remove_peer(self.rckey_to_id[rckey])
            self.rckey_to_id.pop(rckey)

    async def on_pong(self, peer: PeerInfo, id: PublicKey) -> None:
        rckey = f"{peer.address}:{peer.udp_port}"
        if rckey in self.rckey_to_id:
            self.dpt.remove_peer(self.rckey_to_id[rckey])
        self.rckey_to_id[rckey] = id
        self.dpt.add_peer(peer, id)
    
    async def on_find_neighbours(self, peer: PeerInfo,
            target: PublicKey) -> None:
        nodes = self.dpt.get_closest_peers(target)
        await self.controller.neighbours(peer, nodes)
    
    async def on_neighbours(self, nodes: list[PeerInfo]) -> None:
        for peer in nodes:
            rckey = f"{peer.address}:{peer.udp_port}"
            if rckey not in self.rckey_to_id:
                await self.controller.ping(peer)
                await trio.sleep(opts.DIFFER_TIME)
    
    async def on_enrresponse(self, enr: bytes) -> None:
        pass


class NodeDiscCore:
    """
    """
    def __init__(self) -> None:
        self.dpt = DPT(
            opts.PRIVATE_KEY,
            opts.NODES_PER_KBUCKET,
            opts.NUM_ROUTING_TABLE_BUCKETS,
            opts.CLOSEST_NODE_NUM
        )
        self.server = UDPServer(opts.LOCK_TIMEOUT)
        self.my_listener_v4 = MyListenerV4(self.dpt)

    def dpt_register_listener(self, listener: DPTListener) -> None:
        self.dpt.register_listener(listener)

    async def bind(self) -> None:
        async with trio.open_nursery() as node_disc_loop:
            node_disc_loop.start_soon(
                self.server.bind,
                "0.0.0.0",
                opts.MY_PEER.udp_port
            )
            self.controller_v4 = ControllerV4(
                node_disc_loop,
                opts.PRIVATE_KEY,
                opts.MY_PEER,
                opts.ENR_SEQ,
                opts.ENR,
                opts.PING_TIMEOUT
            )
            self.controller_v4.register_listener(self.my_listener_v4)
            self.server.register_controller(self.controller_v4)
            await trio.sleep(1)
            node_disc_loop.start_soon(self.bootstrap, opts.BOOTNODES)
            node_disc_loop.start_soon(self.refresh_loop)

    async def bootstrap(self, bootnodes: list[str]) -> None:
        for boot_node in bootnodes:
            id, ip, port = parse("enode://{}@{}:{}", boot_node)
            peer = PeerInfo(
                ipaddress.ip_address(ip),
                int(port),
                int(port)
            )
            await self.controller_v4.ping(peer)
            await trio.sleep(opts.DIFFER_TIME)
        for ip, port in peer_store.read_peers():
            peer = PeerInfo(
                ipaddress.ip_address(ip),
                int(port),
                int(port)
            )
            await self.controller_v4.ping(peer)
            await trio.sleep(opts.DIFFER_TIME)

    async def alive_check(self) -> None:
        for peer in self.dpt.get_peers():
            await self.controller_v4.ping(peer)
            await trio.sleep(opts.DIFFER_TIME)

    async def query_dns_nodes(self, dns_networks: list[str]) -> None:
        for network in dns_networks:
            dns_peers = dns.get_peers(network, 20)
            logger.info(
                f"Adding {len(dns_peers)} from {network} DNS tree."
            )
            for peer in dns_peers:
                await self.controller_v4.ping(PeerInfo.remake(peer))
                await trio.sleep(opts.DIFFER_TIME)

    async def refresh(self) -> None:
        peers = self.dpt.get_peers()
        logger.info(
            f"Start refreshing. Now {len(self.dpt)} peers in table."
        )
        for peer in peers:
            await self.controller_v4.find_neighbours(
                peer,
                PublicKey(secrets.token_bytes(64))
            )
            await trio.sleep(opts.DIFFER_TIME)

    async def refresh_loop(self) -> None:
        cnt = 0
        async with trio.open_nursery() as refresh_loop:
            while True:
                refresh_loop.start_soon(self.refresh)
                if cnt == 0:
                    refresh_loop.start_soon(self.alive_check)
                    refresh_loop.start_soon(
                        self.query_dns_nodes,
                        opts.DNS_NETWORKS
                    )
                cnt += 1
                cnt %= 6
                await trio.sleep(opts.REFRESH_INTERVAL)