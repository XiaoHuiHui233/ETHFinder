#!/usr/bin/env python
# -*- codeing:utf-8 -*-
"""A implementation of core controller of node discovery protocol.
"""

__author__ = "XiaoHuiHui"

import asyncio
import ipaddress
import logging
import os
import typing
from ipaddress import IPv4Address
from typing import Optional

import parse
from dnsdisc import resolver
from enr.datatypes import ENR
from eth_keys.datatypes import PrivateKey, PublicKey
from lru import LRU

from . import server
from .datatypes import Addr, Node
from .discv4.controller import ControllerV4, ListenerV4
from .dpt import DPT, KBucketParams
from .ipc import IPCServer

logger = logging.getLogger("nodedisc.main")


def decode_from_enode(enode: str) -> Node:
    id: str
    ip: str
    port: str
    id, ip, port = parse.parse(  # type: ignore
        "enode://{}@{}:{}", enode
    )
    tcp_port: str
    udp_port: str
    if "?" in port:
        tcp_port, udp_port = parse.parse(  # type: ignore
            "{}?discport={}", port
        )
    else:
        tcp_port = udp_port = port
    return Node(
        ipaddress.ip_address(ip),
        int(udp_port),
        int(tcp_port),
        PublicKey(bytes.fromhex(id))
    )


class NodeDisc(ListenerV4):
    """
    """
    def __init__(
        self,
        max_enrs: int,
        private_key: PrivateKey,
        me: ENR,
        kb_params: KBucketParams,
        dns_networks: list[str] = [],
        bootnodes: list[str] = [],
        ipc_path: Optional[str] = None,
        cache_path: Optional[str] = None
    ) -> None:
        self.max_enrs = max_enrs
        self.pubkey = private_key.public_key
        self.dpt = DPT(private_key, kb_params)
        self.me = me
        self.controller_v4 = ControllerV4(private_key, me)
        self.dns_networks = dns_networks
        self.bootnodes = bootnodes
        self.ipc_path = ipc_path
        self.cache_path = cache_path
        self.need_check_enrs: dict[Addr, ENR] = LRU(10000)
        self.need_check_nodes: dict[Addr, Node] = LRU(10000)
        self.enrs: dict[PublicKey, ENR] = {}
        self.running = False
        self.need_more_friends = True

    def ban(self, id: PublicKey) -> None:
        id_str = id.to_bytes().hex()[:7]
        logger.info(f"Ban id {id_str}.")
        if id in self.dpt:
            node = self.dpt.remove(id)
            if node is not None:
                self.controller_v4.ban(Addr(node.address, node.udp_port))
        if id in self.enrs:
            self.enrs.pop(id)

    def write(self) -> None:
        if self.cache_path is not None:
            logger.info(f"Write cache nodes to {self.cache_path}")
            with open(self.cache_path, "w", encoding="utf8") as wf:
                for id in self.enrs:
                    wf.write(self.enrs[id].to_text() + "\n")

    async def read(self) -> None:
        if self.cache_path is not None and os.path.exists(self.cache_path):
            logger.info(f"Read cache nodes from {self.cache_path}")
            with open(self.cache_path, "r", encoding="utf8") as rf:
                for line in rf:
                    enr = ENR.from_text(line[:-1])
                    ip = typing.cast(IPv4Address, enr.content["ip"])
                    port = typing.cast(int, enr.content["udp"])
                    self.controller_v4.ping(Addr(ip, port))
                    await asyncio.sleep(0.2)
                    if len(self.enrs) >= self.max_enrs:
                        break

    def check_enr_online(self, enr: ENR) -> None:
        ip = typing.cast(IPv4Address, enr.content["ip"])
        port = typing.cast(int, enr.content["udp"])
        addr = Addr(ip, port)
        self.need_check_enrs[addr] = enr
        self.controller_v4.ping(addr)

    async def query_dns_nodes(self, length: int = 20) -> None:
        for network in self.dns_networks:
            enrs = resolver.get_enrs(network, length)
            logger.info(f"Added {len(enrs)} from {network} DNS tree.")
            for enr in enrs:
                if enr.content["id"] != "v4":
                    continue
                if "ip" not in enr.content:
                    continue
                if "udp" not in enr.content:
                    continue
                self.check_enr_online(enr)
                await asyncio.sleep(0.2)
                if len(self.enrs) >= self.max_enrs:
                    break

    def check_node_online(self, node: Node) -> None:
        addr = Addr(node.address, node.udp_port)
        self.need_check_nodes[addr] = node
        self.controller_v4.ping(addr)

    async def bootstrap(self) -> None:
        for boot_node in self.bootnodes:
            node = decode_from_enode(boot_node)
            self.check_node_online(node)
            await asyncio.sleep(0.2)
            if len(self.enrs) >= self.max_enrs:
                break
        logger.info(f"Added {len(self.bootnodes)} boot nodes.")

    def find_friends(self) -> None:
        logger.info("Peers is not enough, try to find more nodes.")
        random_nodes = self.dpt.shuffle_all(10)
        for node in random_nodes:
            self.controller_v4.find_node(
                self.dpt.id, node.id, Addr(node.address, node.udp_port)
            )

    async def bind(self, host: str, port: int) -> None:
        logger.info("Service is binding.")
        transport, _server = await server.startup(host, port)
        self.transport = transport
        self.running = True
        _server.register_controller(self.controller_v4)
        self.controller_v4.register_listener(self)
        if self.ipc_path is not None:
            self.ipc = IPCServer(self.ipc_path)
            self.ipc_task = asyncio.create_task(self.ipc.bind())
        await self.bootstrap()
        await self.query_dns_nodes()
        await self.read()

    async def run(self) -> None:
        logger.info("Service is running.")
        while self.running:
            logger.info(
                f"Now peers: {len(self.dpt)}, Now Nodes: {len(self.enrs)} "
                f"(Max: {self.max_enrs})"
            )
            if not self.need_more_friends:
                if len(self.enrs) < self.max_enrs // 2:
                    self.need_more_friends = True
            if self.need_more_friends:
                if len(self.enrs) >= self.max_enrs * 9 // 10:
                    self.need_more_friends = False
            if self.need_more_friends:
                if len(self.enrs) <= 0:
                    await self.query_dns_nodes(100)
                self.find_friends()
                await asyncio.sleep(10)
            else:
                await asyncio.sleep(60)
            self.write()
        logger.info("Service is stopped.")
        if self.ipc_path is not None:
            await self.ipc_task
        logger.info("All is stopped.")

    def process_old(self, old: Optional[Node]) -> None:
        if old is not None:
            logger.info(f"Old node {old} is replaced, reping it.")
            self.controller_v4.ping(Addr(old.address, old.udp_port))

    def on_node(self, node: Node, enr_seq: Optional[int]) -> None:
        if node.id == self.pubkey:
            logger.warning("received a node of me!")
            return
        addr = Addr(node.address, node.udp_port)
        if node.id not in self.dpt:
            logger.info(f"received a new node {node}, add it to DHT.")
            old = self.dpt.add(node)
            self.process_old(old)
            self.controller_v4.enr_request(node.id, addr)
        elif enr_seq is not None:
            if node.id not in self.enrs or self.enrs[node.id].seq < enr_seq:
                logger.info(f"received a known node {node}, update it.")
                self.controller_v4.enr_request(node.id, addr)
            else:
                logger.info(f"received a known node {node}, ignore it.")
        else:
            logger.info(f"received a known node {node}, but no seq.")

    def _enr_check(self, enr: ENR) -> bool:
        if enr.content["id"] != "v4":
            return False
        if "ip" not in enr.content:
            return False
        if "tcp" not in enr.content:
            return False
        if "udp" not in enr.content:
            return False
        if enr.eth is not None:
            assert self.me.eth is not None
            if enr.eth["eth"][0][0] != self.me.eth["eth"][0][0]:
                return False
            if enr.eth["eth"][0][1] != self.me.eth["eth"][0][1]:
                return False
        return True

    def on_reply(self, id: PublicKey, addr: Addr) -> None:
        if id == self.dpt.id:
            logger.warning("Record myself!")
            return
        id_str = id.to_bytes().hex()[:7]
        if addr in self.need_check_enrs:
            enr = self.need_check_enrs.pop(addr)
            if not self._enr_check(enr):
                logger.warning(f"Record a trash ENR {id_str}, drop it.")
                return
            self.enrs[id] = enr
            node = Node(
                ipaddress.ip_address(typing.cast(str, enr.content["ip"])),
                typing.cast(int, enr.content["udp"]),
                typing.cast(int, enr.content["tcp"]),
                id
            )
            old = self.dpt.add(node)
            logger.info(f"Use record ENR {node}.")
            self.process_old(old)
        elif addr in self.need_check_nodes:
            node = self.need_check_nodes.pop(addr)
            if id != node.id:
                logger.warning(
                    f"The id from {addr} is different from node record!"
                )
                return
            if node.id in self.dpt:
                return
            old = self.dpt.add(node)
            logger.info(f"Use record Node {node}, try to get ENR.")
            self.process_old(old)
            self.controller_v4.enr_request(node.id, addr)

    def get_nodes(self, target: PublicKey) -> list[Node]:
        return self.dpt.closest(target, 16)

    def on_nodes(self, nodes: list[Node]) -> None:
        for node in nodes:
            if node.id != self.pubkey and node.id not in self.dpt:
                self.controller_v4.ping(Addr(node.address, node.udp_port))
        logger.info(f"received {len(nodes)} nodes, ping them.")

    def on_enr(self, id: PublicKey, enr: ENR) -> None:
        if id == self.dpt.id:
            logger.warning("On ENR myself!")
            return
        id_str = id.to_bytes().hex()[:7]
        logger.info(f"On ENR {id_str}.")
        if id not in self.enrs or self.enrs[id].seq < enr.seq:
            if not self._enr_check(enr):
                logger.warning(f"received a trash ENR {id_str}, ban it.")
                self.ban(id)
                return
            self.enrs[id] = enr
            addr = Addr(
                ipaddress.ip_address(typing.cast(str, enr.content["ip"])),
                typing.cast(int, enr.content["udp"])
            )
            logger.info(f"ENR list added/updated {id_str}({addr}).")
            if self.ipc_path is not None:
                asyncio.create_task(self.ipc.boardcast_new_enr(id, enr))
        else:
            logger.info(f"A outdate useless ENR {id_str}.")

    def on_timeout(self, id: PublicKey) -> None:
        self.ban(id)

    async def close(self) -> None:
        logger.info("Closing.")
        if self.running:
            self.transport.close()
            if self.ipc_path is not None:
                await self.ipc.boardcast_close()
                await self.ipc.close()
            self.running = False

    def force_close(self) -> None:
        logger.info("Force closing.")
        if self.running:
            self.transport.close()
            if self.ipc_path is not None:
                self.ipc_task.cancel("Force closing.")
            self.running = False
