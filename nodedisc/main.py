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

from nodedisc.ipc import IPCServer

from . import server
from .datatypes import Addr, Node
from .discv4.controller import ControllerV4, ListenerV4
from .dpt import DPT, KBucketParams

logger = logging.getLogger("nodedisc.main")


class NodeDisc(ListenerV4):
    """
    """
    def __init__(
        self,
        max_enrs: int,
        private_key: PrivateKey,
        me: ENR,
        kb_params: KBucketParams,
        ipc_path: Optional[str] = None,
        cache_path: Optional[str] = None
    ) -> None:
        self.max_enrs = max_enrs
        self.pubkey = private_key.public_key
        self.dpt = DPT(private_key, kb_params)
        self.controller_v4 = ControllerV4(private_key, me)
        self.ipc_path = ipc_path
        self.cache_path = cache_path
        self.enrs: dict[PublicKey, ENR] = {}
        self.running = False
        self.need_more_friends = False

    def _check_running(self) -> None:
        if not self.running:
            logger.error("UDP server is not running!")
            raise RuntimeError("UDP server is not running!")

    def write(self) -> None:
        if self.cache_path is not None:
            logger.info(f"Write cache nodes to {self.cache_path}")
            with open(self.cache_path, "w", encoding="utf8") as wf:
                for id in self.enrs:
                    wf.write(self.enrs[id].to_text() + "\n")

    async def read(self) -> None:
        self._check_running()
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

    async def query_dns_nodes(self, dns_networks: list[str]) -> None:
        self._check_running()
        for network in dns_networks:
            enrs = resolver.get_enrs(network, 20)
            logger.info(
                f"Added {len(enrs)} from {network} DNS tree."
            )
            for enr in enrs:
                if enr.content["id"] != "v4":
                    continue
                if "ip" not in enr.content:
                    continue
                ip = typing.cast(IPv4Address, enr.content["ip"])
                if "udp" not in enr.content:
                    continue
                port = typing.cast(int, enr.content["udp"])
                self.controller_v4.ping(Addr(ip, port))
                await asyncio.sleep(0.2)
                if len(self.enrs) >= self.max_enrs:
                    break

    async def bootstrap(self, bootnodes: list[str]) -> None:
        self._check_running()
        logger.info(f"Added {len(bootnodes)} boot nodes.")
        for boot_node in bootnodes:
            ip: str
            port: str
            _, ip, port = parse.parse(  # type: ignore
                "enode://{}@{}:{}", boot_node
            )
            addr = Addr(ipaddress.ip_address(ip), int(port))
            self.controller_v4.ping(addr)
            await asyncio.sleep(0.2)
            if len(self.enrs) >= self.max_enrs:
                break

    def find_friends(self) -> None:
        logger.info("Peers is not enough, try to find more nodes.")
        random_nodes = self.dpt.shuffle_all(10)
        for node in random_nodes:
            self.controller_v4.find_node(
                self.dpt.id, node.id, Addr(node.address, node.udp_port)
            )

    def ban(self, id: PublicKey) -> None:
        if id in self.enrs:
            self.enrs.pop(id)
            node = self.dpt.remove(id)
            if node is not None:
                self.controller_v4.ban(Addr(node.address, node.udp_port))

    async def bind(
        self,
        host: str,
        port: int,
        bootnodes: list[str] = [],
        dns_networks: list[str] = []
    ) -> None:
        logger.info("Service is binding.")
        transport, _server = await server.startup(host, port)
        self.transport = transport
        self.running = True
        _server.register_controller(self.controller_v4)
        self.controller_v4.register_listener(self)
        if self.ipc_path is not None:
            self.ipc = IPCServer(self.ipc_path)
            self.ipc_task = asyncio.create_task(self.ipc.bind())
        await self.bootstrap(bootnodes)
        await self.query_dns_nodes(dns_networks)
        await self.read()

    async def run(self) -> None:
        logger.info("Service is running.")
        while self.running:
            logger.info(f"Now peers: {len(self.enrs)}, (Max: {self.max_enrs})")
            if not self.need_more_friends:
                if len(self.enrs) < self.max_enrs // 2:
                    self.need_more_friends = True
            if self.need_more_friends:
                if len(self.enrs) >= self.max_enrs * 9 // 10:
                    self.need_more_friends = False
            if self.need_more_friends:
                self.find_friends()
                await asyncio.sleep(10)
            else:
                await asyncio.sleep(60)
            self.write()
        logger.info("Service is stopped.")
        if self.ipc_path is not None:
            await self.ipc_task
        logger.info("All is stopped.")

    def on_node(self, node: Node, enr_seq: Optional[int]) -> None:
        if node.id == self.pubkey:
            return
        addr = Addr(node.address, node.udp_port)
        if node.id not in self.dpt:
            old = self.dpt.add(node)
            if old is not None:
                self.controller_v4.ping(Addr(old.address, old.udp_port))
            self.controller_v4.enr_request(node.id, addr)
        elif enr_seq is not None:
            if node.id not in self.enrs or self.enrs[node.id].seq < enr_seq:
                self.controller_v4.enr_request(node.id, addr)

    def get_nodes(self, target: PublicKey) -> list[Node]:
        return self.dpt.closest(target, 16)

    def on_nodes(self, nodes: list[Node]) -> None:
        for node in nodes:
            if node.id not in self.dpt and node.id != self.pubkey:
                self.controller_v4.ping(Addr(node.address, node.udp_port))

    def on_enr(self, id: PublicKey, enr: ENR) -> None:
        if id not in self.enrs or self.enrs[id].seq < enr.seq:
            if enr.content["id"] != "v4":
                return
            if "ip" not in enr.content:
                return
            if "tcp" not in enr.content:
                return
            if "udp" not in enr.content:
                return
            self.enrs[id] = enr
            id_str = id.to_bytes().hex()[:7]
            addr = Addr(
                ipaddress.ip_address(typing.cast(str, enr.content["ip"])),
                typing.cast(int, enr.content["udp"])
            )
            if self.ipc_path is not None:
                asyncio.create_task(
                    self.ipc.boardcast_new_enr(id, enr)
                )
            logger.info(f"ENR list added {id_str}({addr}).")

    def on_timeout(self, id: PublicKey) -> None:
        if id in self.dpt:
            self.dpt.remove(id)
        if id in self.enrs:
            self.enrs.pop(id)

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
