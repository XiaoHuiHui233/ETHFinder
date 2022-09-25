#!/usr/bin/env python
# -*- codeing:utf-8 -*-
"""A implementation of core controller of RLPx protocol.
"""

__author__ = "XiaoHuiHui"

import asyncio
import logging
from asyncio import CancelledError
from datetime import datetime
from typing import NamedTuple, Optional

from enr.datatypes import ENR
from eth_keys.datatypes import PrivateKey, PublicKey
from lru import LRU

from .datatypes import DC_REASONS, Addr, Capability
from .ipc import IPCClient
from .peer.p2p import P2pPeer, P2pPeerFactory
from .protocols.eth import EthController
from .server import TCPServer

logger = logging.getLogger("rlpx.main")

eth62 = Capability("eth", 62, 8)
eth63 = Capability("eth", 63, 17)
eth64 = Capability("eth", 64, 29)
eth65 = Capability("eth", 65, 29)
eth66 = Capability("eth", 66, 29)
eth67 = Capability("eth", 67, 29)


def now() -> int:
    return int(datetime.utcnow().timestamp())


class EthControllerParams(NamedTuple):
    network_id: int
    genesis_hash: bytes
    hard_fork_hash: bytes
    next_fork: int
    cache_file: str


class RLPx:
    """
    """
    def __init__(
        self,
        private_key: PrivateKey,
        max_peers: int,
        ipc_client_path: str,
        client_id: str,
        controller_params: EthControllerParams,
        ipc_path: Optional[str] = None
    ) -> None:
        self.pubkey = private_key.public_key
        self.max_peers = max_peers
        self.ipc_client = IPCClient(ipc_client_path)
        self.ipc_path = ipc_path
        self.factory = P2pPeerFactory(private_key, client_id)
        self.eth_controller = EthController(*controller_params, ipc_path)
        self.factory.register_capability(eth62, self.eth_controller.new_eth)
        self.factory.register_capability(eth63, self.eth_controller.new_eth)
        self.factory.register_capability(eth64, self.eth_controller.new_eth)
        self.factory.register_capability(eth65, self.eth_controller.new_eth)
        self.factory.register_capability(eth66, self.eth_controller.new_eth)
        self.factory.register_capability(eth67, self.eth_controller.new_eth)
        self.server = TCPServer(private_key, self.factory, self.on_peer)
        self.conns: dict[Addr, P2pPeer] = {}
        self.peers: dict[Addr, P2pPeer] = {}
        self.ban_list: dict[Addr, int] = LRU(10000)
        self.running = False

    def is_full(self) -> bool:
        return len(self.peers) >= self.max_peers

    def ban(self, addr: Addr) -> None:
        self.ban_list[addr] = now()

    def has_banned(self, addr: Addr) -> bool:
        if addr in self.ban_list:
            last_time = self.ban_list[addr]
            if now() - last_time > 600:
                self.ban_list.pop(addr)
        return addr in self.ban_list

    async def on_client_close(self) -> None:
        await self.close()

    async def on_new_enr(self, id: PublicKey, enr: ENR) -> None:
        assert enr.content["ip"] is not None
        assert enr.content["tcp"] is not None
        assert enr.content["secp256k1"] is not None
        addr = Addr(enr.content["ip"], enr.content["tcp"])
        assert id == enr.content["secp256k1"]
        asyncio.create_task(
            self.server.connect_to(addr, enr.content["secp256k1"]),
            name="on_new_enr"
        )

    async def on_peer(self, peer: P2pPeer) -> None:
        if peer.addr in self.conns:
            logger.warning(f"Peer {peer} is already in conns list.")
            await self.conns[peer.addr].close()
            return
        self.conns[peer.addr] = peer
        await peer.bind()
        if not await peer.has_auth.wait_and_get():
            logger.warning(f"Peer {peer} failed to auth.")
            self.conns.pop(peer.addr)
            return
        if not await peer.has_hello.wait_and_get():
            logger.warning(f"Peer {peer} failed to hello.")
            self.conns.pop(peer.addr)
            return
        if peer.addr in self.peers:
            logger.warning(f"Peer {peer} is already in peers list.")
            await peer.disconnect(DC_REASONS.ALREADY_CONNECTED)
        elif self.is_full():
            logger.warning(f"Peer list is already full, Refuse {peer}.")
            await peer.disconnect(DC_REASONS.TOO_MANY_PEERS)
        elif self.pubkey == peer.remote_id:
            logger.warning("Self peer is connected.")
            await peer.disconnect(DC_REASONS.SAME_IDENTITY)
        elif self.has_banned(peer.addr):
            logger.warning(f"Peer {peer} has been banned.")
            await peer.disconnect(DC_REASONS.UNEXPECTED_IDENTITY)
        else:
            self.conns.pop(peer.addr)
            self.peers[peer.addr] = peer
        await peer.has_closed.wait()
        self.peers.pop(peer.addr)

    async def bind(self, host: str, port: int) -> None:
        logger.info("Service is binding.")
        self.ipc_client.register_callback("new_enr", self.on_new_enr)
        self.ipc_client.register_callback("close", self.on_client_close)
        await self.ipc_client.bind()
        await self.server.bind(host, port)
        await self.eth_controller.bind()
        self.run_task = asyncio.create_task(self.run(), name="rlpx_main")

    async def run(self) -> None:
        self.running = True
        while self.running:
            try:
                await asyncio.sleep(30)
            except CancelledError:
                break
            logger.info(
                f"Now Connections: {len(self.conns)}, "
                f"Now P2P Peers: {len(self.peers)}, "
                f"Max: {self.max_peers}"
            )

    async def close(self) -> None:
        logger.debug("Rlpx main is closing.")
        if self.running:
            self.running = False
            await self.eth_controller.close()
            await self.server.close()
            await self.ipc_client.close()
            self.run_task.cancel()
            await asyncio.sleep(0)
            logger.debug("All peers and conns is closing.")
            await asyncio.gather(
                *[self.peers[addr].disconnect() for addr in self.peers],
                *[self.conns[addr].close() for addr in self.conns],
                return_exceptions=True
            )
            logger.info("All peers and conns is closed.")
            logger.info("Rlpx main is closed.")
            logger.debug(f"Remain tasks: {asyncio.all_tasks()}")
            asyncio.get_event_loop().stop()
