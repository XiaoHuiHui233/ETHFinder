import ipaddress
from typing import Union
import base64
import logging
import secrets

import trio
import rlp
from eth_keys.main import KeyAPI
from eth_keys.datatypes import PublicKey
from eth_hash.auto import keccak
import parse

from nodedisc import DPT, UDPServer, ControllerV4, ListenerV4, PeerInfo
from dnsdisc import dns
import config as opts

RLP = Union[list[list[bytes]], list[bytes], bytes]

logging.basicConfig(
    format="%(asctime)s [%(name)s][%(levelname)s] %(message)s",
    level=logging.INFO,
    handlers=[
        # StreamHandler(),
        # FileHandler("./server.log", "w")
    ]
)
logger = logging.getLogger("test.nodedisc")
fmt = logging.Formatter("%(asctime)s [%(name)s][%(levelname)s] %(message)s")
fh = logging.FileHandler("./logs/test_nodedisc.log", "w")
sh = logging.StreamHandler()
fh.setFormatter(fmt)
sh.setFormatter(fmt)
fh.setLevel(logging.INFO)
sh.setLevel(logging.INFO)
logger.addHandler(fh)
logger.addHandler(sh)

dpt = DPT(
    opts.PRIVATE_KEY, opts.NODES_PER_KBUCKET, opts.NUM_ROUTING_TABLE_BUCKETS
)
server = UDPServer(3)
rckey_to_id: dict[str, PublicKey] = {}


def get_enr(enr_seq: int) -> bytes:
    content = [
        int.to_bytes(enr_seq, 1, "big"),
        b"id",
        b"v4",
        b"ip",
        int.to_bytes(int(ipaddress.ip_address("104.250.52.28")), 4, "big"),
        b"secp256k1",
        opts.PUBLIC_KEY.to_compressed_bytes(),
        b"udp",
        int.to_bytes(30303, 2, "big", signed=False),
    ]
    raw_data = rlp.encode(content)
    sig = KeyAPI().ecdsa_sign(keccak(raw_data), opts.PRIVATE_KEY)
    record = [sig.to_bytes()] + content
    data = rlp.encode(record)
    b64 = base64.urlsafe_b64encode(data).rstrip(b"=")
    return b"".join([b"enr:", b64])


class TestListenerV4(ListenerV4):
    """
    """
    async def on_ping_timeout(self, peer: PeerInfo) -> None:
        rckey = f"{peer.address}:{peer.udp_port}"
        # logger.info(f"on ping timeout {rckey}")
        if rckey in rckey_to_id:
            dpt.remove_peer(rckey_to_id[rckey])
            rckey_to_id.pop(rckey)

    async def on_pong(self, peer: PeerInfo, id: PublicKey) -> None:
        rckey = f"{peer.address}:{peer.udp_port}"
        # logger.info(f"on pong {rckey}")
        if rckey in rckey_to_id:
            dpt.remove_peer(rckey_to_id[rckey])
        rckey_to_id[rckey] = id
        dpt.add_peer(peer, id)

    async def on_find_neighbours(
        self, peer: PeerInfo, target: PublicKey
    ) -> None:
        # rckey = f"{peer.address}:{peer.udp_port}"
        # logger.info(f"on find neighbours {rckey}")
        nodes = dpt.get_closest_peers(target, opts.CLOSEST_NODE_NUM)
        await self.controller.neighbours(peer, nodes)

    async def on_neighbours(self, nodes: list[PeerInfo]) -> None:
        for peer in nodes:
            rckey = f"{peer.address}:{peer.udp_port}"
            if rckey not in rckey_to_id:
                await self.controller.ping(peer)
                await trio.sleep(0.1)

    async def on_enrresponse(self, enr: bytes) -> None:
        pass


async def bootstrap(controller_v4: ControllerV4) -> None:
    for boot_node in opts.BOOTNODES:
        id, ip, port = parse.parse("enode://{}@{}:{}", boot_node)
        peer = PeerInfo(ipaddress.ip_address(ip), int(port), int(port))
        await controller_v4.ping(peer)
        await trio.sleep(0.1)


async def alive_check(controller_v4: ControllerV4) -> None:
    for peer in dpt.get_peers():
        await controller_v4.ping(peer)
        await trio.sleep(0.1)


async def query_dns_nodes(controller_v4: ControllerV4) -> None:
    for network in opts.DNS_NETWORKS:
        dns_peers = dns.get_peers(network, 20)
        logger.info(f"Adding {len(dns_peers)} from {network} DNS tree.")
        for peer in dns_peers:
            await controller_v4.ping(PeerInfo.remake(peer))
            await trio.sleep(0.1)


async def refresh(controller_v4: ControllerV4) -> None:
    peers = dpt.get_peers()
    logger.info(f"Start refreshing. Now {len(dpt)} peers in table.")
    for peer in peers:
        await controller_v4.find_neighbours(
            peer, PublicKey(secrets.token_bytes(64))
        )
        await trio.sleep(0.1)


async def refresh_loop(controller_v4: ControllerV4) -> None:
    cnt = 0
    async with trio.open_nursery() as refresh_loop:
        while True:
            refresh_loop.start_soon(refresh, controller_v4)
            if cnt == 0:
                refresh_loop.start_soon(alive_check, controller_v4)
                refresh_loop.start_soon(query_dns_nodes, controller_v4)
            cnt += 1
            cnt %= 6
            await trio.sleep(opts.REFRESH_INTERVAL)


async def test() -> None:
    async with trio.open_nursery() as nursery:
        nursery.start_soon(server.bind, "0.0.0.0", 30303)
        controller_v4 = ControllerV4(
            nursery,
            opts.PRIVATE_KEY,
            PeerInfo(ipaddress.ip_address("104.250.52.28"), 30303, 30303),
            1,
            get_enr(1),
            10
        )
        listener_v4 = TestListenerV4()
        controller_v4.register_listener(listener_v4)
        server.register_controller(controller_v4)
        await trio.sleep(1)
        nursery.start_soon(bootstrap, controller_v4)
        nursery.start_soon(refresh_loop, controller_v4)


trio.run(test)
