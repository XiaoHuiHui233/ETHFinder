#!/usr/bin/env python
# -*- codeing:utf-8 -*-
"""
"""

__author__ = "XiaoHuiHui"

import asyncio
import logging
import signal
import sys
from multiprocessing import Process

import uvloop
from eth_keys.datatypes import PrivateKey

sys.path.append("./")

if True:  # noqa: E401
    import forks
    from enr.datatypes import ENR
    from nodedisc import KBucketParams, NodeDisc
    from rlpx.main import EthControllerParams, RLPx

logging.basicConfig(
    format="%(asctime)s [%(name)s][%(levelname)s] %(message)s",
    level=logging.DEBUG,
    handlers=[
        # StreamHandler(),
        # FileHandler("./server.log", "w")
    ]
)
uvloop.install()

PRIVATE_KEY = PrivateKey(
    bytes.fromhex(
        "9cc81c95762e34d3dbc2bade47ca93c176823193809ad1bb05b0b0976ae24187"
    )
)
SEQ = 1
ME = ENR.from_sign(
    PRIVATE_KEY,
    SEQ,
    "104.250.52.28",
    30304,
    30304,
    forks.fork_hash,
    forks.fork_next
)

DNS_NETWORKS = [
    "enrtree://AKA3AM6LPBYEUDMVNU3BSVQJ5AD45Y7YPOHJLEF6W26QOE4VTUDPE@"
    "all.mainnet.ethdisco.net"
]
# NodeDisc boot nodes
BOOTNODES = [
    # Geth Bootnodes from
    # https://github.com/ethereum/go-ethereum/blob/1bed5afd92c22a5001aff01620671caccd94a6f8/params/bootnodes.go#L22
    "enode://d860a01f9722d78051619d1e2351aba3f43f943f6f00718d1b9baa4101932a1f5011f16bb2b1bb35db20d6fe28fa0bf09636d26a87d31de9ec6203eeedb1f666@18.138.108.67:30303",  # bootnode-aws-ap-southeast-1-001
    "enode://22a8232c3abc76a16ae9d6c3b164f98775fe226f0917b0ca871128a74a8e9630b458460865bab457221f1d448dd9791d24c4e5d88786180ac185df813a68d4de@3.209.45.79:30303",  # bootnode-aws-us-east-1-001
    "enode://ca6de62fce278f96aea6ec5a2daadb877e51651247cb96ee310a318def462913b653963c155a0ef6c7d50048bba6e6cea881130857413d9f50a621546b590758@34.255.23.113:30303",  # bootnode-aws-eu-west-1-001
    "enode://279944d8dcd428dffaa7436f25ca0ca43ae19e7bcf94a8fb7d1641651f92d121e972ac2e8f381414b80cc8e5555811c2ec6e1a99bb009b3f53c4c69923e11bd8@35.158.244.151:30303",  # bootnode-aws-eu-central-1-001
    "enode://8499da03c47d637b20eee24eec3c356c9a2e6148d6fe25ca195c7949ab8ec2c03e3556126b0d7ed644675e78c4318b08691b7b57de10e5f0d40d05b09238fa0a@52.187.207.27:30303",  # bootnode-azure-australiaeast-001
    "enode://103858bdb88756c71f15e9b5e09b56dc1be52f0a5021d46301dbbfb7e130029cc9d0d6f73f693bc29b665770fff7da4d34f3c6379fe12721b5d7a0bcb5ca1fc1@191.234.162.198:30303",  # bootnode-azure-brazilsouth-001
    "enode://715171f50508aba88aecd1250af392a45a330af91d7b90701c436b618c86aaa1589c9184561907bebbb56439b8f8787bc01f49a7c77276c58c1b09822d75e8e8@52.231.165.108:30303",  # bootnode-azure-koreasouth-001
    "enode://5d6d7cd20d6da4bb83a1d28cadb5d409b64edf314c0335df658c1a54e32c7c4a7ab7823d57c39b6a757556e68ff1df17c748b698544a55cb488b52479a92b60f@104.42.217.25:30303",  # bootnode-azure-westus-001
]
GENESIS_HASH = bytes.fromhex(
    "d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3"
)


nodedisc = NodeDisc(
    200,
    PRIVATE_KEY,
    ME,
    KBucketParams(200, 256),
    DNS_NETWORKS,
    BOOTNODES,
    "/tmp/nodedisc",
    "./datas/peers"
)
rlpx = RLPx(
    PRIVATE_KEY,
    200,
    "/tmp/nodedisc",
    "ETHFinder/v3.0/linux-amd64/Python3.10.4 (made by XiaoHuiHui)",
    EthControllerParams(
        1,
        GENESIS_HASH,
        forks.fork_hash,
        forks.fork_next,
        "./datas/newest.json"
    ),
    None
)
stopped = False


def stop() -> None:
    global stopped
    if stopped:
        return
    print("Received SIGINT or SIGTERM, try to close service.")
    asyncio.create_task(nodedisc.close())
    stopped = True


def do_nothing() -> None:
    pass


def node_disc() -> None:
    loop = asyncio.new_event_loop()
    loop.add_signal_handler(signal.SIGINT, stop)
    loop.add_signal_handler(signal.SIGTERM, stop)
    loop.create_task(nodedisc.bind("0.0.0.0", 30304))
    try:
        loop.run_forever()
    except Exception:
        pass
    finally:
        loop.close()


def rlpx_eth() -> None:
    loop = asyncio.new_event_loop()
    loop.add_signal_handler(signal.SIGINT, do_nothing)
    loop.add_signal_handler(signal.SIGTERM, do_nothing)
    loop.create_task(rlpx.bind("0.0.0.0", 30304))
    try:
        loop.run_forever()
    except Exception:
        pass
    finally:
        loop.close()


if __name__ == "__main__":
    p = Process(target=rlpx_eth)
    p.start()
    node_disc()
    p.join()
