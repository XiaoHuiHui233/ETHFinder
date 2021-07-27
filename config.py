#!/usr/bin/env python
# -*- codeing:utf-8 -*-

"""
"""

__author__ = "XiaoHuiHui"
__version__ = "1.0"

import ipaddress
import secrets
import atexit

from eth_keys import KeyAPI
import ujson

from dpt.dnsdisc.enr import PeerNetworkInfo
from rlpx.procotols.procotol import Capability


# Basic config
PRIVATE_KEY = KeyAPI.PrivateKey(secrets.token_bytes(32))
# PRIVATE_KEY = KeyAPI.PrivateKey(bytes.fromhex("15b95cadffae45bb1cf7b8a7f643cbf1a6073ac588e57a88ae0cdb70c35d82fe"))

# DNS Discovery
# EIP-1459 ENR tree urls to query for peer discovery
DNS_NETWORKS = [
	"enrtree://AKA3AM6LPBYEUDMVNU3BSVQJ5AD45Y7YPOHJLEF6W26QOE4VTUDPE@all.mainnet.ethdisco.net"
]
MAX_DNS_PEERS = 200

# KBucket config
NODES_PER_KBUCKET = 16
NUM_ROUTING_TABLE_BUCKETS = 256
CLOSEST_NODE_NUM = 3

# DPTServer config
# Timeout for peer requests
SERVER_TIMEOUT = 3
# Network info to send a long a request
SERVER_ENDPOINT = PeerNetworkInfo(ipaddress.ip_address("0.0.0.0"), 30303, 30303)

# DPT config
# Interval for peer table refresh
REFRESH_INTERVAL = 10
MAX_DPT_PEERS = 2000

BOOTNODES = [
    # Geth Bootnodes
    # from https:#github.com/ethereum/go-ethereum/blob/1bed5afd92c22a5001aff01620671caccd94a6f8/params/bootnodes.go#L22
    "enode://d860a01f9722d78051619d1e2351aba3f43f943f6f00718d1b9baa4101932a1f5011f16bb2b1bb35db20d6fe28fa0bf09636d26a87d31de9ec6203eeedb1f666@18.138.108.67:30303",   # bootnode-aws-ap-southeast-1-001
	"enode://22a8232c3abc76a16ae9d6c3b164f98775fe226f0917b0ca871128a74a8e9630b458460865bab457221f1d448dd9791d24c4e5d88786180ac185df813a68d4de@3.209.45.79:30303",     # bootnode-aws-us-east-1-001
	"enode://ca6de62fce278f96aea6ec5a2daadb877e51651247cb96ee310a318def462913b653963c155a0ef6c7d50048bba6e6cea881130857413d9f50a621546b590758@34.255.23.113:30303",   # bootnode-aws-eu-west-1-001
	"enode://279944d8dcd428dffaa7436f25ca0ca43ae19e7bcf94a8fb7d1641651f92d121e972ac2e8f381414b80cc8e5555811c2ec6e1a99bb009b3f53c4c69923e11bd8@35.158.244.151:30303",  # bootnode-aws-eu-central-1-001
	"enode://8499da03c47d637b20eee24eec3c356c9a2e6148d6fe25ca195c7949ab8ec2c03e3556126b0d7ed644675e78c4318b08691b7b57de10e5f0d40d05b09238fa0a@52.187.207.27:30303",   # bootnode-azure-australiaeast-001
	"enode://103858bdb88756c71f15e9b5e09b56dc1be52f0a5021d46301dbbfb7e130029cc9d0d6f73f693bc29b665770fff7da4d34f3c6379fe12721b5d7a0bcb5ca1fc1@191.234.162.198:30303", # bootnode-azure-brazilsouth-001
	"enode://715171f50508aba88aecd1250af392a45a330af91d7b90701c436b618c86aaa1589c9184561907bebbb56439b8f8787bc01f49a7c77276c58c1b09822d75e8e8@52.231.165.108:30303",  # bootnode-azure-koreasouth-001
	"enode://5d6d7cd20d6da4bb83a1d28cadb5d409b64edf314c0335df658c1a54e32c7c4a7ab7823d57c39b6a757556e68ff1df17c748b698544a55cb488b52479a92b60f@104.42.217.25:30303",   # bootnode-azure-westus-001
]

# RLPx config
RLPX_TIMEOUT = 10
MAX_PEERS = 500
CLIENT_ID = "Ethereum Finder (version: 1.0 beta) made by XiaoHuiHui using python3 and trio."
REMOTE_ID_FILTER = []
REFILL_INTERVALL = 10
EIP8 = True
CAPABILITIES = [
    # Capability("eth", 62, 8),
    Capability("eth", 63, 17),
    Capability("eth", 64, 29),
    Capability("eth", 65, 29),
    # Capability("eth", 66, 29),
]

# ETH procotol config
GENESIS_HASH = "d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3"
# berlin hard fork
HARD_FORK_BLOCK = 12244000
HARD_FORK_HASH = "0eb440f6"
# london is defined
NEXT_FORK = 0
# NEXT_FORK = 12965000
# NEXT_FORK_HASH = "b715077d"

NOW_HEIGHT = 0
NOW_HASH = b""
NOW_TD = 0
with open("./config.json", "r") as rf:
    d = ujson.load(rf)
    NOW_HEIGHT = int(d["now"]["height"])
    NOW_HASH = bytes.fromhex(d["now"]["hash"])
    NOW_TD = int(d["now"]["td"])

@atexit.register
def save():
    with open("./config.json", "w") as wf:
        ujson.dump(
            {
                "now": {
                    "height": str(NOW_HEIGHT),
                    "hash": NOW_HASH.hex(),
                    "td": str(NOW_TD)
                }
            },
            wf,
            ensure_ascii=False,
            indent=4
        )

PROD_PORT = 18745