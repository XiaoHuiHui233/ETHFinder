#!/usr/bin/env python
# -*- codeing:utf-8 -*-

"""
"""

__author__ = "XiaoHuiHui"
__version__ = "1.0"

import ipaddress
from ipaddress import IPv4Address, IPv6Address
import secrets
import base64
from typing import Union

import rlp
from eth_hash.auto import keccak
from eth_keys import KeyAPI
from eth_keys.datatypes import PrivateKey

from nodedisc import PeerInfo
from store import block

IPAddress = Union[IPv4Address, IPv6Address]


def get_enr(enr_seq: int, ip: IPAddress, port: int,
        private_key: PrivateKey) -> bytes:
    content = [
        int.to_bytes(enr_seq, 1, "big"),
        b"id",
        b"v4",
        b"ip",
        int.to_bytes(int(ip), 4, "big"),
        b"secp256k1",
        private_key.public_key.to_compressed_bytes(),
        b"udp",
        int.to_bytes(port, 2, "big", signed=False),
    ]
    raw_data = rlp.encode(content)
    sig = KeyAPI().ecdsa_sign(keccak(raw_data), private_key)
    record = [sig.to_bytes()] + content
    data = rlp.encode(record)
    b64 = base64.urlsafe_b64encode(data).rstrip(b"=")
    return b"".join([b"enr:", b64])


# Basic config
PRIVATE_KEY = PrivateKey(secrets.token_bytes(32))
# PRIVATE_KEY = KeyAPI.PrivateKey(bytes.fromhex("15b95cadffae45bb1cf7b8a7f643cbf1a6073ac588e57a88ae0cdb70c35d82fe"))
MY_PEER = PeerInfo(
    ipaddress.ip_address("104.250.52.28"), # ip address
    30303,                                 # udp port
    30303                                  # tcp port
)
# DPT config
NODES_PER_KBUCKET = 16
NUM_ROUTING_TABLE_BUCKETS = 256
CLOSEST_NODE_NUM = 3
# UDP Server config
LOCK_TIMEOUT = 3
# ENR config
ENR_SEQ = 1
ENR = get_enr(ENR_SEQ, MY_PEER.address, MY_PEER.udp_port, PRIVATE_KEY)
# Node Discovery config
PING_TIMEOUT = 5
REFRESH_INTERVAL = 10
DIFFER_TIME = 0.1
# DNS Discovery
# EIP-1459 ENR tree urls to query for peer discovery
DNS_NETWORKS = [
	"enrtree://AKA3AM6LPBYEUDMVNU3BSVQJ5AD45Y7YPOHJLEF6W26QOE4VTUDPE@all.mainnet.ethdisco.net"
]
MAX_DNS_PEERS = 200
# NodeDisc boot nodes
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
# RLPx network config
MAX_PEERS = 500
EIP8 = True
RLPX_TIMEOUT = 5
RLPX_LOCK_TIMEOUT = 3
REFILL_INTERVALL = 10
# RLPx protocol config
RLPX_PROTOCOL_VERSION = 5
RLPX_PROTOCOL_LENGTH = 16
RLPX_PING_INTERVAL = 15
RLPX_PING_TIMEOUT = 5
RLPX_HELLO_TIMEOUT = 5
CLIENT_ID = "Ethereum Finder (version: 1.0 beta) made by XiaoHuiHui using python3 and trio."
REMOTE_ID_FILTER = []
# Eth procotol config
ETH_STATUS_TIMEOUT = 5
NETWORK_ID = 1 # mainnet
GENESIS_HASH = bytes.fromhex("d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3")
HARD_FORK_BLOCK = 12965000 # london hard fork
HARD_FORK_HASH = bytes.fromhex("b715077d")
NEXT_FORK = 0
# Eth parsing config
PRINT_INTERVAL = 10
MSG_TIMEOUT = 3
# Now status
NOW_HEIGHT, NOW_HASH, NOW_TD = block.read_latest_block()
# web client
SERVICE_INTERVAL = 10
POST_BLOCK_URLS = [
    "http://172.17.0.1:8088/block",
    "http://block_monitor:8893/block"
]
POST_TICK_URLS = [
    "http://172.17.0.1:8088/balance",
    "http://tick_server:8889/info"
]
# web service
WEB_ADRESS = "0.0.0.0"
WEB_PORT = 8089