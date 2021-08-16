#!/usr/bin/env python
# -*- codeing:utf-8 -*-

"""A implementation of peer data store module.
"""

__author__ = "XiaoHuiHui"
__version__ = "1.1"

import random

import ujson

MAX_STORE_PEERS = 1000


def read_peers() -> list[tuple[str, int]]:
    with open("./datas/peer.json", "r") as rf:
        ls = ujson.load(rf)
        for d in ls:
            yield (d["ip"], d["port"])


def write_peers(peers: list[str]) -> None:
    for ip, port in read_peers():
        peers.append(f"{ip}:{port}")
    peers = list(set(peers))
    if len(peers) > MAX_STORE_PEERS:
        peers = random.sample(peers, MAX_STORE_PEERS)
    ls = []
    for rckey in peers:
        ss = rckey.split(":")
        if len(ss) == 2:
            ip = ss[0]
            port = ss[1]
            try:
                ls.append({
                    "ip": ip,
                    "port": int(port)
                })
            except Exception:
                continue
    with open("./datas/peer.json", "w") as wf:
        ujson.dump(
            ls,
            wf,
            ensure_ascii=False,
            indent=4
        )