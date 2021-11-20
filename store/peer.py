#!/usr/bin/env python
# -*- codeing:utf-8 -*-
"""A implementation of peer data store module.
"""

__author__ = "XiaoHuiHui"
__version__ = "1.1"

import random

import ujson

MAX_STORE_PEERS = 1000
first = True
cache = None
new_cache = None


def read_peers() -> list[tuple[str, int]]:
    global first, cache, new_cache
    if first:
        with open("./datas/peer.json", "r") as rf:
            ls = ujson.load(rf)
            cache = list(ls)
            new_cache = cache
            first = False
    for d in cache:
        yield (d["ip"], d["port"])
    cache = new_cache


def write_peers(peers: list[str]) -> None:
    global new_cache
    peers += new_cache
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
                    "ip": ip, "port": int(port)
                })
            except Exception:
                continue
    with open("./datas/peer.json", "w") as wf:
        ujson.dump(ls, wf, ensure_ascii=False, indent=4)
    new_cache = peers
