#!/usr/bin/env python
# -*- codeing:utf-8 -*-
"""
"""

import zlib

__author__ = "XiaoHuiHui"

genesis_hash = bytes.fromhex(
    "d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3"
)

chain_id = 1

forks: list[tuple[str, int]] = [
    ("Homestead", 1_150_000),
    ("DAO fork", 1_920_000),
    ("Tangerine whistle", 2_463_000),
    ("Spurious Dragon", 2_675_000),
    ("Byzantium", 4_370_000),
    ("Constantinople", 7_280_000),
    ("Istanbul", 9_069_000),
    ("MuirGlacier", 9_200_000),
    ("Berlin", 12_244_000),
    ("London", 12_965_000),
    ("ArrowGlacier", 13_773_000),
    ("GrayGlacier", 15_050_000),
]

bs = [genesis_hash]
for fork in forks:
    bs.append(int.to_bytes(fork[1], 8, "big", signed=False))

fork_hash = int.to_bytes(zlib.crc32(b"".join(bs)), 4, "big", signed=False)

fork_next = 0
