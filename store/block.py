#!/usr/bin/env python
# -*- codeing:utf-8 -*-
"""A implementation of block data store module.
"""

__author__ = "XiaoHuiHui"
__version__ = "1.1"

import ujson


def read_latest_block() -> tuple[int, bytes, int]:
    with open("./datas/block.json", "r") as rf:
        d = ujson.load(rf)
        now_height = d["now"]["height"]
        now_hash = bytes.fromhex(d["now"]["hash"])
        now_td = int(d["now"]["td"])
        return now_height, now_hash, now_td


def write_latest_block(height: int, hash: bytes, td: int) -> None:
    with open("./datas/block.json", "w") as wf:
        ujson.dump(
            {
                "now": {
                    "height": height, "hash": hash.hex(), "td": str(td)
                }
            },
            wf,
            ensure_ascii=False,
            indent=4
        )
