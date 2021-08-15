#!/usr/bin/env python
# -*- codeing:utf-8 -*-

"""A implementation of tick data store module.
"""

__author__ = "XiaoHuiHui"
__version__ = "1.1"

from typing import Any

import ujson


def read_latest_tick() -> tuple[int, int]:
    with open("./datas/tick.json", "r") as rf:
        return ujson.load(rf)


def write_latest_tick(d: dict[str, Any]) -> None:
    with open("./datas/tick.json", "w") as wf:
        ujson.dump(d, wf, ensure_ascii=False, indent=4)