#!/usr/bin/env python
# -*- codeing:utf-8 -*-

"""A implementation of services, include web service and store
service.
"""

__author__ = "XiaoHuiHui"
__version__ = "1.1"

import logging
from logging import Formatter, FileHandler, StreamHandler
from multiprocessing import Queue
from typing import Any
import traceback
from decimal import Decimal

import trio
from httpx import AsyncClient
from quart_trio import QuartTrio
from hypercorn.config import Config
from hypercorn.trio import serve

from store import tick
import config as opts

logger = logging.getLogger("core.service")
fmt = Formatter("%(asctime)s [%(name)s][%(levelname)s] %(message)s")
fh = FileHandler("./logs/core/service.log", "w", encoding="utf-8")
sh = StreamHandler()
fh.setFormatter(fmt)
sh.setFormatter(fmt)
fh.setLevel(logging.INFO)
sh.setLevel(logging.INFO)
logger.addHandler(fh)
logger.addHandler(sh)

d = tick.read_latest_tick()

receive_ts = d["receive_ts"]
block_ts = d["block_ts"]
block_id = d["block_id"]
block_hash = bytes.fromhex(d["block_hash"])
sqrt_price = int(d["sqrt_price"])
latest_tick = d["tick"]


class StoreService:
    """
    """
    def __init__(self, channel: Queue) -> None:
        self.channel = channel

    async def bind(self) -> None:
        async with trio.open_nursery() as server_loop:
            server_loop.start_soon(self.listen_channel)
            server_loop.start_soon(self.output_info)

    async def output_info(self) -> None:
        while True:
            logger.info(
                f"StoreService is alive. "
                f"Queue size: {self.channel.qsize()}"
            )
            await trio.sleep(opts.SERVICE_INTERVAL)
    
    async def listen_channel(self) -> None:
        while True:
            try:
                datas: dict[str: Any] = self.channel.get_nowait()
            except Exception:
                await trio.sleep(0)
                continue
            if datas["type"] == "new_block":
                await self.handle_new_block(datas)
            elif datas["type"] == "uniswap":
                await self.handle_uniswap(datas)

    async def handle_new_block(self, datas: dict[str, Any]) -> None:
        for url in opts.POST_BLOCK_URLS:
            try:
                async with AsyncClient() as client:
                    r = await client.post(
                        url,
                        json = {
                            "timestamp": datas["receive_ts"],
                            "block_ts": datas["block_ts"],
                            "block_id": datas["height"],
                            "block_hash": datas["hash"].hex(),
                            "sqrt_price": f"0x{sqrt_price:x}",
                            "tick_current": latest_tick,
                            "info": "eth_finder"
                        }
                    )
                    logger.info(
                        f"Post new block to {url}(HTTP {r.status_code})."
                    )
            except Exception:
                logger.error(
                    f"Error on post new block to {url}.\n"
                    f"Detail: {traceback.format_exc()}"
                )

    async def handle_uniswap(self, datas: dict[str, Any]) -> None:
        global receive_ts, block_ts, block_id, block_hash
        global sqrt_price, latest_tick
        receive_ts = datas["receive_ts"]
        block_ts = datas["block_ts"]
        block_id = datas["height"]
        block_hash = datas["hash"]
        sqrt_price = datas["sqrt_price"]
        latest_tick = datas["tick"]
        tick.write_latest_tick(
            {
                "receive_ts": receive_ts,
                "block_ts": block_ts,
                "block_id": block_id,
                "block_hash": block_hash.hex(),
                "sqrt_price": str(sqrt_price),
                "tick": latest_tick
            }
        )
        balance0 = Decimal(datas["balance0"]) / Decimal("1000000")
        balance1 = Decimal(datas["balance1"]) / Decimal("1000000000000000000")
        amount0 = Decimal(datas["amount0"]) / Decimal("1000000")
        amount1 = Decimal(datas["amount1"]) / Decimal("1000000000000000000")
        for url in opts.POST_TICK_URLS:
            try:
                async with AsyncClient() as client:
                    r = await client.post(
                        url,
                        json = {
                            "timestamp": datas["receive_ts"],
                            "block_ts": datas["block_ts"],
                            "block_id": datas["height"],
                            "block_hash": datas["hash"].hex(),
                            "amount0": str(balance0),
                            "amount1": str(balance1),
                            "sqrt_price": f"0x{datas['sqrt_price']:x}",
                            "tick_current": datas["tick"],
                            "ex_amount": str(abs(amount0)),
                            "ex_price": str(abs(amount0 / amount1)),
                            "info": "eth_finder"
                        }
                    )
                    logger.info(
                        f"Post tick to {url}(HTTP {r.status_code})."
                    )
            except Exception:
                logger.error(
                    f"Error on post tick to {url}.\n"
                    f"Detail: {traceback.format_exc()}"
                )


app = QuartTrio("ETHFinder")

@app.route("/tick")
async def get_tick():
    return {
        "receive_ts": receive_ts,
        "block_ts": block_ts,
        "block_id": block_id,
        "block_hash": block_hash.hex(),
        "sqrt_price": str(sqrt_price),
        "tick": latest_tick
    }

async def start_web_service() -> None:
    config = Config()
    config.bind = f"{opts.WEB_ADRESS}:{opts.WEB_PORT}"
    await serve(app, config)