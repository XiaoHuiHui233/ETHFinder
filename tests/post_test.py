import traceback

import trio
from httpx import AsyncClient

import config as opts


async def test():
    for url in opts.POST_TICK_URLS:
        try:
            async with AsyncClient() as client:
                r = await client.post(
                    url,
                    json={
                        "block_ts": 1628935532,
                        "timestamp": 1628935532,
                        "block_hash":
                        "5a0b54d5dc17e0aadc383d2db43b0a0d3e029c4c",
                        "block_id": 13022497,
                        "amount0": "33495.775825",
                        "amount1": "2.041048939533870299",
                        "sqrt_price":
                        f"0x{1376622538332305416138451960000000:x}",
                        "tick_current": 195265,
                        "ex_amount": "2190.829375",
                        "ex_price": "2.041048939533870299",
                        "info": "test"
                    }
                )
                print(f"{url} done! {r.status_code}")
        except Exception:
            print(f"error detail: {traceback.format_exc()}")
    for url in opts.POST_BLOCK_URLS:
        try:
            async with AsyncClient() as client:
                r = await client.post(
                    url,
                    json={
                        "block_ts": 1628935532,
                        "timestamp": 1628935532,
                        "block_hash":
                        "5a0b54d5dc17e0aadc383d2db43b0a0d3e029c4c",
                        "block_id": 13022497,
                        "sqrt_price":
                        f"0x{1376622538332305416138451960000000:x}",
                        "tick_current": 195265,
                        "info": "test"
                    }
                )
                print(f"{url} done! {r.status_code}")
        except Exception:
            print(f"error detail: {traceback.format_exc()}")


trio.run(test)
