import traceback

import ujson
import requests

try:
    r = requests.post(
        "http://172.17.0.1:8088/balance",
        ujson.dumps({
            "block_ts": 1628935532,
            "timestamp": 1628935532,
            "block_hash": "5a0b54d5dc17e0aadc383d2db43b0a0d3e029c4c",
            "block_id": 13022497,
            "amount0": "33495775825",
            "amount1": "2041048939533870299",
            "sqrt_price": "1376622538332305416138451960000000",
            "tick_current": 195265,
            "info": "test"
        })
    )
    print(r)
    print("done!")
except Exception:
    print(f"error detail: {traceback.format_exc()}")