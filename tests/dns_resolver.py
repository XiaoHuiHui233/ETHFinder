import logging
import sys

sys.path.append("./")

if True:  # noqa: E401
    from ..dnsdisc import resolver

logging.basicConfig(
    format="%(asctime)s [%(name)s][%(levelname)s] %(message)s",
    level=logging.DEBUG,
    handlers=[
        # StreamHandler(),
        # FileHandler("./server.log", "w")
    ]
)

# test for get 2000 enrs
enrs = resolver.get_enrs(
    "enrtree://AKA3AM6LPBYEUDMVNU3BSVQJ5AD45Y7YPOHJLEF6W26QOE4VTUDPE@"
    "all.mainnet.ethdisco.net",
    200
)

# all enrs got were stored in this
rckey_list: list[str] = []

for enr in enrs:
    rckey_list.append(f"{enr.content['ip']}:{enr.content['udp']}")

print(
    f"total peers: {len(rckey_list)}, "
    f"after deduplication: {len(set(rckey_list))}"
)
print()
print(rckey_list[:10])
