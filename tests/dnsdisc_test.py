import sys

sys.path.append("./")

if True:  # noqa: E401
    from dnsdisc import resolver

# test for get 2000 enrs
enrs = resolver.get_enrs(
    "enrtree://AKA3AM6LPBYEUDMVNU3BSVQJ5AD45Y7YPOHJLEF6W26QOE4VTUDPE@"
    "all.mainnet.ethdisco.net",
    10
)

# all enrs got were stored in this
rckey_list: list[str] = []

for enr in enrs:
    rckey_list.append(f"{enr.content['ip']}:{enr.content['udp']}")

print(
    f"total peers: {len(rckey_list)}, "
    f"after deduplication: {len(set(rckey_list))}"
)
