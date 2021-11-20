from dnsdisc import dns


# test for get 2000 peers
peers = dns.get_peers(
    "enrtree://AKA3AM6LPBYEUDMVNU3BSVQJ5AD45Y7YPOHJLEF6W26QOE4VTUDPE@"
    "all.mainnet.ethdisco.net",
    2000
)

# all peers got were stored in this
rckey_list = []

for peer in peers:
    rckey_list.append(f"{peer.address}:{peer.udp_port}")

print(
    f"total peers: {len(rckey_list)}, "
    f"after deduplication: {len(set(rckey_list))}"
)
