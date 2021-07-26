#!/usr/bin/env python
# -*- codeing:utf-8 -*-

"""
"""

__author__ = "XiaoHuiHui"
__version__ = "1.0"

import ipaddress
import secrets
import atexit

from eth_keys import KeyAPI
import ujson

from dpt.dnsdisc.enr import PeerNetworkInfo
from rlpx.procotols.procotol import Capability


# Basic config
PRIVATE_KEY = KeyAPI.PrivateKey(secrets.token_bytes(32))
# PRIVATE_KEY = KeyAPI.PrivateKey(bytes.fromhex("15b95cadffae45bb1cf7b8a7f643cbf1a6073ac588e57a88ae0cdb70c35d82fe"))

# DNS Discovery
# EIP-1459 ENR tree urls to query for peer discovery
DNS_NETWORKS = [
	"enrtree://AKA3AM6LPBYEUDMVNU3BSVQJ5AD45Y7YPOHJLEF6W26QOE4VTUDPE@all.mainnet.ethdisco.net"
]
MAX_DNS_PEERS = 20

# KBucket config
NODES_PER_KBUCKET = 16
NUM_ROUTING_TABLE_BUCKETS = 256
CLOSEST_NODE_NUM = 3

# DPTServer config
# Timeout for peer requests
SERVER_TIMEOUT = 3
# Network info to send a long a request
SERVER_ENDPOINT = PeerNetworkInfo(ipaddress.ip_address("0.0.0.0"), 30303, 30303)

# DPT config
# Interval for peer table refresh
REFRESH_INTERVAL = 10
MAX_DPT_PEERS = 200

BOOTNODES = [
    'enode://a979fb575495b8d6db44f750317d0f4622bf4c2aa3365d6af7c284339968eef29b69ad0dce72a4d8db5ebb4968de0e3bec910127f134779fbcb0cb6d3331163c@52.16.188.185:30303',  # noqa: E501
    'enode://aa36fdf33dd030378a0168efe6ed7d5cc587fafa3cdd375854fe735a2e11ea3650ba29644e2db48368c46e1f60e716300ba49396cd63778bf8a818c09bded46f@13.93.211.84:30303',  # noqa: E501
    'enode://78de8a0916848093c73790ead81d1928bec737d565119932b98c6b100d944b7a95e94f847f689fc723399d2e31129d182f7ef3863f2b4c820abbf3ab2722344d@191.235.84.50:30303',  # noqa: E501
    'enode://158f8aab45f6d19c6cbf4a089c2670541a8da11978a2f90dbf6a502a4a3bab80d288afdbeb7ec0ef6d92de563767f3b1ea9e8e334ca711e9f8e2df5a0385e8e6@13.75.154.138:30303',  # noqa: E501
    'enode://1118980bf48b0a3640bdba04e0fe78b1add18e1cd99bf22d53daac1fd9972ad650df52176e7c7d89d1114cfef2bc23a2959aa54998a46afcf7d91809f0855082@52.74.57.123:30303',   # noqa: E501

    # Geth Bootnodes
    # from https://github.com/ethereum/go-ethereum/blob/1bed5afd92c22a5001aff01620671caccd94a6f8/params/bootnodes.go#L22  # noqa: E501
    "enode://d860a01f9722d78051619d1e2351aba3f43f943f6f00718d1b9baa4101932a1f5011f16bb2b1bb35db20d6fe28fa0bf09636d26a87d31de9ec6203eeedb1f666@18.138.108.67:30303",  # noqa: E501
    "enode://22a8232c3abc76a16ae9d6c3b164f98775fe226f0917b0ca871128a74a8e9630b458460865bab457221f1d448dd9791d24c4e5d88786180ac185df813a68d4de@3.209.45.79:30303",  # noqa: E501
    "enode://ca6de62fce278f96aea6ec5a2daadb877e51651247cb96ee310a318def462913b653963c155a0ef6c7d50048bba6e6cea881130857413d9f50a621546b590758@34.255.23.113:30303",  # noqa: E501
    "enode://279944d8dcd428dffaa7436f25ca0ca43ae19e7bcf94a8fb7d1641651f92d121e972ac2e8f381414b80cc8e5555811c2ec6e1a99bb009b3f53c4c69923e11bd8@35.158.244.151:30303",  # noqa: E501
    "enode://8499da03c47d637b20eee24eec3c356c9a2e6148d6fe25ca195c7949ab8ec2c03e3556126b0d7ed644675e78c4318b08691b7b57de10e5f0d40d05b09238fa0a@52.187.207.27:30303",  # noqa: E501
    "enode://103858bdb88756c71f15e9b5e09b56dc1be52f0a5021d46301dbbfb7e130029cc9d0d6f73f693bc29b665770fff7da4d34f3c6379fe12721b5d7a0bcb5ca1fc1@191.234.162.198:30303",  # noqa: E501
    "enode://715171f50508aba88aecd1250af392a45a330af91d7b90701c436b618c86aaa1589c9184561907bebbb56439b8f8787bc01f49a7c77276c58c1b09822d75e8e8@52.231.165.108:30303",  # noqa: E501
    "enode://5d6d7cd20d6da4bb83a1d28cadb5d409b64edf314c0335df658c1a54e32c7c4a7ab7823d57c39b6a757556e68ff1df17c748b698544a55cb488b52479a92b60f@104.42.217.25:30303",  # noqa: E501

    # Parity Bootnodes
    # from https://raw.githubusercontent.com/paritytech/parity-ethereum/master/ethcore/res/ethereum/foundation.json  # noqa: E501
    "enode://81863f47e9bd652585d3f78b4b2ee07b93dad603fd9bc3c293e1244250725998adc88da0cef48f1de89b15ab92b15db8f43dc2b6fb8fbd86a6f217a1dd886701@193.70.55.37:30303",  # noqa: E501
    "enode://4afb3a9137a88267c02651052cf6fb217931b8c78ee058bb86643542a4e2e0a8d24d47d871654e1b78a276c363f3c1bc89254a973b00adc359c9e9a48f140686@144.217.139.5:30303",  # noqa: E501
    "enode://c16d390b32e6eb1c312849fe12601412313165df1a705757d671296f1ac8783c5cff09eab0118ac1f981d7148c85072f0f26407e5c68598f3ad49209fade404d@139.99.51.203:30303",  # noqa: E501
    "enode://4faf867a2e5e740f9b874e7c7355afee58a2d1ace79f7b692f1d553a1134eddbeb5f9210dd14dc1b774a46fd5f063a8bc1fa90579e13d9d18d1f59bac4a4b16b@139.99.160.213:30303",  # noqa: E501
    "enode://6a868ced2dec399c53f730261173638a93a40214cf299ccf4d42a76e3fa54701db410669e8006347a4b3a74fa090bb35af0320e4bc8d04cf5b7f582b1db285f5@163.172.131.191:30303",  # noqa: E501
    "enode://66a483383882a518fcc59db6c017f9cd13c71261f13c8d7e67ed43adbbc82a932d88d2291f59be577e9425181fc08828dc916fdd053af935a9491edf9d6006ba@212.47.247.103:30303",  # noqa: E501
    "enode://cd6611461840543d5b9c56fbf088736154c699c43973b3a1a32390cf27106f87e58a818a606ccb05f3866de95a4fe860786fea71bf891ea95f234480d3022aa3@163.172.157.114:30303",  # noqa: E501
    "enode://1d1f7bcb159d308eb2f3d5e32dc5f8786d714ec696bb2f7e3d982f9bcd04c938c139432f13aadcaf5128304a8005e8606aebf5eebd9ec192a1471c13b5e31d49@138.201.223.35:30303",  # noqa: E501
    "enode://0cc5f5ffb5d9098c8b8c62325f3797f56509bff942704687b6530992ac706e2cb946b90a34f1f19548cd3c7baccbcaea354531e5983c7d1bc0dee16ce4b6440b@40.118.3.223:30305",  # noqa: E501
    "enode://1c7a64d76c0334b0418c004af2f67c50e36a3be60b5e4790bdac0439d21603469a85fad36f2473c9a80eb043ae60936df905fa28f1ff614c3e5dc34f15dcd2dc@40.118.3.223:30308",  # noqa: E501
    "enode://85c85d7143ae8bb96924f2b54f1b3e70d8c4d367af305325d30a61385a432f247d2c75c45c6b4a60335060d072d7f5b35dd1d4c45f76941f62a4f83b6e75daaf@40.118.3.223:30309",  # noqa: E501
    "enode://de471bccee3d042261d52e9bff31458daecc406142b401d4cd848f677479f73104b9fdeb090af9583d3391b7f10cb2ba9e26865dd5fca4fcdc0fb1e3b723c786@54.94.239.50:30303",  # noqa: E501
    "enode://4cd540b2c3292e17cff39922e864094bf8b0741fcc8c5dcea14957e389d7944c70278d872902e3d0345927f621547efa659013c400865485ab4bfa0c6596936f@138.201.144.135:30303",  # noqa: E501
    "enode://01f76fa0561eca2b9a7e224378dd854278735f1449793c46ad0c4e79e8775d080c21dcc455be391e90a98153c3b05dcc8935c8440de7b56fe6d67251e33f4e3c@51.15.42.252:30303",  # noqa: E501
    "enode://2c9059f05c352b29d559192fe6bca272d965c9f2290632a2cfda7f83da7d2634f3ec45ae3a72c54dd4204926fb8082dcf9686e0d7504257541c86fc8569bcf4b@163.172.171.38:30303",  # noqa: E501
    "enode://efe4f2493f4aff2d641b1db8366b96ddacfe13e7a6e9c8f8f8cf49f9cdba0fdf3258d8c8f8d0c5db529f8123c8f1d95f36d54d590ca1bb366a5818b9a4ba521c@163.172.187.252:30303",  # noqa: E501
    "enode://bcc7240543fe2cf86f5e9093d05753dd83343f8fda7bf0e833f65985c73afccf8f981301e13ef49c4804491eab043647374df1c4adf85766af88a624ecc3330e@136.243.154.244:30303",  # noqa: E501
    "enode://ed4227681ca8c70beb2277b9e870353a9693f12e7c548c35df6bca6a956934d6f659999c2decb31f75ce217822eefca149ace914f1cbe461ed5a2ebaf9501455@88.212.206.70:30303",  # noqa: E501
    "enode://cadc6e573b6bc2a9128f2f635ac0db3353e360b56deef239e9be7e7fce039502e0ec670b595f6288c0d2116812516ad6b6ff8d5728ff45eba176989e40dead1e@37.128.191.230:30303",  # noqa: E501
    "enode://595a9a06f8b9bc9835c8723b6a82105aea5d55c66b029b6d44f229d6d135ac3ecdd3e9309360a961ea39d7bee7bac5d03564077a4e08823acc723370aace65ec@46.20.235.22:30303",  # noqa: E501
    "enode://029178d6d6f9f8026fc0bc17d5d1401aac76ec9d86633bba2320b5eed7b312980c0a210b74b20c4f9a8b0b2bf884b111fa9ea5c5f916bb9bbc0e0c8640a0f56c@216.158.85.185:30303",  # noqa: E501
    "enode://fdd1b9bb613cfbc200bba17ce199a9490edc752a833f88d4134bf52bb0d858aa5524cb3ec9366c7a4ef4637754b8b15b5dc913e4ed9fdb6022f7512d7b63f181@212.47.247.103:30303",  # noqa: E501
    "enode://cc26c9671dffd3ee8388a7c8c5b601ae9fe75fc0a85cedb72d2dd733d5916fad1d4f0dcbebad5f9518b39cc1f96ba214ab36a7fa5103aaf17294af92a89f227b@52.79.241.155:30303",  # noqa: E501
    "enode://140872ce4eee37177fbb7a3c3aa4aaebe3f30bdbf814dd112f6c364fc2e325ba2b6a942f7296677adcdf753c33170cb4999d2573b5ff7197b4c1868f25727e45@52.78.149.82:30303"  # noqa: E501
]

# RLPx config
RLPX_TIMEOUT = 10
MAX_PEERS = 50
CLIENT_ID = "Ethereum Finder (version: 1.0 beta) made by XiaoHuiHui using python3 and trio."
REMOTE_ID_FILTER = []
REFILL_INTERVALL = 10
EIP8 = True
CAPABILITIES = [
    Capability("eth", 62, 8),
    Capability("eth", 63, 17),
    Capability("eth", 64, 29),
    Capability("eth", 65, 29),
]

# ETH procotol config
GENESIS_HASH = "d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3"
# berlin hard fork
HARD_FORK_BLOCK = 12244000
HARD_FORK_HASH = "0eb440f6"
# london is undefined
NEXT_FORK = 0

NOW_HEIGHT = 0
NOW_HASH = b""
NOW_TD = 0
with open("./config.json", "r") as rf:
    d = ujson.load(rf)
    NOW_HEIGHT = int(d["now"]["height"])
    NOW_HASH = bytes.fromhex(d["now"]["hash"])
    NOW_TD = int(d["now"]["td"])

@atexit.register
def save():
    with open("./config.json", "w") as wf:
        ujson.dump(
            {
                "now": {
                    "height": str(NOW_HEIGHT),
                    "hash": NOW_HASH.hex(),
                    "td": str(NOW_TD)
                }
            },
            wf,
            ensure_ascii=False,
            indent=4
        )

PROD_PORT = 18745