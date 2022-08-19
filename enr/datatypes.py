#!/usr/bin/env python
# -*- codeing:utf-8 -*-
"""The realization of the data structure of the DNS discovery protocol.
"""

__author__ = "XiaoHuiHui"

import ipaddress
import typing
from ipaddress import IPv4Address, IPv6Address
from typing import Any, NamedTuple, Optional, TypedDict

import rlp
from eth_hash.auto import keccak
from eth_keys.datatypes import PublicKey, Signature
from eth_keys.main import KeyAPI

IPAddress = IPv4Address | IPv6Address


class ENRContent(TypedDict):
    id: str
    secp256k1: Optional[PublicKey]
    ip: Optional[IPv4Address]
    tcp: Optional[int]
    udp: Optional[int]
    ip6: Optional[IPv6Address]
    tcp6: Optional[int]
    udp6: Optional[int]


def _decode_port(data: bytes) -> int:
    port = int.from_bytes(data, "big", signed=False)
    if port <= 0 or port > 65535:
        raise ValueError(f"Invalid port: {port}.")
    return port


def _decode_enr_content(data: dict[str, bytes]) -> ENRContent:
    return {
        "id":
        data["id"].decode(),
        "secp256k1":
        None if "secp256k1" not in data else
        PublicKey.from_compressed_bytes(data["secp256k1"]),
        "ip":
        None if "ip" not in data else
        typing.cast(IPv4Address, ipaddress.ip_address(data["ip"])),
        "tcp":
        None if "tcp" not in data else _decode_port(data["tcp"]),
        "udp":
        None if "udp" not in data else _decode_port(data["udp"]),
        "ip6":
        None if "ip6" not in data else
        typing.cast(IPv6Address, ipaddress.ip_address(data["ip6"])),
        "tcp6":
        None if "tcp" not in data else _decode_port(data["tcp6"]),
        "udp6":
        None if "udp" not in data else _decode_port(data["udp6"]),
    }


class ENR(NamedTuple):
    signature: Signature
    seq: int
    content: ENRContent

    def to_RLP(self) -> list[int | bytes | str]:
        r: list[int | bytes | str] = [
            self.signature.to_bytes(),
            self.seq,
        ]
        for key in self.content:
            if self.content[key] is None:
                continue
            r.append(key)
            if key == "secp256k1":
                v = typing.cast(PublicKey, self.content[key])
                r.append(v.to_compressed_bytes())
            elif key in ("ip", "ip6"):
                v = typing.cast(IPAddress, self.content[key])
                r.append(int(v))
            else:
                v = typing.cast(int | str, self.content[key])
                r.append(v)
        return r

    @classmethod
    def from_RLP(cls, data: list[bytes]) -> "ENR":
        # The public key of some parsing results is not 65-byte, indicating
        # that it does not contain recid bits. But the analysis here doesn't
        # seem to need this bit, just add one bit to it.
        sig_bytes = bytearray(data[0])
        if len(sig_bytes) == 64:
            sig_bytes.append(0)
        sig = Signature(bytes(sig_bytes))
        msg_hash = keccak(rlp.encode(data[1:]))  # type: ignore
        seq = int.from_bytes(data[1], "big", signed=False)
        kvs = data[2:]
        # Convert ENR key/value pairs to object
        obj: dict[str, Any] = {}
        for i in range(0, len(kvs), 2):
            obj[kvs[i].decode()] = kvs[i + 1]
        content = _decode_enr_content(obj)
        if content["secp256k1"] is not None:
            assert (
                KeyAPI().ecdsa_verify(msg_hash, sig, content["secp256k1"])
            ), "Unable to verify ENR node record signature."
        return cls(sig, seq, content)
