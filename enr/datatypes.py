#!/usr/bin/env python
# -*- codeing:utf-8 -*-
"""The realization of the data structure of the DNS discovery protocol.
"""

__author__ = "XiaoHuiHui"

import base64
import ipaddress
import typing
from ipaddress import IPv4Address, IPv6Address
from typing import Any, NamedTuple, Optional, TypedDict

import rlp
from eth_hash.auto import keccak
from eth_keys.datatypes import PrivateKey, PublicKey, Signature
from eth_keys.main import KeyAPI

IPAddress = IPv4Address | IPv6Address


def base64_padding(raw: str) -> str:
    """Add padding to the end of a non-standard base64 string to return
    it as a standardized base64 string.

    Since python's base64 parsing library only supports complete base64
    strings that comply with RFC4648. But the definition in the Ethereum
    specification is non-standard, it removes the padding at the end of
    the string. So this function is used to refill it.

    See Reference in EIP-1459:
    https://github.com/ethereum/EIPs/blob/master/EIPS/eip-1459.md

    Also see: https://www.rfc-editor.org/rfc/rfc4648.txt

    :param str raw: Non-standard base64 string.
    :return str: Standard base64 string with paddings.
    """
    missing_padding = len(raw) % 4
    for _ in range(4 - missing_padding):
        raw += "="
    return raw


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


def _decode_enr_content(
    data: dict[str, bytes]
) -> tuple[ENRContent, dict[str, Any]]:
    content: ENRContent = {
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
        None if "tcp6" not in data else _decode_port(data["tcp6"]),
        "udp6":
        None if "udp6" not in data else _decode_port(data["udp6"]),
    }
    extra = {}
    for key in data:
        if key not in (
            "id", "secp256k1", "ip", "tcp", "udp", "ip6", "tcp6", "udp6"
        ):
            extra[key] = data[key]
    return content, extra


class ENR(NamedTuple):
    signature: Signature
    seq: int
    content: ENRContent
    extra: dict[str, Any]
    order: list[str]

    def __hash__(self) -> int:
        return hash(self.signature) ^ hash(self.seq)

    def to_RLP(self) -> list[int | bytes | str]:
        r: list[int | bytes | str] = [
            self.signature.to_bytes()[:-1],
            self.seq,
        ]
        for key in self.order:
            if key in self.content:
                if self.content[key] is None:
                    continue
                r.append(key)
                match key:
                    case "secp256k1":
                        v = typing.cast(PublicKey, self.content[key])
                        r.append(v.to_compressed_bytes())
                    case "ip" | "ip6":
                        v = typing.cast(IPAddress, self.content[key])
                        r.append(int(v))
                    case _:
                        v = typing.cast(int | str, self.content[key])
                        r.append(v)
            else:
                r.append(key)
                r.append(self.extra[key])
        return r

    def to_text(self) -> str:
        rlps = self.to_RLP()
        rlp_encoded: bytes = rlp.encode(rlps)  # type: ignore
        raw = base64.urlsafe_b64encode(rlp_encoded)
        return f"enr:{raw.decode().rstrip('=')}"

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
        order: list[str] = []
        # Convert ENR key/value pairs to object
        obj: dict[str, Any] = {}
        for i in range(0, len(kvs), 2):
            order.append(kvs[i].decode())
            obj[kvs[i].decode()] = kvs[i + 1]
        content, extra = _decode_enr_content(obj)
        if content["secp256k1"] is not None:
            assert (
                KeyAPI().ecdsa_verify(msg_hash, sig, content["secp256k1"])
            ), "Unable to verify ENR node record signature."
        return cls(sig, seq, content, extra, order)

    @classmethod
    def from_text(cls, text: str) -> "ENR":
        # ENRs are RLP encoded and written to DNS TXT entries as base64
        # url-safe strings.
        enr_bytes = base64.urlsafe_b64decode(base64_padding(text[4:]))
        enr_rlp: list[bytes] = rlp.decode(enr_bytes)  # type: ignore
        return ENR.from_RLP(enr_rlp)

    @classmethod
    def from_sign(
        cls,
        prikey: PrivateKey,
        seq: int,
        ip: str,
        udp_port: int,
        tcp_port: int
    ) -> "ENR":
        pubkey = prikey.public_key
        content = [
            seq,
            "id",
            "v4",
            "secp256k1",
            pubkey.to_compressed_bytes(),
            "ip",
            ip,
            "tcp",
            tcp_port,
            "udp",
            udp_port
        ]
        encode: bytes = rlp.encode(content)  # type: ignore
        sig = KeyAPI().ecdsa_sign(keccak(encode), prikey)
        return cls(
            sig,
            seq,
            {
                "id": "v4",
                "secp256k1": pubkey,
                "ip": typing.cast(IPv4Address, ipaddress.ip_address(ip)),
                "tcp": tcp_port,
                "udp": udp_port,
                "ip6": None,
                "tcp6": None,
                "udp6": None
            },
            {},
            ["id", "secp256k1", "tcp", "udp"]
        )
