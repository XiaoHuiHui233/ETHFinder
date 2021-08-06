#!/usr/bin/env python
# -*- codeing:utf-8 -*-

"""
"""

__author__ = "XiaoHuiHui"
__version__ = "1.1"

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from eth_hash.auto import keccak

CIPHER = algorithms.AES
MODE = modes.ECB


def xor(left: bytes, right: bytes) -> bytes:
    left_num = int.from_bytes(left, byteorder="big")
    right_num = int.from_bytes(right , byteorder="big")
    return int.to_bytes(
        left_num ^ right_num,
        byteorder="big",
        length = max(len(left), len(right))
    )


class MAC:
    """
    """
    
    def __init__(self, secret: bytes, nonce: bytes, packet: bytes) -> None:
        self.hash = keccak.new(xor(secret, nonce) + packet)
        self.secret = secret
    
    def update(self, data: bytes) -> None:
        self.hash.update(data)
    
    def update_header(self, header_ciphertext: bytes) -> bytes:
        aes = Cipher(
            CIPHER(self.secret),
            MODE(),
            default_backend()
        ).encryptor()
        header_mac_seed = xor(
            aes.update(self.digest()[:16]),
            header_ciphertext
        )
        self.update(header_mac_seed)
        return self.digest()[:16]
    
    def update_body(self, frame_ciphertext: bytes) -> None:
        self.update(frame_ciphertext)
        aes = Cipher(
            CIPHER(self.secret),
            MODE(),
            default_backend()
        ).encryptor()
        prev = self.digest()[:16]
        frame_mac_seed = xor(
            aes.update(prev),
            prev
        )
        self.update(frame_mac_seed)
        return self.digest()[:16]
    
    def digest(self) -> bytes:
        return self.hash.digest()