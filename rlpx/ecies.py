import os
import random
import struct
from hashlib import sha256
from typing import cast
import secrets

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import \
    EllipticCurvePrivateKeyWithSerialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.constant_time import bytes_eq
from eth_utils import int_to_big_endian
from eth_keys import KeyAPI
from eth_keys.datatypes import PrivateKey, PublicKey, Signature
from eth_keys.validation import ValidationError
from eth_hash.auto import keccak
import rlp

from rlpx.mac import MAC

PUBKEY_LEN = 64
CIPHER = algorithms.AES
MODE = modes.CTR
CURVE = ec.SECP256K1()
# ECIES using AES256 and HMAC-SHA-256-32
KEY_LEN = 32


def pad32(value: bytes) -> bytes:
    return value.rjust(32, b"\x00")


def padding(value: bytes) -> bytes:
    length = len(value) % 16
    if length > 0:
        return value + (16-length) * b"\0"
    else:
        return value


def xor(left: bytes, right: bytes) -> bytes:
    left_num = int.from_bytes(left, byteorder="big")
    right_num = int.from_bytes(right , byteorder="big")
    return int.to_bytes(
        left_num ^ right_num,
        byteorder="big",
        length = len(left)
    )


class InvalidPublicKey(Exception):
    """
    A custom exception raised when trying to convert bytes
    into an elliptic curve public key.
    """
    pass


def generate_privkey() -> PrivateKey:
    """Generate a new SECP256K1 private key and return it
    """
    privkey = cast(
        EllipticCurvePrivateKeyWithSerialization,
        ec.generate_private_key(CURVE, default_backend()))
    return KeyAPI().PrivateKey(
        pad32(
            int_to_big_endian(
                privkey.private_numbers().private_value
            )
        )
    )


def ecdh_agree(privkey: PrivateKey, pubkey: PublicKey) -> bytes:
    """Performs a key exchange operation using the ECDH algorithm.
    """
    privkey_as_int = int(cast(int, privkey))
    ec_privkey = ec.derive_private_key(
        privkey_as_int,
        CURVE,
        default_backend()
    )
    pubkey_bytes = b"\x04" + pubkey.to_bytes()
    try:
        # either of these can raise a ParseError:
        pubkey_nums = ec.EllipticCurvePublicKey.from_encoded_point(
            CURVE,
            pubkey_bytes
        )
        ec_pubkey = pubkey_nums.public_numbers().public_key(default_backend())
    except ParseError as exc:
        # Not all bytes can be made into valid public keys, see the 
        # warning at
        # https://cryptography.io/en/latest/hazmat/primitives/asymmetric/ec/
        # under EllipticCurvePublicNumbers(x, y)
        raise InvalidPublicKey(str(exc)) from exc
    return ec_privkey.exchange(ec.ECDH(), ec_pubkey)


def encrypt(data: bytes, pubkey: PublicKey,
        shared_mac_data: bytes = b"") -> bytes:
    """Encrypt data with ECIES method to the given public key
    1) generate r = random value
    2) generate shared-secret = kdf( ecdhAgree(r, P) )
    3) generate R = rG [same op as generating a public key]
    4) 0x04 || R || AsymmetricEncrypt(shared-secret, plaintext) || tag
    """
    # 1) generate r = random value
    ephemeral = generate_privkey()

    # 2) generate shared-secret = kdf( ecdhAgree(r, P) )
    key_material = ecdh_agree(ephemeral, pubkey)
    key = kdf(key_material)
    key_enc, key_mac = key[:KEY_LEN // 2], key[KEY_LEN // 2:]

    key_mac = sha256(key_mac).digest()
    # 3) generate R = rG [same op as generating a public key]
    ephem_pubkey = ephemeral.public_key

    # Encrypt
    algo = CIPHER(key_enc)
    iv = os.urandom(algo.block_size // 8)
    ctx = Cipher(algo, MODE(iv), default_backend()).encryptor()
    ciphertext = ctx.update(data) + ctx.finalize()

    # 4) 0x04 || R || AsymmetricEncrypt(shared-secret, plaintext) || tag
    msg = b"\x04" + ephem_pubkey.to_bytes() + iv + ciphertext

    # the MAC of a message (called the tag) as per SEC 1, 3.5.
    tag = hmac_sha256(key_mac, msg[1 + PUBKEY_LEN:] + shared_mac_data)
    return msg + tag


def decrypt(data: bytes, privkey: PrivateKey, shared_mac_data: bytes = b"") -> bytes:
    """Decrypt data with ECIES method using the given private key
    1) generate shared-secret = kdf( ecdhAgree(myPrivKey, msg[1:65]) )
    2) verify tag
    3) decrypt
    ecdhAgree(r, recipientPublic) == ecdhAgree(recipientPrivate, R)
    [where R = r*G, and recipientPublic = recipientPrivate*G]
    """
    if data[:1] != b"\x04":
        raise ParseError("wrong ecies header")

    #  1) generate shared-secret = kdf( ecdhAgree(myPrivKey, msg[1:65]) )
    shared = data[1:1 + PUBKEY_LEN]
    try:
        key_material = ecdh_agree(privkey, PublicKey(shared))
    except InvalidPublicKey as exc:
        raise ParseError(
            f"Failed to generate shared secret with pubkey {shared!r}: {exc}"
        ) from exc
    key = kdf(key_material)
    key_enc, key_mac = key[:KEY_LEN // 2], key[KEY_LEN // 2:]
    key_mac = sha256(key_mac).digest()
    tag = data[-KEY_LEN:]

    # 2) Verify tag
    expected_tag = hmac_sha256(key_mac, data[1 + PUBKEY_LEN:- KEY_LEN] + shared_mac_data)
    if not bytes_eq(expected_tag, tag):
        raise ParseError("Failed to verify tag")

    # 3) Decrypt
    algo = CIPHER(key_enc)
    blocksize = algo.block_size // 8
    iv = data[1 + PUBKEY_LEN:1 + PUBKEY_LEN + blocksize]
    ciphertext = data[1 + PUBKEY_LEN + blocksize:- KEY_LEN]
    ctx = Cipher(algo, MODE(iv), default_backend()).decryptor()
    return ctx.update(ciphertext) + ctx.finalize()


def kdf(key_material: bytes) -> bytes:
    """NIST SP 800-56a Concatenation Key Derivation Function (see section 5.8.1).
    Pretty much copied from geth's implementation:
    https://github.com/ethereum/go-ethereum/blob/673007d7aed1d2678ea3277eceb7b55dc29cf092/crypto/ecies/ecies.go#L167
    """
    key = b""
    hash_ = hashes.SHA256()
    # FIXME: Need to find out why mypy thinks SHA256 has no "block_size" attribute
    hash_blocksize = hash_.block_size  # type: ignore
    reps = ((KEY_LEN + 7) * 8) / (hash_blocksize * 8)
    counter = 0
    while counter <= reps:
        counter += 1
        ctx = sha256()
        ctx.update(struct.pack(">I", counter))
        ctx.update(key_material)
        key += ctx.digest()
    return key[:KEY_LEN]


def hmac_sha256(key: bytes, msg: bytes) -> bytes:
    mac = hmac.HMAC(key, hashes.SHA256(), default_backend())
    mac.update(msg)
    return mac.finalize()


class ParseError(Exception):
    """
    """


class ECIES:
    def __init__(self, private_key: PrivateKey, id: PublicKey,
            remote_id: PublicKey) -> None:
        self.private_key = private_key
        self.public_key = id
        self.remote_pubkey = remote_id
        self.nonce = secrets.token_bytes(32)
        self.ephemeral_private_key = generate_privkey()
        self.ephemeral_pubkey = \
            KeyAPI().private_key_to_public_key(self.ephemeral_private_key)
        self.got_EIP8_auth = False
        self.got_EIP8_ack = False
        self.remote_init_msg = None
        self.remote_nonce = None
        self.ephemeral_shared_secret = None
        self.init_msg = None
        self.ingress_aes = None
        self.egress_aes = None
        self.ingress_mac = None
        self.egress_mac = None
        self.body_size = None

    def parse_auth_plain(self, data: bytes,
            shared_mac_data: bytes = b"") -> bytes:
        prefix = shared_mac_data
        self.remote_init_msg = b"".join((prefix, data))
        try:
            decrypted = decrypt(data, self.private_key, shared_mac_data)
            if not self.got_EIP8_auth:
                if len(decrypted) != 194:
                    raise ParseError("Invalid packet length.")
                sig = Signature(decrypted[:65])
                heid = decrypted[65:97] # 32 bytes
                remote_pubkey = PublicKey(decrypted[97:161])
                remote_nonce = decrypted[161:193]
            else:
                decoded = rlp.decode(decrypted, strict=False)
                sig = Signature(decoded[0][:65])
                heid = None
                remote_pubkey = PublicKey(decoded[1])
                remote_nonce = decoded[2]
        except ValidationError as err:
            raise ParseError(f"Except validation error, detail: {err}")
        # parse packet
        self.remote_pubkey = remote_pubkey # 64 bytes
        self.remote_nonce = remote_nonce # 32 bytes
        if decrypted[193] != 0:
            raise ParseError("Invalid postfix.")
        static_shared_secret = ecdh_agree(self.private_key, self.remote_pubkey)
        self.remote_ephemeral_pubkey = \
            KeyAPI().ecdsa_recover(
                xor(static_shared_secret, self.remote_nonce),
                sig
            )
        self.ephemeral_shared_secret = \
            ecdh_agree(
                self.ephemeral_private_key,
                self.remote_ephemeral_pubkey
            )
        if heid is not None:
            if keccak(self.remote_ephemeral_pubkey) != heid:
                raise ParseError("The hash of the ephemeral key should match.")
    
    def parse_auth_EIP8(self, data: bytes) -> None:
        auth_size = int.from_bytes(data[:2], byteorder="big") + 2
        if len(data) != auth_size:
            raise ParseError(
                "Message length different from specified size (EIP8)."
            )
        self.parse_auth_plain(data[2:], data[:2])

    def create_ack_EIP8(self) -> bytes:
        ack_vsn = 0x04
        data = [
            self.ephemeral_pubkey.to_bytes(),
            self.nonce,
            ack_vsn
        ]
        ack_body = rlp.encode(data)
        # Random padding between 100, 250
        ack_padding = secrets.token_bytes(random.randint(100, 250))
        ack_body = b"".join((ack_body, ack_padding))
        overhead_length = 113
        ack_size = len(ack_body) + overhead_length
        ack_size_bytes = int.to_bytes(
            ack_size,
            length=2,
            byteorder="big"
        )
        enc_ack_body = encrypt(ack_body, self.remote_pubkey, ack_size_bytes)
        self.init_msg = b"".join(ack_size_bytes, enc_ack_body)
        self.setup_frame(True)
        return self.init_msg

    def create_ack_old(self) -> bytes:
        data = b"".join((
            self.ephemeral_pubkey.to_bytes(),
            self.nonce,
            int.to_bytes(0x00, byteorder="big", length=1)
        ))
        self.init_msg = encrypt(data, self.remote_pubkey)
        self.setup_frame(True)
        return self.init_msg
    
    def setup_frame(self, incoming: bool) -> None:
        nonce_material = b"".join(
            (self.nonce, self.remote_nonce) if incoming \
                else (self.remote_nonce, self.nonce)
        )
        h_nonce = keccak(nonce_material)
        IV = int.to_bytes(0, byteorder="big", length=16)
        shared_secret = keccak(b"".join((
            self.ephemeral_shared_secret,
            h_nonce
        )))
        aes_secret = keccak(b"".join((
            self.ephemeral_shared_secret,
            shared_secret
        )))
        self.ingress_aes = \
            Cipher(CIPHER(aes_secret), MODE(IV), default_backend()).decryptor()
        self.egress_aes = \
            Cipher(CIPHER(aes_secret), MODE(IV), default_backend()).decryptor()
        mac_secret = keccak(b"".join((
            self.ephemeral_shared_secret,
            aes_secret
        )))
        self.ingress_mac = MAC(mac_secret, self.nonce, self.remote_init_msg)
        self.egress_mac = MAC(mac_secret, self.remote_nonce, self.init_msg)

    def create_header(self, frame_size: int) -> bytes:
        frame_size_bytes = int.to_bytes(frame_size, byteorder="big", length=3)
        # TODO: the rlp will contain something else someday
        capability_id = 0
        context_id = 0
        header = b"".join((
            frame_size_bytes,
            rlp.encode([capability_id, context_id])
        ))
        header = padding(header)
        header_ciphertext = self.egress_aes.update(header)
        header_mac = self.egress_mac.update_header(header_ciphertext)
        return b"".join((header_ciphertext, header_mac))
    
    def create_body(self, frame: bytes) -> bytes:
        frame = padding(frame)
        frame_ciphertext = self.egress_aes.update(frame)
        frame_mac = self.egress_mac.update_body(frame_ciphertext)
        return b"".join((frame_ciphertext, frame_mac))

    def create_auth_EIP8(self) -> bytes:
        """
        auth-vsn         = 4
        auth-size        = size of enc-auth-body, encoded as a big-endian 16-bit integer
        auth-body        = rlp.list(sig, initiator-pubk, initiator-nonce, auth-vsn)
        enc-auth-body    = ecies.encrypt(recipient-pubk, auth-body, auth-size)
        auth-packet      = auth-size || enc-auth-body
        """
        static_shared_secret = ecdh_agree(self.private_key, self.remote_pubkey)
        sig = KeyAPI().ecdsa_sign(
            xor(static_shared_secret, self.nonce),
            self.ephemeral_private_key
        )
        auth_vsn = 0x04
        auth_body = [
            sig.to_bytes(),
            # keccak(self.ephemeral_pubkey.to_bytes()),
            self.public_key.to_bytes(),
            self.nonce,
            auth_vsn,
        ]
        auth_body = rlp.encode(auth_body)
        # Random padding between 100, 250
        auth_padding = secrets.token_bytes(random.randint(100, 250))
        auth_body += auth_padding
        overhead_length = 113
        auth_size = len(auth_body) + overhead_length
        auth_size_bytes = int.to_bytes(
            auth_size,
            length=2,
            byteorder="big"
        )
        enc_auth_body = encrypt(auth_body, self.remote_pubkey, auth_size_bytes)
        self.init_msg = b"".join((auth_size_bytes, enc_auth_body))
        return self.init_msg
    
    def create_auth_non_EIP8(self) -> bytes:
        static_shared_secret = ecdh_agree(self.private_key, self.remote_pubkey)
        sig = KeyAPI().ecdsa_sign(
            xor(static_shared_secret, self.nonce),
            self.ephemeral_private_key
        )
        data = b"".join([
            sig.to_bytes(),
            keccak(self.ephemeral_pubkey.to_bytes()),
            self.public_key.to_bytes(),
            self.nonce,
            int.to_bytes(0x00, length=1, byteorder="big"),
        ])
        self.init_msg = encrypt(data, self.remote_pubkey)
        return self.init_msg
    
    def parse_ack_plain(self, data: bytes,
            shared_mac_data: bytes = b"") -> None:
        self.remote_init_msg = b"".join((shared_mac_data, data))
        decrypted = decrypt(data, self.private_key, shared_mac_data)
        if not self.got_EIP8_ack:
            if len(decrypted) != 97:
                raise ParseError("Invalid packet length.")
            if decrypted[96] != 0:
                raise ParseError("Invalid postfix.")
            remote_ephemeral_pubkey = PublicKey(decrypted[:64])
            remote_nonce = decrypted[64:96]
        else:
            decoded = rlp.decode(decrypted, strict=False)
            remote_ephemeral_pubkey = PublicKey(decoded[0])
            remote_nonce = decoded[1]
        # parse packet
        self.remote_ephemeral_pubkey = remote_ephemeral_pubkey
        self.remote_nonce = remote_nonce
        self.ephemeral_shared_secret = ecdh_agree(
            self.ephemeral_private_key,
            self.remote_ephemeral_pubkey
        )
        self.setup_frame(False)

    def parse_ack_EIP8(self, data: bytes) -> None:
        size = int.from_bytes(data[:2], byteorder="big") + 2
        if len(data) != size:
            raise ParseError(
                "Message length different from specified size (EIP8)."
            )
        self.parse_ack_plain(data[2:], data[0:2])
    

    def parse_header(self, data: bytes) -> int:
        header_ciphertext = data[:16]
        header_mac = data[16:32]
        _mac = self.ingress_mac.update_header(header_ciphertext)
        if _mac != header_mac:
            raise ParseError("Invalid MAC.")
        header = self.ingress_aes.update(header_ciphertext)
        self.body_size = int.from_bytes(header[:3], byteorder="big")
        return self.body_size
    
    def parse_body(self, data: bytes) -> bytes:
        if self.body_size is None:
            raise ParseError("Need to parse header first.")
        frame_ciphertext = data[:-16]
        frame_mac = data[-16:]
        _mac = self.ingress_mac.update_body(frame_ciphertext)
        if _mac != frame_mac:
            raise ParseError("Invalid MAC.")
        size = self.body_size
        self.body_size = None
        frame = self.ingress_aes.update(frame_ciphertext)
        return frame[:size]