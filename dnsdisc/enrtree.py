#!/usr/bin/env python
# -*- codeing:utf-8 -*-
"""Resolved ENR nodes, ENR trees, ENR root, and ENR branches according
to the rules defined in EIP-1459.

See: https://github.com/ethereum/EIPs/blob/master/EIPS/eip-1459.md
"""

__author__ = "XiaoHuiHui"
__version__ = "1.6"

import base64

import parse
from eth_hash.auto import keccak
from eth_keys.datatypes import PublicKey, Signature
from eth_keys.main import KeyAPI

from enr.datatypes import ENR

TREE_PREFIX = "enrtree:"
RECORD_PREFIX = "enr:"
BRANCH_PREFIX = "enrtree-branch:"
ROOT_PREFIX = "enrtree-root:"


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


def parse_tree(tree: str) -> tuple[str, str]:
    """Parse the enrtree expression and return the domain and public
    key.

    To refer to a DNS node list, clients use a URL with 'enrtree'
    scheme. The URL contains the DNS name on which the list can be found
    as well as the public key that signed the list. The public key is
    contained in the username part of the URL and is the base32 encoding
    of the compressed 32-byte binary public key.

    enrtree://<key>@<fqdn> is a leaf pointing to a different list
    located at another fully qualified domain name. Note that this
    format matches the URL encoding. This type of entry may only appear
    in the subtree pointed to by link-root.

    See: https://github.com/ethereum/EIPs/blob/master/EIPS/eip-1459.md

    :param str tree: The enrtree expression.
    :return tuple[str, str]: The domain and public key.
    """
    if not tree.startswith(TREE_PREFIX):
        raise ValueError(f"ENRTree should start with '{TREE_PREFIX}'")
    ss = tree[len(TREE_PREFIX) + 2:].split("@")
    return ss[0], ss[1]


def parse_and_verify_record(enr: str) -> ENR:
    """Parse the enr node record expression and verify it by ecdsa.
    Return an object represents the network infomation of a peer which
    is contained by the enr node expression.

    enr:<node-record> is a leaf containing a node record. The node
    record is encoded as a URL-safe base64 string. Note that this type
    of entry matches the canonical ENR text encoding. It may only appear
    in the enr-root subtree.

    See: https://github.com/ethereum/EIPs/blob/master/EIPS/eip-1459.md

    :param str enr: The enr node record expression.
    :return ENR: The ENR resolvation of the node.
    """
    if not enr.startswith(RECORD_PREFIX):
        raise ValueError(
            f"String encoded ENR must start with '{RECORD_PREFIX}'"
        )
    return ENR.from_text(enr)


def parse_and_verify_root(root: str, public_key: PublicKey) -> str:
    """Parse the enr root expression and verify it by ecdsa. Return a
    subdomain string which will be resolved later.

    The nodes in a list are encoded as a merkle tree for distribution
    via the DNS protocol. Entries of the merkle tree are contained in
    DNS TXT records. The root of the tree is a TXT record with the
    following content:

    enrtree-root:v1 e=<enr-root> l=<link-root> seq=<sequence-number>
        sig=<signature>

    where

    enr-root and link-root refer to the root hashes of subtrees
        containing nodes and links subtrees.

    sequence-number is the tree's update sequence number, a decimal
        integer.

    signature is a 65-byte secp256k1 EC signature over the keccak256
        hash of the record content, excluding the sig= part, encoded as
        URL-safe base64.

    Further TXT records on subdomains map hashes to one of three entry
    types. The subdomain name of any entry is the base32 encoding of the
    (abbreviated) keccak256 hash of its text content.

    See: https://github.com/ethereum/EIPs/blob/master/EIPS/eip-1459.md

    :param str root: The enr root expression.
    :param public_key: The public key of ENR tree node.
    :return str: The subdomain will be resolved later.
    """
    if not root.startswith(ROOT_PREFIX):
        raise ValueError(f"ENR root entry must start with '{ROOT_PREFIX}'")
    e: str
    seq: str
    raw_sig: str
    e, _, seq, raw_sig = parse.parse(  # type: ignore
        ROOT_PREFIX + "v1 e={} l={} seq={} sig={}",
        root
    )
    int(seq)
    signed_component = root.split(" sig")[0]
    msg_hash = keccak(signed_component.encode())
    sig = base64.urlsafe_b64decode(base64_padding(raw_sig))
    # The public key of some parsing results is not 65-byte, indicating
    # that it does not contain recid bits. But the analysis here doesn't
    # seem to need this bit, just add one bit to it.
    sig_bytes = bytearray(sig)
    if len(sig_bytes) == 64:
        sig_bytes.append(0)
    sig = Signature(bytes(sig_bytes))
    # The signature is a 65-byte secp256k1 over the keccak256 hash
    # of the record content, excluding the `sig=` part, encoded as URL-safe
    # base64 string (Trailing recovery bit must be trimmed to pass
    # `ecdsaVerify` method)
    if not KeyAPI().ecdsa_verify(msg_hash, sig, public_key):
        raise ValueError("Unable to verify ENR root signature.")
    return e


def parse_branch(branch: str) -> list[str]:
    """Parse the enr tree branch expression and verify it by ecdsa.
    Return a list of subdomain strings those will be resolved later.

    enr:<node-record> is a leaf containing a node record. The node
    record is encoded as a URL-safe base64 string. Note that this type
    of entry matches the canonical ENR text encoding. It may only appear
    in the enr-root subtree.

    No particular ordering or structure is defined for the tree.
    Whenever the tree is updated, its sequence number should increase.
    The content of any TXT record should be small enough to fit into the
    512 byte limit imposed on UDP DNS packets. This limits the number of
    hashes that can be placed into an enrtree-branch entry.

    See: https://github.com/ethereum/EIPs/blob/master/EIPS/eip-1459.md

    :param str branch: The enr tree branch expression.
    :return list[str] A list of subdomain strings will be resolved
        later.
    """
    if not branch.startswith(BRANCH_PREFIX):
        raise ValueError(f"ENR branch entry must start with '{BRANCH_PREFIX}'")
    return branch[len(BRANCH_PREFIX):].split(",")
