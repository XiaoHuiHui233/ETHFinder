#!/usr/bin/env python
# -*- codeing:utf-8 -*-
"""A implementation of DNS resolution service and EIP-1459.

This used to resolve domain which are containing node record and convert
them into peer information.

See: https://github.com/ethereum/EIPs/blob/master/EIPS/eip-1459.md
"""

__author__ = "XiaoHuiHui"

import base64
import logging
import math
import random
import traceback
from typing import Optional

from dns.rdatatype import TXT
from dns.resolver import Answer, Resolver
from enr.datatypes import ENR
from eth_keys.datatypes import PublicKey

from . import enrtree

logger = logging.getLogger("dnsdisc")

dns_tree_cache: dict[str, str] = {}
resolver = Resolver()


class Context:
    """An information class used to implement records in the recursive
    parsing process and verify the legitimacy of the parsing elements.
    """
    def __init__(self, domain: str, public_key_base64: str) -> None:
        self.domain = domain
        # Base32 strings also need padding.
        public_key_bytes = base64.b32decode(
            "".join((public_key_base64, "==="))
        )
        self.public_key = PublicKey.from_compressed_bytes(public_key_bytes)
        self.visits: dict[str, bool] = {}


def get_txt_record(subdomain: str, context: Context) -> str:
    """Return the result of resolving domain by TXT mode.

    :param str subdomain: The domain name to be resolved.
    :param Context context: The context of recursive resolution.
    :return str: The result of resolving.
    """
    if subdomain in dns_tree_cache:
        return dns_tree_cache[subdomain]
    if subdomain is not context.domain:
        location = f"{subdomain}.{context.domain}"
    else:
        location = context.domain
    answer: Answer = resolver.query(location, TXT)  # type: ignore
    rrset: Optional[Answer] = answer.rrset   # type: ignore
    if rrset is None:
        raise ValueError(
            "Received empty result array while fetching TXT record."
        )
    result = b"".join(rrset[0].strings).decode()  # type: ignore
    if not result:
        raise ValueError("Received empty TXT record.")
    logger.debug(f"Successfully resolve domain: {location}")
    dns_tree_cache[subdomain] = result
    return result


def select_random_path(branches: list[str], context: Context) -> str:
    """Randomly return a branch from branches.

    The branches those have been searched will be ignored.

    :param list[str] branches: list of branches to be selected.
    :param Context context: The context of the recording of selected
        branch.
    :return str: A randomly selected branch.
    """
    circular_refs: dict[int, bool] = {}
    for idx, subdomain in enumerate(branches):
        if subdomain in context.visits:
            circular_refs[idx] = True
    if len(circular_refs) == len(branches):
        raise ValueError("Unresolvable circular path detected.")
    index = math.floor(random.random() * len(branches))
    while (index in circular_refs and circular_refs[index]):
        index = math.floor(random.random() * len(branches))
    return branches[index]


def search(subdomain: str, context: Context) -> Optional[ENR]:
    """Recursively search and resolve DNS node sequence, and return
    node information.

    The result of DNS resolution was formatted as protocol://id@network.
    According to different protocol headers, the type of each domain
    resolution is also different. These rules constitute a node record
    tree. Therefore, this function recursively parses the entire node
    record tree. For each search, it can be regarded as a classification
    based on the protocol header and then be analyzed recursively.

    For the definition of the protocol header and specific parsing
    rules, please refer to EIP-1459.

    See: https://github.com/ethereum/EIPs/blob/master/EIPS/eip-1459.md

    :param str subdomain: The domain that needs to be resolved and
        analyzed.
    :param Context context: Contextual information passed recursively
        for parsing and analysis.
    :return ENR: The analyzed node network information.
    """
    try:
        entry = get_txt_record(subdomain, context)
        context.visits[subdomain] = True
        if (entry.startswith(enrtree.RECORD_PREFIX)):
            return enrtree.parse_and_verify_record(entry)
        elif (entry.startswith(enrtree.BRANCH_PREFIX)):
            branches = enrtree.parse_branch(entry)
            next = select_random_path(branches, context)
            return search(next, context)
        elif (entry.startswith(enrtree.ROOT_PREFIX)):
            next = enrtree.parse_and_verify_root(entry, context.public_key)
            return search(next, context)
        else:
            raise ValueError("Not Impossible!")
    except Exception:
        logger.error(f"Errored searching DNS tree at subdomain {subdomain}.")
        logger.error(traceback.format_exc())


def get_enrs(domain: str, max: int) -> set[ENR]:
    """Returns a set of nodes resolved by a given DNS domain.

    :param str domain: A DNS domain.
    :param int peer_num: The number of peers are wanted to return.
    :return set[ENR]: A set of node network information.
    """
    global dns_tree_cache
    dns_tree_cache = {}
    enrs: set[ENR] = set()
    while max > 0:
        public_key, subdomain = enrtree.parse_tree(domain)
        context = Context(subdomain, public_key)
        enr_node = search(subdomain, context)
        if enr_node is not None:
            enrs.add(enr_node)
        max -= 1
    logger.info(
        f"Got {len(enrs)} new ENR(s) candidate from DNS address={domain}"
    )
    return enrs
