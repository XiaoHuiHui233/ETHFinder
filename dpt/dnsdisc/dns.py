#!/usr/bin/env python
# -*- codeing:utf-8 -*-

"""A implementation of DNS resolution service and EIP-1459.

This used to resolve domain which are containing node record and convert
them into peer information.

See: https://github.com/ethereum/EIPs/blob/master/EIPS/eip-1459.md
"""

__author__ = "XiaoHuiHui"
__version__ = "1.8"

import math
import random
import logging
from logging import FileHandler, Formatter
from typing import List, Dict
import base64

from dns import rdatatype
from dns.resolver import Resolver, NXDOMAIN, NoNameservers
from eth_keys.datatypes import PublicKey

from dpt.dnsdisc import enr
from dpt.dnsdisc.enr import ENRFormatError
from dpt.classes import PeerNetworkInfo

import config as opts

logger = logging.getLogger("dnsdisc")
fh = FileHandler("./logs/dnsdisc.log")
fmt = Formatter("%(asctime)s [%(name)s][%(levelname)s] %(message)s")
fh.setFormatter(fmt)
fh.setLevel(logging.INFO)
logger.addHandler(fh)

dns_tree_cache = {}
resolver = Resolver()


class Context:
    """An information class used to implement records in the recursive
    parsing process and verify the legitimacy of the parsing elements.
    """

    def __init__(self, domain: str, public_key: bytes) -> None:
        self.domain = domain
        # Base32 strings also need padding.
        public_key_bytes = base64.b32decode("".join((public_key, "===")))
        self.public_key = PublicKey.from_compressed_bytes(public_key_bytes)
        self.visits: Dict[str, bool] = {}


class EmptyResolvedError(Exception):
    """An error indicating that the text result of DNS resolution is
    empty.
    """
    pass


class UnresolvableError(Exception):
    """An error indicating that random branch selection cannot be
    resolved.
    """
    pass


def get_txt_record(subdomain: str, context: Context) -> str:
    """Return the result of resolving domain by TXT mode.

    :param str subdomain: The domain name to be resolved.
    :param Context context: The context of recursive resolution.
    :return str: The result of resolving.
    :raises EmptyResolvedError: If the result of raw DNS resolution is
        empty.
    """
    if subdomain in dns_tree_cache:
        return dns_tree_cache[subdomain]
    if subdomain is not context.domain:
        location = f"{subdomain}.{context.domain}"
    else:
        location = context.domain
    try:
        rrset = resolver.query(location, rdatatype.TXT).rrset
    except NXDOMAIN as err:
        raise EmptyResolvedError(
            f"Occerred a NXDOMAIN error. Detail: {err}"
        )
    except NoNameservers as err:
        raise EmptyResolvedError(
            f"Occerred a NoNameservers error. Detail: {err}"
        )
    if not rrset:
        raise EmptyResolvedError(
            "Received empty result array while fetching TXT record."
        )
    result = b"".join(rrset[0].strings).decode()
    if len(result) == 0:
        raise EmptyResolvedError("Received empty TXT record.")
    logger.info(f"Successfully resolve domain: {location}")
    dns_tree_cache[subdomain] = result
    return result
    

def select_random_path(branches: List[str], context: Context) -> str:
    """Randomly return a branch from branches.

    The branches those have been searched will be ignored.

    :param List[str] branches: List of branches to be selected.
    :param Context context: The context of the recording of selected
        branch.
    :return str: A randomly selected branch.
    :raise UnresolvableError: If all branches have been selected.
    """
    circular_refs: Dict[str, bool] = {}
    for idx, subdomain in enumerate(branches):
        if subdomain in context.visits:
            circular_refs[idx] = True
    if len(circular_refs) == len(branches):
        raise UnresolvableError("Unresolvable circular path detected.")
    index = math.floor(random.random() * len(branches))
    while (index in circular_refs
            and circular_refs[index]):
        index = math.floor(random.random() * len(branches))
    return branches[index]


def search(subdomain: str, context: Context) -> PeerNetworkInfo:
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
    :return PeerNetworkInfo: The analyzed node network information.  
    """
    try:
        entry = get_txt_record(subdomain, context)
        context.visits[subdomain] = True
        if (entry.startswith(enr.RECORD_PREFIX)):
            return enr.parse_and_verify_record(entry)
        elif (entry.startswith(enr.BRANCH_PREFIX)):
            branches = enr.parse_branch(entry)
            next = select_random_path(branches, context)
            return search(next, context)
        elif (entry.startswith(enr.ROOT_PREFIX)):
            next = enr.parse_and_verify_root(entry, context.public_key)
            return search(next, context)
    except EmptyResolvedError as err:
        logger.warning(
            f"Errored searching DNS tree at subdomain {subdomain}"
        )
        logger.error(f"EmptyResolvedError: {err}")
    except UnresolvableError as err:
        logger.warning(
            f"Errored searching DNS tree at subdomain {subdomain}"
        )
        logger.error(f"UnresolvableError: {err}")
    except ENRFormatError as err:
        logger.warning(
            f"Errored parsing ENR node record at subdomain {subdomain}"
        )
        logger.error(f"ENRFormatError: {err}")
    return None


def get_peers(domains: List[str]) -> List[PeerNetworkInfo]:
    """Returns a list of all node network information resolved by a
    given DNS domain list.

    This method will recursively resolve all domain in the given list
    without specifying an upper limit.

    :param List[str] domains: A list of domain.
    :return List[PeerNetworkInfo]: A list of node network information.
    """
    peers: List[PeerNetworkInfo] = []
    for dns_network in domains:
        cnt = 0
        for i in range(opts.MAX_DNS_PEERS):
            public_key, domain = enr.parse_tree(dns_network)
            context = Context(domain, public_key)
            peer = search(domain, context)
            if peer is None:
                continue
            if peer not in peers:
                peers.append(peer)
                cnt += 1
        logger.info(
            f"Got {cnt} new peer(s) candidate from DNS address={peer.address}"
        )
    return peers