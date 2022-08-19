#!/usr/bin/env python
# -*- codeing:utf-8 -*-
"""A simple implementation of Ethereum Improvement Proposals EIP-778.

The node record is defined by EIP-778.

The canonical encoding of a node record is an RLP list of
[signature, seq, k, v, ...]. The maximum encoded size of a node record
is 300 bytes. Implementations should reject records larger than this size.

Records are signed and encoded as follows:

content   = [seq, k, v, ...]
signature = sign(content)
record    = [signature, seq, k, v, ...]

See: https://github.com/ethereum/EIPs/blob/master/EIPS/eip-778.md
"""

__author__ = "XiaoHuiHui"
__version__ = "1.0"

from enr.datatypes import ENR, ENRContent

__all__ = ["ENR", "ENRContent"]
