#!/usr/bin/env python
# -*- codeing:utf-8 -*-
"""A implemention of RLPx protocol.
"""

__author__ = "XiaoHuiHui"
__version__ = "1.1"

from typing import Union, Any

RLP = Union[list[list[bytes]], list[bytes], bytes]


class Capability:
    """
    """
    def __init__(self, name: str, version: int, length: int) -> None:
        self.name = name
        self.version = version
        self.length = length

    def __eq__(self, obj: Any) -> bool:
        if not isinstance(obj, Capability):
            return False
        return self.name == obj.name \
            and self.version == obj.version

    def __ne__(self, obj: Any) -> bool:
        if not isinstance(obj, Capability):
            return True
        return self.name != obj.name \
            or self.version != obj.version

    def __lt__(self, obj: Any) -> bool:
        if not isinstance(obj, Capability):
            return False
        if self.name != obj.name:
            return False
        return self.version < obj.version

    def __le__(self, obj: Any) -> bool:
        if not isinstance(obj, Capability):
            return False
        if self.name != obj.name:
            return False
        return self.version <= obj.version

    def __gt__(self, obj: Any) -> bool:
        if not isinstance(obj, Capability):
            return False
        if self.name != obj.name:
            return False
        return self.version > obj.version

    def __ge__(self, obj: Any) -> bool:
        if not isinstance(obj, Capability):
            return False
        if self.name != obj.name:
            return False
        return self.version >= obj.version

    def __hash__(self) -> int:
        return hash(self.name + str(self.version))

    def to_RLP(self) -> bytes:
        return [self.name, self.version]

    def __str__(self) -> str:
        return f"{self.name}, {self.version}, {self.length}"
