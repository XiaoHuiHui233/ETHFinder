from __future__ import annotations
from abc import ABCMeta, abstractmethod
from typing import Coroutine, TypeVar, List, Any, Dict, Type, TYPE_CHECKING

from trio import Nursery

if TYPE_CHECKING:
    from rlpx.procotols.p2p import P2pProcotol

RLP = TypeVar("RLP", List[List[bytes]], List[bytes], bytes)


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


class Procotol(metaclass=ABCMeta):
    """
    """
    
    rel: Dict[Capability, Type["Procotol"]] = {}

    def __init__(self, base: P2pProcotol, capability: Capability,
            offset: int, peer_loop: Nursery) -> None:
        self.base = base
        self.name = capability.name
        self.version = capability.version
        self.length = capability.length
        self.offset = offset
        self.peer_loop = peer_loop
    
    def __str__(self) -> str:
        return f"{self.name}, {self.version}, {self.length}, {self.offset}"

    async def bind(self) -> Coroutine:
        pass

    @abstractmethod
    async def handle_message(self, code: int, payload: RLP) -> Coroutine:
        return NotImplemented
    
    @classmethod
    def register(cls, capability: Capability,
            procotol: Type["Procotol"]) -> None:
        cls.rel[capability] = procotol

    @classmethod
    def generate(cls, base: P2pProcotol, capability: Capability,
            offset: int, peer_loop: Nursery) -> "Procotol":
        return cls.rel[capability](base, capability, offset, peer_loop)
    
