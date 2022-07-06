#!/usr/bin/env python
# -*- codeing:utf-8 -*-
"""A set of simple useful functions.
"""

__author__ = "XiaoHuiHui"
__version__ = "1.1"

from typing import Generic, Sequence, TypeVar, Union
from ipaddress import IPv4Address, IPv6Address

from trio import SocketStream, Event

T = TypeVar('T')
RLP = Union[Sequence["RLP"], int, bytes]
IPAddress = Union[IPv4Address, IPv6Address]


def get_socket_rckey(socket_stream: SocketStream) -> str:
    tp = socket_stream.socket.getpeername()
    address, port = tp[0], tp[1]
    if len(tp) > 2:
        return f"[{address}]:{port}"
    else:
        return f"{address}:{port}"


async def unsafe_close(socket_stream: SocketStream) -> None:
    try:
        await socket_stream.aclose()
    except Exception:
        pass


class Promise(Generic[T]):
    """A cheaper Promise implementation using trio.Event.
    """
    def __init__(self) -> None:
        self.event = Event()
        self.result = None

    def is_set(self) -> bool:
        return self.event.is_set()

    async def wait(self) -> None:
        await self.event.wait()

    def set(self, result: T) -> None:
        self.event.set()
        self.result = result

    def get_result(self) -> T:
        return self.result
