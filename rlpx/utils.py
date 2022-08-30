#!/usr/bin/env python
# -*- codeing:utf-8 -*-
"""A set of simple useful functions.
"""

__author__ = "XiaoHuiHui"

from asyncio import Event
from typing import Generic, TypeVar

T = TypeVar("T")


class Promise(Generic[T]):
    """A cheaper Promise implementation using trio.Event.
    """
    def __init__(self) -> None:
        self.event = Event()
        self.result: T = None

    def is_set(self) -> bool:
        return self.event.is_set()

    async def wait(self) -> None:
        await self.event.wait()

    def set(self, result: T) -> None:
        self.event.set()
        self.result = result

    def get_result(self) -> T:
        return self.result

    async def wait_and_get(self) -> T:
        await self.event.wait()
        return self.result
