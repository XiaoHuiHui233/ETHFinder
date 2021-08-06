#!/usr/bin/env python
# -*- codeing:utf-8 -*-

"""Use coroutine UDP socket to realize the network communication part
of Node Discovery Protocol.
"""

__author__ = "XiaoHuiHui"
__version__ = "2.1"

import logging
from logging import FileHandler, Formatter
from ipaddress import IPv4Address, IPv6Address
import traceback
from typing import Union
from abc import ABCMeta, abstractmethod

import trio
from trio import Nursery, StrictFIFOLock
from trio.socket import socket, AF_INET, SOCK_DGRAM, SocketType

from .datatypes import PeerInfo

BUFF_SIZE = 1280

IPAddress = Union[IPv4Address, IPv6Address]

logger = logging.getLogger("nodedisc.server")
fh = FileHandler("./logs/nodedisc/server.log", "w", encoding="utf-8")
fmt = Formatter("%(asctime)s [%(name)s][%(levelname)s] %(message)s")
fh.setFormatter(fmt)
fh.setLevel(logging.INFO)
logger.addHandler(fh)

class Controller(metaclass=ABCMeta):
    """
    """
    def __init__(self, base_loop: Nursery) -> None:
        self.base_loop = base_loop

    def bind(self, server: "UDPServer") -> None:
        self.server = server

    @abstractmethod
    async def on_message(data: bytes, address: tuple[str, int]) -> None:
        return NotImplemented


class UDPServer:
    """A async UDP socket peer-to-peer node, support node
    discovery procotol v4 and v5.
    """

    def __init__(self, lock_timeout: float) -> None:
        self.lock_timeout = lock_timeout
        self.switch = False
        self.send_lock = StrictFIFOLock()
        self.controllers: list[Controller] = []

    def register_controller(self, controller: Controller) -> None:
        controller.bind(self)
        self.controllers.append(controller)
    
    async def bind(self, address: str, port: int) -> None:
        """Bind local listening ip and port to UDP socket."""
        self.server: SocketType = socket(AF_INET, SOCK_DGRAM)
        await self.server.bind((address, port))
        logger.info(
            f"UDP server bind on {address}:{port}."
        )
        self.switch = True
        await self.recv_loop()

    async def handle_message(self, controller: Controller, data: bytes,
            address: IPAddress) -> None:
        try:
            await controller.on_message(data, address)
        except Exception:
            logger.error(
                f"Error on calling on_message to controller.\n"
                f"Detail: {traceback.format_exc()}"
            )
    
    async def recv_loop(self) -> None:
        """Receiving the information obtained by the UDP listening port
        in a cyclic blocking mode.

        Thanks to trio, we can use asynchronous coroutines to achieve
        this, which greatly improves efficiency.
        """
        async with trio.open_nursery() as recv_loop:
            while self.switch:
                try:
                    data, address = await self.server.recvfrom(BUFF_SIZE)
                except Exception:
                    logger.warn(
                        f"Error on recv udp packet.\n"
                        f"Detail:{traceback.format_exc()}"
                    )
                    continue
                logger.info(
                    f"Recieved data from {address[0]}:{address[1]}."
                )
                for controller in self.controllers:
                    recv_loop.start_soon(
                        self.handle_message,
                        controller,
                        data,
                        address
                    )

    async def send(self, peer: PeerInfo, data: bytes) -> None:
        """Send a message packet to the designated peer network node.

        :param PeerInfo peer: The designated peer network node.
        :param bytes data: The data is wanted to send.
        """
        if self.switch:
            logger.info(
                f"Send data to {peer.address}:{peer.udp_port}."
            )
            async with self.send_lock:
                with trio.move_on_after(self.lock_timeout) as cancel_scope:
                    try:
                        await self.server.sendto(
                            data,
                            (str(peer.address), peer.udp_port)
                        )
                    except Exception:
                        # TODO: fix this error
                        # got socket.gaierror:
                        # [Errno -9] Address family for hostname not supported
                        # I don't know why, maybe about ipv6
                        # but I can pass all exceptions here.
                        pass
                if cancel_scope.cancelled_caught:
                    logger.warn(
                        "Stop sending after waiting for "
                        f"{self.lock_timeout} seconds."
                    )
        else:
            logger.warn("Server is not running when recieve a send call.")
    
    def close(self) -> None:
        self.switch = False
