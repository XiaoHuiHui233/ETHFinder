#!/usr/bin/env python
# -*- codeing:utf-8 -*-
"""Use coroutine UDP socket to realize the network communication part
of Node Discovery Protocol.
"""

__author__ = "XiaoHuiHui"

import abc
import asyncio
import ipaddress
import logging
import traceback
from abc import ABCMeta
from asyncio import BaseTransport, DatagramProtocol, DatagramTransport
from typing import Any

from .datatypes import Addr

logger = logging.getLogger("nodedisc.server")

MAX_ALLOWED_DATA_LENGTH = 1280


class UDPServer(DatagramProtocol):
    """A async UDP socket peer-to-peer node, support node
    discovery procotol v4 and v5.
    """
    def __init__(self) -> None:
        self.controllers: list[Controller] = []

    def register_controller(self, controller: "Controller") -> None:
        controller.bind(self)
        self.controllers.append(controller)

    def connection_made(self, transport: DatagramTransport) -> None:
        self.transport = transport

    def datagram_received(
        self, data: bytes, addr: tuple[str | Any, int]
    ) -> None:
        if len(data) > MAX_ALLOWED_DATA_LENGTH:
            logger.warning(f"received data from {addr}, but too large!")
            return
        try:
            new_addr = Addr(ipaddress.ip_address(addr[0]), addr[1])
            logger.debug(f"received data from {new_addr}.")
            for controller in self.controllers:
                controller.on_message(data, new_addr)
        except Exception:
            logger.error(
                f"Error on datagram_received.\n"
                f"Detail: {traceback.format_exc()}"
            )

    def error_received(self, exc: Exception) -> None:
        logger.warning(
            f"Error on received data.\nDetail: {traceback.format_exc()}"
        )

    def send(self, data: bytes, addr: Addr) -> None:
        logger.debug(f"Send data to {addr}.")
        try:
            self.transport.sendto(data, (str(addr.address), addr.udp_port))
        except Exception:
            logger.error(
                f"Error on sending data to {addr}.\n"
                f"Detail: {traceback.format_exc()}"
            )


class Controller(metaclass=ABCMeta):
    def bind(self, server: UDPServer) -> None:
        self.server = server

    @abc.abstractmethod
    def on_message(self, data: bytes, addr: Addr) -> None:
        raise NotImplementedError()


async def startup(address: str, port: int) -> tuple[BaseTransport, UDPServer]:
    loop = asyncio.get_running_loop()
    transport, protocol = await loop.create_datagram_endpoint(
        lambda: UDPServer(),
        local_addr=(address, port)
    )
    logger.info(f"UDP server has been started up on {address}:{port}.")
    return transport, protocol
