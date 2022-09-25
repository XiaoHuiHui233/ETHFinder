#!/usr/bin/env python
# -*- codeing:utf-8 -*-
"""A implementation of TCP sockets.
"""

__author__ = "XiaoHuiHui"

import asyncio
import ipaddress
import logging
import traceback
from asyncio import StreamReader, StreamWriter
from datetime import datetime
from socket import socket
from typing import Any, Callable, Coroutine, Optional

from eth_keys.datatypes import PrivateKey, PublicKey
from lru import LRU

from .datatypes import Addr
from .peer.p2p import P2pPeer, P2pPeerFactory

logger = logging.getLogger("rlpx.server")


def now() -> int:
    return int(datetime.utcnow().timestamp())


async def safe_close(
    writer: StreamWriter, raw_addr: Optional[Addr] = None
) -> None:
    try:
        writer.close()
        await writer.wait_closed()
    except Exception:
        logger.warning(
            f"Occurred an error when safe closing {raw_addr}.\n"
            f"Detail: {traceback.format_exc()}"
        )


class TCPServer:
    """
    """
    def __init__(
        self,
        private_key: PrivateKey,
        factory: P2pPeerFactory,
        callback: Callable[[P2pPeer], Coroutine[Any, Any, None]]
    ) -> None:
        self.private_key = private_key
        self.factory = factory
        self.callback = callback
        self.ban_list: dict[Addr, int] = LRU(25000)

    def ban(self, addr: Addr) -> None:
        self.ban_list[addr] = now()

    def has_banned(self, addr: Addr) -> bool:
        if addr in self.ban_list:
            last_time = self.ban_list[addr]
            if now() - last_time > 600:
                self.ban_list.pop(addr)
        return addr in self.ban_list

    async def bind(self, address: str, port: int) -> None:
        logger.info(f"TCP server on bind {address}:{port}.")
        self.port = port
        self.server = await asyncio.start_server(
            self.on_connect, address, port
        )
        self.run_task = asyncio.create_task(self.run(), name="tcp_run")

    async def run(self) -> None:
        await self.server.serve_forever()

    async def close(self) -> None:
        logger.debug("TCP Server is closing.")
        self.server.close()
        await self.server.wait_closed()
        self.run_task.cancel()
        logger.info("TCP Server is closed.")

    async def connect_to(self, addr: Addr, remote_id: PublicKey) -> None:
        logger.info(f"Active Connecting to {addr}.")
        try:
            reader, writer = await asyncio.open_connection(
                str(addr.address), addr.tcp_port
            )
            await self.on_connect(reader, writer, remote_id, addr)
        except Exception:
            logger.warning(
                f"Failed to connect to {addr}.\n"
                f"Detail: {traceback.format_exc()}"
            )

    async def on_connect(
        self,
        reader: StreamReader,
        writer: StreamWriter,
        remote_id: Optional[PublicKey] = None,
        raw_addr: Optional[Addr] = None
    ) -> None:
        sock: socket = writer.get_extra_info("socket")
        if sock is None:
            logger.warning("Socket is not avaliable! Close the connection.")
            asyncio.create_task(
                safe_close(writer, raw_addr), name="safe_close"
            )
            return
        ip, port = sock.getpeername()
        addr = Addr(ipaddress.ip_address(ip), port)
        logger.debug(f"Successfully connected to {addr}.")
        if raw_addr is not None and addr != raw_addr:
            logger.warning(
                f"We want to connect to {raw_addr}, "
                f"but actually connect to {addr}"
            )
        peer = self.factory.create(addr, self.port, remote_id, reader, writer)
        await self.callback(peer)
