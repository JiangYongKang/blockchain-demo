"""Localhost TCP gossip network (asyncio, JSON-lines).

Each node listens on 127.0.0.1:<p2p_port> and dials every peer. Messages are
newline-delimited JSON envelopes. Gossip uses a bounded seen-set so messages
are forwarded at most once per node. No external hosts are ever contacted.
"""

from __future__ import annotations

import asyncio
import json
from typing import Awaitable, Callable

from .crypto import hash_obj

MAX_LINE = 4 * 1024 * 1024
SEEN_LIMIT = 50_000


class Network:
    def __init__(
        self,
        host: str,
        port: int,
        peers: list[dict],
        handler: Callable[[dict, "Peer"], None],
        peer_height: Callable[[], int],
        log: Callable[[str], None],
    ):
        self.host = host
        self.port = port
        self.peers_cfg = peers
        self.handler = handler
        self.peer_height = peer_height
        self.log = log
        self.server: asyncio.Server | None = None
        self.connections: set[Peer] = set()
        self._seen: set[str] = set()

    async def start(self) -> None:
        self.server = await asyncio.start_server(self._accept, self.host, self.port)
        for peer in self.peers_cfg:
            asyncio.create_task(self._dial_loop(peer))

    async def stop(self) -> None:
        if self.server:
            self.server.close()
        for conn in list(self.connections):
            conn.close()

    # ------------------------------------------------------------- connections
    async def _accept(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        await self._serve(Peer(reader, writer))

    async def _dial_loop(self, peer: dict) -> None:
        while True:
            try:
                reader, writer = await asyncio.open_connection(peer["host"], peer["port"])
                await self._serve(Peer(reader, writer))
            except (OSError, asyncio.IncompleteReadError):
                pass
            await asyncio.sleep(1.0)

    async def _serve(self, conn: "Peer") -> None:
        self.connections.add(conn)
        try:
            # Handshake: announce our height so the peer can offer sync.
            conn.send({"type": "hello", "data": {"height": self.peer_height()}})
            while True:
                line = await conn.reader.readline()
                if not line:
                    break
                if len(line) > MAX_LINE:
                    break
                try:
                    msg = json.loads(line)
                except json.JSONDecodeError:
                    continue
                self._receive(msg, conn)
        except (ConnectionResetError, asyncio.IncompleteReadError, BrokenPipeError):
            pass
        finally:
            self.connections.discard(conn)
            conn.close()

    # --------------------------------------------------------------- gossip
    def _receive(self, msg: dict, conn: "Peer") -> None:
        if msg.get("type") == "hello":
            self.handler(msg, conn)
            return
        mid = hash_obj(msg)
        if mid in self._seen:
            return
        if len(self._seen) > SEEN_LIMIT:
            self._seen.clear()
        self._seen.add(mid)
        self.handler(msg, conn)
        self.broadcast(msg, exclude=conn)

    def broadcast(self, msg: dict, exclude: "Peer | None" = None) -> None:
        mid = hash_obj(msg)
        self._seen.add(mid)
        for conn in list(self.connections):
            if conn is not exclude:
                conn.send(msg)


class Peer:
    """One TCP connection to another node."""

    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        self.reader = reader
        self.writer = writer
        self.height = 0  # last height the peer announced

    def send(self, msg: dict) -> None:
        try:
            self.writer.write(json.dumps(msg).encode() + b"\n")
        except (ConnectionResetError, BrokenPipeError, RuntimeError):
            pass

    def close(self) -> None:
        try:
            self.writer.close()
        except Exception:
            pass
