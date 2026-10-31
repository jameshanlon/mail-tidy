#!/usr/bin/env python3
"""
Read-only IMAP gate in front of Proton Mail Bridge.

The gate holds the real Bridge credentials and logs in to Bridge itself.
Clients connect to the gate on a loopback port, log in with the gate's own
password (GATE_PASS, or one generated at startup), and are limited to an
allowlist of commands that cannot change the mailbox:

    CAPABILITY NOOP LOGIN LOGOUT LIST LSUB STATUS EXAMINE SEARCH FETCH
    (and UID SEARCH / UID FETCH)

FETCH may only request items that do not set \\Seen (BODY.PEEK, not BODY[]).
Anything else, including literals, is refused with a tagged BAD and is never
forwarded to Bridge.

Environment: BRIDGE_USER, BRIDGE_PASS [, GATE_PASS, BRIDGE_HOST, BRIDGE_PORT]
BRIDGE_HOST must be a loopback address.

Usage: imap_gate.py [--listen-port 1144]
"""

import argparse
import asyncio
import hmac
import logging
import os
import re
import secrets
import ssl
import sys
from dataclasses import dataclass

log = logging.getLogger("imap_gate")

MAX_LINE = 8192
BACKEND_LIMIT = 1 << 20
BACKEND_TAG = b"gate"
CHUNK = 64 * 1024
LOOPBACK_HOSTS = {"127.0.0.1", "localhost", "::1"}

TAG_RE = re.compile(rb"[A-Za-z0-9._-]{1,32}")
SEQSET_RE = re.compile(rb"[0-9:,*]+")
PEEK_RE = re.compile(rb"(?:BODY|BINARY)\.PEEK\[[^\]]*\](?:<\d+\.\d+>)?", re.I)
ITEM_RE = re.compile(rb"[A-Za-z0-9.]+")
LITERAL_RE = re.compile(rb"\{(\d+)\}\r\n$")

SAFE_FETCH_ITEMS = {
    b"ALL",
    b"FAST",
    b"FULL",
    b"UID",
    b"FLAGS",
    b"INTERNALDATE",
    b"RFC822.SIZE",
    b"ENVELOPE",
    b"BODY",
    b"BODYSTRUCTURE",
}

LOCAL = {b"CAPABILITY", b"NOOP", b"LOGIN", b"LOGOUT"}
FORWARDED = {
    b"LIST",
    b"LSUB",
    b"STATUS",
    b"EXAMINE",
    b"SEARCH",
    b"FETCH",
    b"UID SEARCH",
    b"UID FETCH",
}


class Blocked(Exception):
    """A command that the gate refuses to forward."""


@dataclass
class Decision:
    """The gate's ruling on one client command."""

    tag: bytes
    command: bytes
    args: bytes
    local: bool


def login_password(args):
    """Extract the password from the arguments of a LOGIN command."""
    token = args.rsplit(b" ", 1)[-1]
    if len(token) >= 2 and token[:1] == b'"' and token[-1:] == b'"':
        token = token[1:-1].replace(b'\\"', b'"').replace(b"\\\\", b"\\")
    return token


def check_fetch_items(args):
    """Raise Blocked unless a FETCH argument list only asks for safe items."""
    try:
        seqset, items = args.split(b" ", 1)
    except ValueError:
        raise Blocked("malformed FETCH")
    if not SEQSET_RE.fullmatch(seqset):
        raise Blocked("malformed sequence set")
    rest = PEEK_RE.sub(b" ", items)
    if b"[" in rest or b"]" in rest or b"<" in rest:
        raise Blocked("FETCH must use BODY.PEEK")
    for item in ITEM_RE.findall(rest):
        if item.upper() not in SAFE_FETCH_ITEMS:
            raise Blocked(f"FETCH item not permitted: {item.decode()}")


def check_command(line, authed):
    """
    Decide whether a client command line (without CRLF) may proceed.

    Returns a Decision, or raises Blocked with the reason it is refused.
    """
    if not all(0x20 <= b < 0x7F for b in line):
        raise Blocked("control or non-ASCII byte")
    if b"{" in line:
        raise Blocked("literals not permitted")

    tag, _, rest = line.partition(b" ")
    command, _, args = rest.partition(b" ")
    command = command.upper()
    if not TAG_RE.fullmatch(tag) or not command:
        raise Blocked("malformed command")

    if command in LOCAL:
        return Decision(tag, command, args, local=True)
    if not authed:
        raise Blocked("not logged in")

    if command == b"UID":
        sub, _, args = args.partition(b" ")
        command += b" " + sub.upper()
    if command not in FORWARDED:
        raise Blocked("command not permitted")
    if command.endswith(b"FETCH"):
        check_fetch_items(args)
    return Decision(tag, command, args, local=False)


def quote(value):
    """Quote a string for an IMAP LOGIN command."""
    if re.search(rb"[\r\n]", value):
        raise ValueError("line break in credential")
    return b'"' + value.replace(b"\\", b"\\\\").replace(b'"', b'\\"') + b'"'


async def relay_response(reader, writer, tag):
    """
    Copy one command's response from Bridge to the client.

    Returns the tagged status line. Literals are copied by length so their
    content is never mistaken for protocol lines. With no writer the response
    is read and dropped.
    """
    prefix = tag + b" "
    while True:
        first = None
        while True:
            line = await reader.readuntil(b"\r\n")
            if first is None:
                first = line
            if writer:
                writer.write(line)
            match = LITERAL_RE.search(line)
            if not match:
                break
            remaining = int(match.group(1))
            while remaining:
                chunk = await reader.readexactly(min(remaining, CHUNK))
                remaining -= len(chunk)
                if writer:
                    writer.write(chunk)
                    await writer.drain()
        if writer:
            await writer.drain()
        if first.startswith(prefix):
            return first


class Gate:
    """Accepts client connections and proxies the permitted commands."""

    def __init__(
        self, host, port, user, password, client_password, backend_starttls=True
    ):
        if host not in LOOPBACK_HOSTS:
            raise ValueError("Bridge host must be a loopback address")
        self.host = host
        self.port = port
        self.user = user
        self.password = password
        self.client_password = client_password.encode()
        self.backend_starttls = backend_starttls

    async def _open_backend(self):
        reader, writer = await asyncio.open_connection(
            self.host, self.port, limit=BACKEND_LIMIT
        )
        await reader.readuntil(b"\r\n")
        if self.backend_starttls:
            writer.write(BACKEND_TAG + b" STARTTLS\r\n")
            status = await relay_response(reader, None, BACKEND_TAG)
            if not status.startswith(BACKEND_TAG + b" OK"):
                raise ConnectionError("Bridge refused STARTTLS")
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            await writer.start_tls(ctx)
        writer.write(
            BACKEND_TAG
            + b" LOGIN "
            + quote(self.user.encode())
            + b" "
            + quote(self.password.encode())
            + b"\r\n"
        )
        status = await relay_response(reader, None, BACKEND_TAG)
        if not status.startswith(BACKEND_TAG + b" OK"):
            raise ConnectionError("Bridge login failed")
        return reader, writer

    async def handle(self, creader, cwriter):
        """Serve one client connection until it logs out or disconnects."""
        peer = cwriter.get_extra_info("peername")
        log.info("client connected %s", peer)
        breader = bwriter = None
        try:
            breader, bwriter = await self._open_backend()
            cwriter.write(b"* OK [CAPABILITY IMAP4rev1] read-only gate ready\r\n")
            await cwriter.drain()
            await self._serve(creader, cwriter, breader, bwriter)
        except (
            ConnectionError,
            asyncio.IncompleteReadError,
            asyncio.LimitOverrunError,
            OSError,
        ) as exc:
            log.warning("connection ended: %s", exc)
            try:
                cwriter.write(b"* BYE gate backend unavailable\r\n")
                await cwriter.drain()
            except OSError:
                pass
        finally:
            for w in (bwriter, cwriter):
                if w is not None:
                    w.close()
            log.info("client disconnected %s", peer)

    async def _serve(self, creader, cwriter, breader, bwriter):
        authed = False
        while True:
            try:
                raw = await creader.readuntil(b"\r\n")
            except asyncio.IncompleteReadError:
                return
            except asyncio.LimitOverrunError:
                cwriter.write(b"* BYE command line too long\r\n")
                await cwriter.drain()
                return
            line = raw[:-2]
            try:
                decision = check_command(line, authed)
            except Blocked as exc:
                tag = line.split(b" ", 1)[0]
                if not TAG_RE.fullmatch(tag):
                    tag = b"*"
                log.warning("DENY %r: %s", line[:200], exc)
                cwriter.write(tag + b" BAD blocked by read-only gate\r\n")
                await cwriter.drain()
                continue

            tag, command = decision.tag, decision.command
            log.info("ALLOW %r", b"LOGIN" if command == b"LOGIN" else line[:200])

            if decision.local:
                if command == b"LOGIN":
                    authed = hmac.compare_digest(
                        login_password(decision.args), self.client_password
                    )
                    if authed:
                        reply = tag + b" OK LOGIN completed\r\n"
                    else:
                        reply = tag + b" NO [AUTHENTICATIONFAILED] bad login\r\n"
                elif command == b"CAPABILITY":
                    reply = (
                        b"* CAPABILITY IMAP4rev1\r\n"
                        + tag
                        + b" OK CAPABILITY completed\r\n"
                    )
                elif command == b"LOGOUT":
                    cwriter.write(
                        b"* BYE\r\n" + tag + b" OK LOGOUT completed\r\n"
                    )
                    await cwriter.drain()
                    return
                else:
                    reply = tag + b" OK NOOP completed\r\n"
                cwriter.write(reply)
                await cwriter.drain()
                continue

            bwriter.write(line + b"\r\n")
            await bwriter.drain()
            await relay_response(breader, cwriter, tag)


async def serve(gate, port, ready=None):
    """Run the gate on a loopback port until cancelled."""
    server = await asyncio.start_server(
        gate.handle, "127.0.0.1", port, limit=MAX_LINE
    )
    if ready is not None:
        ready.set_result(server.sockets[0].getsockname()[1])
    async with server:
        await server.serve_forever()


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--listen-port", type=int, default=1144)
    args = ap.parse_args()

    user = os.environ.get("BRIDGE_USER")
    password = os.environ.get("BRIDGE_PASS")
    if not user or not password:
        sys.exit("Set BRIDGE_USER and BRIDGE_PASS.")

    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s"
    )
    client_password = os.environ.get("GATE_PASS")
    if not client_password:
        client_password = secrets.token_urlsafe(16)
        log.info("GATE_PASS not set; client password is %s", client_password)
    gate = Gate(
        os.environ.get("BRIDGE_HOST", "127.0.0.1"),
        int(os.environ.get("BRIDGE_PORT", "1143")),
        user,
        password,
        client_password,
    )
    log.info("listening on 127.0.0.1:%d", args.listen_port)
    try:
        asyncio.run(serve(gate, args.listen_port))
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
