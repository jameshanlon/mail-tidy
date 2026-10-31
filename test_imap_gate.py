import asyncio
import unittest

import imap_gate
from imap_gate import Blocked, Gate, check_command


class FakeBridge:
    """A minimal IMAP backend that records every line it receives."""

    def __init__(self):
        self.received = []

    async def handle(self, reader, writer):
        writer.write(b"* OK fake bridge\r\n")
        while True:
            try:
                line = await reader.readuntil(b"\r\n")
            except asyncio.IncompleteReadError:
                break
            self.received.append(line[:-2])
            tag = line.split(b" ", 1)[0]
            if b" LIST " in line:
                writer.write(b'* LIST () "/" {5}\r\nINBOX\r\n')
            writer.write(tag + b" OK done\r\n")
            await writer.drain()
        writer.close()


class Client:
    def __init__(self, reader, writer):
        self.reader, self.writer = reader, writer
        self.n = 0

    async def send(self, command, raw=False):
        self.n += 1
        tag = b"t%d" % self.n
        self.writer.write(command if raw else tag + b" " + command + b"\r\n")
        data = b""
        while True:
            line = await asyncio.wait_for(self.reader.readuntil(b"\r\n"), 5)
            data += line
            if line.startswith(tag + b" ") or b" BAD " in line:
                return data


class CheckCommandTest(unittest.TestCase):
    def allowed(self, line):
        return check_command(line, authed=True)

    def test_read_only_commands_allowed(self):
        for line in [
            b'a LIST "" "*"',
            b"a STATUS INBOX (MESSAGES)",
            b"a EXAMINE INBOX",
            b"a SEARCH ALL",
            b"a UID SEARCH ALL",
            b"a FETCH 1:10 (UID FLAGS RFC822.SIZE)",
            b"a UID FETCH 1:10 (BODY.PEEK[HEADER.FIELDS (FROM SUBJECT)])",
            b"a FETCH 1 BODY.PEEK[]<0.100>",
        ]:
            self.allowed(line)

    def test_mutating_commands_blocked(self):
        for line in [
            b"a SELECT INBOX",
            b"a STORE 1 +FLAGS (\\Deleted)",
            b"a UID STORE 1 +FLAGS (\\Seen)",
            b"a COPY 1 Trash",
            b"a MOVE 1 Trash",
            b"a UID MOVE 1 Trash",
            b"a UID COPY 1 Trash",
            b"a EXPUNGE",
            b"a UID EXPUNGE 1",
            b"a CLOSE",
            b"a DELETE Foo",
            b"a CREATE Foo",
            b"a RENAME Foo Bar",
            b"a APPEND INBOX",
            b"a STARTTLS",
            b"a AUTHENTICATE PLAIN",
            b"a UID",
            b"a",
            b"",
        ]:
            with self.subTest(line=line), self.assertRaises(Blocked):
                self.allowed(line)

    def test_fetch_that_sets_seen_blocked(self):
        for line in [
            b"a FETCH 1 BODY[]",
            b"a FETCH 1 (FLAGS BODY[TEXT])",
            b"a FETCH 1 RFC822",
            b"a FETCH 1 RFC822.TEXT",
            b"a UID FETCH 1 (UID BINARY[1])",
            b"a FETCH 1 (BODY.PEEK[HEADER] BODY[])",
            b"a FETCH 1 (FLAGS) (CHANGEDSINCE 5)",
            b"a FETCH x BODY.PEEK[]",
        ]:
            with self.subTest(line=line), self.assertRaises(Blocked):
                self.allowed(line)

    def test_smuggling_blocked(self):
        for line in [
            b"a SEARCH {5}",
            b"a SEARCH ALL\nb STORE 1 FLAGS ()",
            b"a SEARCH ALL\rb STORE 1 FLAGS ()",
            b"a SEARCH \xc3\xa9",
            b"a SEARCH \x00",
        ]:
            with self.subTest(line=line), self.assertRaises(Blocked):
                self.allowed(line)

    def test_login_required(self):
        with self.assertRaises(Blocked):
            check_command(b"a LIST \"\" \"*\"", authed=False)
        check_command(b"a LOGIN u p", authed=False)


class GateEndToEndTest(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.bridge = FakeBridge()
        self.bridge_server = await asyncio.start_server(
            self.bridge.handle, "127.0.0.1", 0, limit=imap_gate.BACKEND_LIMIT
        )
        bridge_port = self.bridge_server.sockets[0].getsockname()[1]
        gate = Gate(
            "127.0.0.1", bridge_port, "u", "p", "gatepw", backend_starttls=False
        )
        ready = asyncio.get_running_loop().create_future()
        self.gate_task = asyncio.create_task(imap_gate.serve(gate, 0, ready))
        gate_port = await ready
        reader, writer = await asyncio.open_connection("127.0.0.1", gate_port)
        await reader.readuntil(b"\r\n")
        self.client = Client(reader, writer)

    async def asyncTearDown(self):
        self.client.writer.close()
        self.gate_task.cancel()
        self.bridge_server.close()

    async def login(self):
        out = await self.client.send(b'LOGIN anyone "gatepw"')
        self.assertIn(b" OK ", out)

    async def test_blocked_commands_never_reach_backend(self):
        await self.login()
        await asyncio.sleep(0.05)
        baseline = list(self.bridge.received)
        for command in [
            b"SELECT INBOX",
            b"STORE 1 +FLAGS (\\Deleted)",
            b"UID MOVE 1 Trash",
            b"EXPUNGE",
            b"DELETE Foo",
            b"APPEND INBOX {3}",
            b"FETCH 1 BODY[]",
            b"SEARCH {3}",
        ]:
            out = await self.client.send(command)
            self.assertIn(b" BAD ", out, command)
        out = await self.client.send(
            b"x SEARCH ALL\nSTORE 1 FLAGS ()\r\n", raw=True
        )
        self.assertIn(b"BAD", out)
        await asyncio.sleep(0.05)
        self.assertEqual(self.bridge.received, baseline)

    async def test_allowed_commands_forwarded_with_literals(self):
        await self.login()
        out = await self.client.send(b'LIST "" "*"')
        self.assertIn(b"{5}\r\nINBOX\r\n", out)
        self.assertIn(b" OK ", out.splitlines()[-1])
        await self.client.send(b"EXAMINE INBOX")
        await self.client.send(b"UID FETCH 1:2 (UID BODY.PEEK[HEADER])")
        self.assertTrue(
            self.bridge.received[-1].endswith(b" UID FETCH 1:2 (UID BODY.PEEK[HEADER])")
        )

    async def test_not_logged_in_blocked(self):
        out = await self.client.send(b'LIST "" "*"')
        self.assertIn(b" BAD ", out)

    async def test_wrong_password_rejected(self):
        out = await self.client.send(b"LOGIN anyone wrong")
        self.assertIn(b" NO ", out)
        out = await self.client.send(b'LIST "" "*"')
        self.assertIn(b" BAD ", out)

    async def test_non_loopback_bridge_refused(self):
        with self.assertRaises(ValueError):
            Gate("192.0.2.1", 1143, "u", "p", "gatepw")

    async def test_login_is_not_forwarded(self):
        await self.login()
        self.assertFalse(
            any(b"anyone" in line for line in self.bridge.received)
        )


if __name__ == "__main__":
    unittest.main()
