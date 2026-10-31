#!/usr/bin/env python3
"""
Read-only sender-volume report for a mailbox exposed by Proton Mail Bridge.

Credentials come from the environment (the Bridge-generated IMAP username and
password, not the Proton account password):

    BRIDGE_USER, BRIDGE_PASS [, BRIDGE_HOST, BRIDGE_PORT, BRIDGE_STARTTLS]

When connecting through imap_gate.py, use its port, set BRIDGE_STARTTLS=0, and
any placeholder user and password.

Usage: sender_report.py [--folder INBOX] [--top 40] [--csv senders.csv]

Messages are fetched with BODY.PEEK and the mailbox is opened read-only, so
nothing is modified or marked as read.
"""

import argparse
import csv
import email
import imaplib
import os
import re
import ssl
import sys
from collections import defaultdict
from email.header import decode_header, make_header
from email.utils import parseaddr

BATCH = 500
FIELDS = "FROM SUBJECT DATE LIST-UNSUBSCRIBE"


def connect():
    """Open a STARTTLS IMAP connection to the local Bridge."""
    host = os.environ.get("BRIDGE_HOST", "127.0.0.1")
    port = int(os.environ.get("BRIDGE_PORT", "1143"))
    user = os.environ.get("BRIDGE_USER")
    password = os.environ.get("BRIDGE_PASS")
    if not user or not password:
        sys.exit("Set BRIDGE_USER and BRIDGE_PASS.")

    # Bridge uses a self-signed certificate on the loopback interface.
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    conn = imaplib.IMAP4(host, port)
    if os.environ.get("BRIDGE_STARTTLS", "1") != "0":
        conn.starttls(ssl_context=ctx)
    conn.login(user, password)
    return conn


def decode(value):
    """Decode an RFC 2047 header value to plain text."""
    try:
        return str(make_header(decode_header(value or "")))
    except Exception:
        return value or ""


def fetch_headers(conn, ids):
    """Yield (size, parsed header message) for each message id."""
    for i in range(0, len(ids), BATCH):
        chunk = b",".join(ids[i : i + BATCH]).decode()
        status, data = conn.fetch(
            chunk, f"(RFC822.SIZE BODY.PEEK[HEADER.FIELDS ({FIELDS})])"
        )
        if status != "OK":
            sys.exit(f"FETCH failed: {status}")
        for item in data:
            if not isinstance(item, tuple):
                continue
            size = re.search(rb"RFC822\.SIZE (\d+)", item[0])
            yield (
                int(size.group(1)) if size else 0,
                email.message_from_bytes(item[1]),
            )
        print(f"  {min(i + BATCH, len(ids))}/{len(ids)}", file=sys.stderr)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--folder", default="INBOX")
    ap.add_argument("--top", type=int, default=40)
    ap.add_argument("--csv", default="senders.csv")
    args = ap.parse_args()

    conn = connect()
    folder = args.folder.replace("\\", "\\\\").replace('"', '\\"')
    status, _ = conn.select(f'"{folder}"', readonly=True)
    if status != "OK":
        sys.exit(f"Cannot open folder {args.folder!r}.")
    status, data = conn.search(None, "ALL")
    if status != "OK":
        sys.exit("SEARCH failed.")
    ids = data[0].split()
    print(f"{len(ids)} messages in {args.folder}", file=sys.stderr)

    senders = defaultdict(
        lambda: {"count": 0, "bytes": 0, "unsub": 0, "subjects": []}
    )
    for size, msg in fetch_headers(conn, ids):
        addr = parseaddr(decode(msg["From"]))[1].lower() or "(unknown)"
        s = senders[addr]
        s["count"] += 1
        s["bytes"] += size
        s["unsub"] += bool(msg["List-Unsubscribe"])
        if len(s["subjects"]) < 3:
            s["subjects"].append(decode(msg["Subject"]).replace("\n", " ")[:80])
    conn.logout()

    rows = sorted(senders.items(), key=lambda kv: -kv[1]["count"])
    with open(args.csv, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["sender", "count", "mb", "has_unsubscribe", "samples"])
        for addr, s in rows:
            w.writerow(
                [
                    addr,
                    s["count"],
                    round(s["bytes"] / 1e6, 2),
                    "yes" if s["unsub"] else "no",
                    " | ".join(s["subjects"]),
                ]
            )

    print(f"\nTop {args.top} senders by volume (full list in {args.csv}):\n")
    for addr, s in rows[: args.top]:
        flag = "U" if s["unsub"] else " "
        print(f"{s['count']:6d} {s['bytes'] / 1e6:7.1f}MB [{flag}] {addr}")
    print("\n[U] = carries a List-Unsubscribe header (likely bulk/newsletter)")


if __name__ == "__main__":
    main()
