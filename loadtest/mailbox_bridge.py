"""The load test's inbox in staging: the SES receipt rule's bucket, served as Mailpit's two
search calls (#249).

    uv run --project services/api python loadtest/mailbox_bridge.py \\
        --bucket BUCKET --prefix loadtest/ \\
        --shard 3 --port 8025

k6 reads link and code emails through Mailpit's API (loadtest/k6/lib/mailbox.js). In
staging the recipients and uploaders are addresses in the load-test mail domain, which
SES receives into the mailbox bucket, one raw object per message
(docs/runbooks/synthetic-probe.md has the receipt rule; the probe uses the same bucket
under `probe/`). This process lists the prefix every 2 seconds, reads each new object
once with the probe's parser (`sft.probe.mailbox`), keeps the ones addressed to its own
shard's recipients (`lt-<kind>-<shard>-...`), deletes those from the bucket, and answers
`GET /api/v1/search?query=to:"<address>"` and `GET /api/v1/message/<id>` on 127.0.0.1
only. Other shards' messages are left for their own bridge; the bucket's lifecycle rule
removes anything a run leaves.

It uses the runner's AWS credentials (the load-test role the workflow assumes through
OIDC) and never prints a message, a token or a code.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import parse_qs, urlsplit

from botocore.exceptions import BotoCoreError, ClientError
from sft.probe.mailbox import S3Mailbox, parse_raw

QUERY = re.compile(r'^to:"([^"]+)"$')


class Inbox:
    """Messages by recipient, as the poller finds them."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._by_address: dict[str, list[int]] = {}
        self._texts: dict[int, str] = {}

    def add(self, recipients: set[str], text: str) -> None:
        with self._lock:
            number = len(self._texts) + 1
            self._texts[number] = text
            for address in recipients:
                self._by_address.setdefault(address, []).append(number)

    def search(self, address: str) -> list[int]:
        with self._lock:
            return list(
                reversed(self._by_address.get(address.lower(), []))
            )  # newest first

    def text(self, number: int) -> str | None:
        with self._lock:
            return self._texts.get(number)


def poll(
    client: Any, bucket: str, prefix: str, mine: re.Pattern[str], inbox: Inbox
) -> None:
    seen: set[str] = set()
    while True:
        try:
            listed = client.list_objects_v2(Bucket=bucket, Prefix=prefix)
            taken = []
            for item in listed.get("Contents", []):
                key = item["Key"]
                if key in seen:
                    continue
                seen.add(key)
                recipients, text = parse_raw(
                    client.get_object(Bucket=bucket, Key=key)["Body"].read()
                )
                ours = {r for r in recipients if mine.match(r)}
                if ours:
                    inbox.add(ours, text)
                    taken.append({"Key": key})
            if taken:
                client.delete_objects(
                    Bucket=bucket, Delete={"Objects": taken, "Quiet": True}
                )
        except (OSError, ValueError, BotoCoreError, ClientError) as exc:  # keep polling
            print(f"mailbox poll failed: {type(exc).__name__}", file=sys.stderr)
        time.sleep(2)


def handler(inbox: Inbox) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        def _json(self, status: int, body: object) -> None:
            data = json.dumps(body).encode()
            self.send_response(status)
            self.send_header("content-type", "application/json")
            self.send_header("content-length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self) -> None:
            url = urlsplit(self.path)
            if url.path == "/api/v1/search":
                found = QUERY.match(parse_qs(url.query).get("query", [""])[0])
                ids = inbox.search(found.group(1)) if found else []
                self._json(200, {"messages": [{"ID": str(n)} for n in ids[:50]]})
                return
            if url.path.startswith("/api/v1/message/"):
                number = url.path.rsplit("/", 1)[-1]
                text = inbox.text(int(number)) if number.isdigit() else None
                if text is None:
                    self._json(404, {})
                else:
                    self._json(200, {"Text": text})
                return
            self._json(404, {})

        def log_message(self, format: str, *args: object) -> None:
            return  # no request lines: a query holds an address

    return Handler


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Serve the staging mailbox bucket as Mailpit's search API"
    )
    parser.add_argument("--bucket", required=True)
    parser.add_argument("--prefix", default="loadtest/")
    parser.add_argument("--region", default="ap-northeast-1")
    parser.add_argument("--shard", default="0")
    parser.add_argument("--port", type=int, default=8025)
    args = parser.parse_args()
    mailbox = S3Mailbox.create(
        region=args.region, bucket=args.bucket, prefix=args.prefix
    )
    mine = re.compile(rf"^lt-[a-z]+-{re.escape(args.shard)}-")
    inbox = Inbox()
    threading.Thread(
        target=poll,
        args=(mailbox._client, args.bucket, args.prefix, mine, inbox),
        daemon=True,
    ).start()
    server = ThreadingHTTPServer(("127.0.0.1", args.port), handler(inbox))
    print(f"mailbox bridge on 127.0.0.1:{args.port} for shard {args.shard}")
    server.serve_forever()
    return 0


if __name__ == "__main__":
    sys.exit(main())
