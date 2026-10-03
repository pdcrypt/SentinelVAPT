"""A tiny HTTP site on 127.0.0.1 for scan tests. Never a public address."""

import contextlib
import threading
import time
from collections.abc import Iterator
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any


@dataclass
class Page:
    status: int = 200
    body: bytes = b""
    content_type: str = "text/html; charset=utf-8"
    headers: list[tuple[str, str]] = field(default_factory=list)
    delay_s: float = 0.0


class LabSite:
    def __init__(self) -> None:
        self.pages: dict[str, Page] = {}
        self.requests: list[tuple[str, str]] = []
        site = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, format: str, *args: Any) -> None:
                return

            def _handle(self) -> None:
                site.requests.append((self.command, self.path))
                page = site.pages.get(self.path.split("?", 1)[0]) or Page(
                    status=404, body=b"not found", content_type="text/plain"
                )
                if page.delay_s:
                    time.sleep(page.delay_s)
                with contextlib.suppress(OSError):
                    self.send_response(page.status)
                    self.send_header("Content-Type", page.content_type)
                    for name, value in page.headers:
                        self.send_header(name, value)
                    self.send_header("Content-Length", str(len(page.body)))
                    self.end_headers()
                    if self.command != "HEAD":
                        self.wfile.write(page.body)

            do_GET = do_HEAD = do_OPTIONS = do_POST = _handle

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.httpd.daemon_threads = True
        self.httpd.block_on_close = False
        self.port = int(self.httpd.server_address[1])
        self._thread = threading.Thread(
            target=self.httpd.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True
        )

    def html(self, path: str, body: str, **kwargs: Any) -> None:
        self.pages[path] = Page(body=f"<!doctype html><html>{body}</html>".encode(), **kwargs)

    def url(self, path: str = "/") -> str:
        return f"http://lab.test:{self.port}{path}"

    def slow_site(self, pages: int = 40, delay_s: float = 0.15) -> None:
        """Slow pages all linked from the home page (depth 1, so the crawl depth
        limit does not end the scan early): a scan takes ~pages * delay_s."""
        self.html("/", "".join(f'<a href="/p{i}">{i}</a>' for i in range(pages)))
        for i in range(pages):
            self.html(f"/p{i}", "<title>slow</title>", delay_s=delay_s)

    def __enter__(self) -> "LabSite":
        self._thread.start()
        return self

    def __exit__(self, *_: object) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()


@contextlib.contextmanager
def running_site() -> Iterator[LabSite]:
    with LabSite() as site:
        yield site
