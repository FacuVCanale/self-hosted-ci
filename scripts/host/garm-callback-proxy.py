#!/usr/bin/env python3
"""Minimal fail-closed reverse proxy for runner metadata and callbacks."""

from __future__ import annotations

import argparse
import http.client
import http.server
import ipaddress
import socketserver
import urllib.parse

MAX_BODY = 1024 * 1024
HOP_HEADERS = {"connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "te", "trailer", "transfer-encoding", "upgrade"}


def allowed(method: str, raw_path: str) -> bool:
    target = urllib.parse.urlsplit(raw_path)
    path = target.path
    lowered = path.lower()
    decoded = path
    if "%25" in lowered:
        return False
    for _ in range(3):
        next_decoded = urllib.parse.unquote(decoded)
        if next_decoded == decoded:
            break
        decoded = next_decoded
    if "\\" in decoded or "%2f" in lowered or "%5c" in lowered:
        return False
    if any(segment in {".", ".."} for segment in decoded.split("/")):
        return False
    if method in {"GET", "HEAD"}:
        return path == "/api/v1/metadata" or path.startswith("/api/v1/metadata/")
    if method == "POST":
        return path == "/api/v1/callbacks" or path.startswith("/api/v1/callbacks/")
    return False


class CallbackProxy(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    upstream_host = "127.0.0.1"
    upstream_port = 9997
    client_network = ipaddress.ip_network("10.254.0.0/28")

    def _handle(self) -> None:
        try:
            client = ipaddress.ip_address(self.client_address[0])
        except ValueError:
            self.send_error(403)
            return
        if client not in self.client_network:
            self.send_error(403)
            return
        target = urllib.parse.urlsplit(self.path)
        if target.scheme or target.netloc:
            self.send_error(400, "absolute-form targets are not accepted")
            return
        if target.fragment:
            self.send_error(400, "fragments are not accepted")
            return
        if not allowed(self.command, self.path):
            self.send_error(404)
            return
        if self.headers.get("Transfer-Encoding"):
            self.send_error(400, "transfer encoding is not accepted")
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            self.send_error(400, "invalid content length")
            return
        if length < 0 or length > MAX_BODY:
            self.send_error(413)
            return
        body = self.rfile.read(length) if length else None
        headers = {key: value for key, value in self.headers.items() if key.lower() not in HOP_HEADERS and key.lower() != "host"}
        headers["Host"] = f"{self.upstream_host}:{self.upstream_port}"
        upstream = http.client.HTTPConnection(self.upstream_host, self.upstream_port, timeout=15)
        try:
            upstream.request(self.command, self.path, body=body, headers=headers)
            response = upstream.getresponse()
            payload = response.read(MAX_BODY + 1)
            if len(payload) > MAX_BODY:
                raise OSError("upstream response exceeds limit")
        except (OSError, http.client.HTTPException):
            self.send_error(502)
            return
        finally:
            upstream.close()
        self.send_response(response.status)
        for key, value in response.getheaders():
            if key.lower() not in HOP_HEADERS and key.lower() != "content-length":
                self.send_header(key, value)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(payload)

    do_GET = _handle
    do_HEAD = _handle
    do_POST = _handle
    do_PUT = _handle
    do_DELETE = _handle
    do_PATCH = _handle
    do_CONNECT = _handle

    def log_message(self, fmt: str, *args: object) -> None:
        # Callback paths may carry opaque runner identifiers. Do not emit URLs,
        # headers or credentials; service health is observed via systemd.
        return


class Server(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--listen-host", default="10.254.0.1")
    parser.add_argument("--listen-port", type=int, default=8080)
    parser.add_argument("--upstream-host", default="127.0.0.1")
    parser.add_argument("--upstream-port", type=int, default=9997)
    parser.add_argument("--client-network", default="10.254.0.0/28")
    args = parser.parse_args()
    if ipaddress.ip_address(args.upstream_host) != ipaddress.ip_address("127.0.0.1"):
        parser.error("upstream must be 127.0.0.1")
    CallbackProxy.upstream_host = args.upstream_host
    CallbackProxy.upstream_port = args.upstream_port
    CallbackProxy.client_network = ipaddress.ip_network(args.client_network)
    with Server((args.listen_host, args.listen_port), CallbackProxy) as server:
        server.serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
