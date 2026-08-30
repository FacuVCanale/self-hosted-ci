from __future__ import annotations

import http.client
import http.server
import importlib.util
import subprocess
import threading
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
NETWORK_SCRIPT = ROOT / "scripts/host/apply-runner-network-policy.sh"
RUNNER_SCRIPT = ROOT / "scripts/host/run-egress-proxies.sh"
INSTALL_SCRIPT = ROOT / "scripts/host/install-runner-network-runtime.sh"
CALLBACK_SCRIPT = ROOT / "scripts/host/garm-callback-proxy.py"
SQUID = ROOT / "packaging/network/squid.conf"


class _Upstream(http.server.BaseHTTPRequestHandler):
    seen: list[tuple[str, str, bytes]] = []

    def do_GET(self) -> None:
        self.seen.append((self.command, self.path, b""))
        body = b"metadata"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self) -> None:
        body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        self.seen.append((self.command, self.path, body))
        self.send_response(204)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, *_: object) -> None:
        pass


class NetworkPolicyAndProxyTests(unittest.TestCase):
    def test_shell_scripts_are_syntactically_valid(self) -> None:
        for path in (NETWORK_SCRIPT, RUNNER_SCRIPT, INSTALL_SCRIPT):
            result = subprocess.run(
                ["bash", "-n", str(path)], text=True, capture_output=True
            )
            self.assertEqual(0, result.returncode, result.stderr)

    def test_nft_policy_is_scoped_atomic_and_fail_closed(self) -> None:
        source = NETWORK_SCRIPT.read_text()
        self.assertIn("nft -f -", source)
        self.assertIn("table ${table_family} ${table_name}", source)
        self.assertIn('iifname "${bridge}" ip saddr != ${runner_subnet}', source)
        self.assertIn("udp sport 68 udp dport 67", source)
        self.assertLess(
            source.index("udp sport 68 udp dport 67"),
            source.index("ip saddr != ${runner_subnet}"),
        )
        self.assertIn("tcp dport { 3128, 8079, 8080 }", source)
        self.assertIn("ip daddr 10.254.0.1 udp dport 53", source)
        self.assertIn("ip daddr 10.254.0.1 tcp dport 53", source)
        self.assertIn('iifname "${bridge}" counter drop', source)
        self.assertIn('oifname "${bridge}" counter drop', source)
        runner_return = 'oifname "${bridge}" ip daddr ${runner_subnet} counter accept'
        self.assertIn(runner_return, source)
        self.assertLess(
            source.index(runner_return),
            source.index("ip daddr @forbidden_v4 counter drop"),
        )
        self.assertIn("quarantine_policy", source)
        self.assertIn(
            "ExecStop=/usr/local/lib/self-hosted-ci/apply-runner-network-policy.sh quarantine",
            (
                ROOT / "packaging/systemd/self-hosted-ci-network-policy.service"
            ).read_text(),
        )

    def test_squid_is_connect_only_allowlisted_and_rebinding_safe(self) -> None:
        source = SQUID.read_text()
        self.assertIn("http_port 10.254.0.1:3128", source)
        self.assertIn("acl CONNECT method CONNECT", source)
        self.assertIn("acl tls_port port 443", source)
        for network in (
            "10.0.0.0/8",
            "100.64.0.0/10",
            "127.0.0.0/8",
            "169.254.0.0/16",
            "172.16.0.0/12",
            "192.168.0.0/16",
            "fc00::/7",
            "fe80::/10",
        ):
            self.assertIn(network, NETWORK_SCRIPT.read_text())
        for domain in (
            ".actions.githubusercontent.com",
            ".blob.core.windows.net",
            "objects.githubusercontent.com",
            "release-assets.githubusercontent.com",
        ):
            self.assertIn(domain, source)
        self.assertNotIn(" .githubusercontent.com", source)
        self.assertLess(source.index("http_access deny !github_domains"), source.index("http_access allow github_domains"))
        self.assertIn(
            "access_log stdio:/var/log/self-hosted-ci/squid-access.log", source
        )
        self.assertTrue(source.rstrip().endswith("pinger_enable off"))
        self.assertIn("http_access deny all", source)

    def test_units_remain_sentinel_gated_and_are_no_longer_placeholders(self) -> None:
        for name in (
            "self-hosted-ci-network-policy.service",
            "self-hosted-ci-egress-proxy.service",
        ):
            source = (ROOT / "packaging/systemd" / name).read_text()
            self.assertIn(
                "ConditionPathExists=/etc/self-hosted-ci/ACTIVATION_APPROVED", source
            )
            self.assertNotIn("ExecStart=/usr/bin/false", source)

    def test_policy_units_wait_for_incus_to_publish_the_runner_bridge(self) -> None:
        for name in (
            "self-hosted-ci-network-policy.service",
            "self-hosted-ci-canary-network-policy.service",
        ):
            source = (ROOT / "packaging/systemd" / name).read_text()
            self.assertIn(
                "Requires=self-hosted-ci-network-quarantine.service incus.service",
                source,
            )
            self.assertIn(
                "After=self-hosted-ci-network-quarantine.service incus.service",
                source,
            )

        quarantine = (
            ROOT / "packaging/systemd/self-hosted-ci-network-quarantine.service"
        ).read_text()
        self.assertIn(
            "Before=incus.service self-hosted-ci-canary-network-policy.service",
            quarantine,
        )

    def test_proxy_units_allow_only_required_socket_families(self) -> None:
        expected = "RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK"
        for name in (
            "self-hosted-ci-egress-proxy.service",
            "self-hosted-ci-canary-egress-proxy.service",
        ):
            source = (ROOT / "packaging/systemd" / name).read_text()
            self.assertIn(expected, source)
            self.assertIn("LogsDirectory=self-hosted-ci", source)
            self.assertIn("LogsDirectoryMode=0750", source)

    def test_installer_is_inert_and_installs_every_runtime_file(self) -> None:
        source = INSTALL_SCRIPT.read_text()
        self.assertIn('[[ ! -e "${target_root}/ACTIVATION_APPROVED" ]]', source)
        self.assertNotIn("systemctl enable", source)
        self.assertIn("systemctl disable --now", source)
        self.assertNotIn("curl ", source)
        for filename in (
            "squid.conf",
            "apply-runner-network-policy.sh",
            "run-egress-proxies.sh",
            "garm-callback-proxy.py",
            "self-hosted-ci-network-policy.service",
            "self-hosted-ci-egress-proxy.service",
        ):
            self.assertIn(filename, source)

    def test_callback_proxy_forwards_only_metadata_and_callbacks(self) -> None:
        callback_source = CALLBACK_SCRIPT.read_text()
        self.assertNotIn('print(f"callback-proxy', callback_source)
        spec = importlib.util.spec_from_file_location("callback_proxy", CALLBACK_SCRIPT)
        assert spec and spec.loader
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        upstream = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Upstream)
        module.CallbackProxy.upstream_port = upstream.server_port
        module.CallbackProxy.client_network = module.ipaddress.ip_network("127.0.0.0/8")
        proxy = module.Server(("127.0.0.1", 0), module.CallbackProxy)
        threads = [
            threading.Thread(target=server.serve_forever, daemon=True)
            for server in (upstream, proxy)
        ]
        for thread in threads:
            thread.start()
        try:
            conn = http.client.HTTPConnection("127.0.0.1", proxy.server_port)
            conn.request("GET", "/api/v1/metadata/runner-id?token=opaque")
            response = conn.getresponse()
            self.assertEqual(200, response.status)
            response.read()
            conn.request(
                "POST",
                "/api/v1/callbacks/runner-id",
                body=b"{}",
                headers={"Content-Length": "2"},
            )
            response = conn.getresponse()
            self.assertEqual(204, response.status)
            response.read()
            conn.request("GET", "/webhooks/forbidden")
            response = conn.getresponse()
            self.assertEqual(404, response.status)
            response.read()
            for path in (
                "/api/v1/metadata/../admin",
                "/api/v1/metadata/%2e%2e/admin",
                "/api/v1/metadata/%2fadmin",
                "/api/v1/callbacks/%5cadmin",
            ):
                conn.request("GET", path)
                response = conn.getresponse()
                self.assertIn(response.status, (400, 404))
                response.read()
            self.assertEqual(
                [
                    "/api/v1/metadata/runner-id?token=opaque",
                    "/api/v1/callbacks/runner-id",
                ],
                [item[1] for item in _Upstream.seen[-2:]],
            )
            conn.close()
        finally:
            proxy.shutdown()
            upstream.shutdown()
            proxy.server_close()
            upstream.server_close()


if __name__ == "__main__":
    unittest.main()
