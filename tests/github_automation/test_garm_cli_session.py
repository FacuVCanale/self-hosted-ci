from __future__ import annotations

import base64
import hashlib
import hmac
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import time
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
HELPER = ROOT / "scripts/host/garm-cli-session.py"


def load_helper():
    spec = importlib.util.spec_from_file_location("garm_cli_session", HELPER)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def jwt(secret: bytes, *, expires: int, admin: bool = True) -> str:
    def encode(value: object) -> str:
        return base64.urlsafe_b64encode(json.dumps(value, separators=(",", ":")).encode()).rstrip(b"=").decode()
    header = encode({"alg": "HS256", "typ": "JWT"})
    claims = encode({"exp": expires, "iss": "garm", "is_admin": admin, "user": "user-id", "token_id": "token-id", "generation": 1})
    signature = base64.urlsafe_b64encode(hmac.new(secret, f"{header}.{claims}".encode(), hashlib.sha256).digest()).rstrip(b"=").decode()
    return f"{header}.{claims}.{signature}"


class Response:
    status = 200

    def __init__(self, body: bytes):
        self.body = body

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read(self, _size: int) -> bytes:
        return self.body


class Opener:
    def __init__(self, response: Response):
        self.response = response
        self.request = None

    def open(self, request, timeout: int):
        self.request = request
        self.timeout = timeout
        return self.response


class GarmCliSessionTests(unittest.TestCase):
    def test_jwt_signature_authority_and_expiry_are_fail_closed(self) -> None:
        helper = load_helper(); secret = b"s" * 32; now = int(time.time())
        token = jwt(secret, expires=now + 3600)
        self.assertEqual(now + 3600, helper.validate_jwt(token, secret, now=now))
        with self.assertRaises(helper.SessionError):
            helper.validate_jwt(token, b"x" * 32, now=now)
        with self.assertRaises(helper.SessionError):
            helper.validate_jwt(jwt(secret, expires=now + 10), secret, now=now)
        with self.assertRaises(helper.SessionError):
            helper.validate_jwt(jwt(secret, expires=now + 3600, admin=False), secret, now=now)

    def test_session_refreshes_from_file_credentials_into_run_only_config(self) -> None:
        helper = load_helper(); secret = b"j" * 32; token = jwt(secret, expires=int(time.time()) + 3600)
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw); runtime = root / "run/garm-cli"; credentials = root / "etc"
            credentials.mkdir()
            username = credentials / "username"; password = credentials / "password"; jwt_key = credentials / "jwt"
            for path, value in ((username, b"admin\n"), (password, b"correct horse battery staple\n"), (jwt_key, secret + b"\n")):
                path.write_bytes(value); os.chmod(path, 0o600)
            helper.RUNTIME_HOME = runtime
            helper.USERNAME_FILE = username
            helper.PASSWORD_FILE = password
            helper.JWT_SECRET_FILE = jwt_key
            body = json.dumps({"token": token}).encode()
            def secure_directory(path: Path) -> None:
                path.mkdir(mode=0o700, parents=True, exist_ok=True); os.chmod(path, 0o700)
            secret_values = {username: b"admin", password: b"correct horse battery staple", jwt_key: secret}
            opener = Opener(Response(body))
            with mock.patch.object(helper.os, "geteuid", return_value=0), mock.patch.object(helper.os, "fchown"), mock.patch.object(helper, "_secure_directory", side_effect=secure_directory), mock.patch.object(helper, "_root_secret", side_effect=lambda path: secret_values[path]), mock.patch.object(helper.urllib.request, "build_opener", return_value=opener):
                config = helper.ensure_session()
            self.assertEqual(runtime / ".local/share/garm-cli/config.toml", config)
            self.assertEqual(0o600, stat_mode(config))
            self.assertEqual(0o700, stat_mode(runtime))
            self.assertIn(token, config.read_text())
            sent = json.loads(opener.request.data)
            self.assertEqual({"username": "admin", "password": "correct horse battery staple"}, sent)

    def test_no_password_or_token_is_placed_in_garm_cli_argv_or_environment(self) -> None:
        source = HELPER.read_text(encoding="utf-8")
        self.assertNotIn('"--password"', source)
        self.assertNotIn('"-p"', source)
        self.assertIn('data=payload', source)
        self.assertIn('"HOME": str(RUNTIME_HOME)', source)
        self.assertNotIn('"PASSWORD"', source)
        self.assertNotIn('"TOKEN"', source)


def stat_mode(path: Path) -> int:
    return path.stat().st_mode & 0o777


if __name__ == "__main__":
    unittest.main()
