#!/usr/bin/env python3
"""Run garm-cli with a short-lived, locally authenticated root-only session."""

from __future__ import annotations

import argparse
import base64
from contextlib import contextmanager
import fcntl
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request


BASE_URL = "http://127.0.0.1:9997"
LOGIN_URL = f"{BASE_URL}/api/v1/auth/login"
RUNTIME_HOME = Path("/run/self-hosted-ci/garm-cli")
USERNAME_FILE = Path("/etc/self-hosted-ci/garm/admin-username")
PASSWORD_FILE = Path("/etc/self-hosted-ci/garm/admin-password")
JWT_SECRET_FILE = Path("/etc/self-hosted-ci/garm/jwt-secret")
GARM_CLI = Path("/usr/local/bin/garm-cli")
MIN_VALID_SECONDS = 300
MAX_TOKEN_SECONDS = 25 * 60 * 60


class SessionError(RuntimeError):
    """A deliberately non-secret session failure."""


def _root_secret(path: Path, *, maximum_size: int = 4096) -> bytes:
    try:
        details = path.lstat()
    except OSError as exc:
        raise SessionError(f"required credential file is unavailable: {path}") from exc
    if (
        not stat.S_ISREG(details.st_mode)
        or details.st_uid != 0
        or details.st_nlink != 1
    ):
        raise SessionError(f"credential metadata is unsafe: {path}")
    if stat.S_IMODE(details.st_mode) != 0o600 or details.st_size > maximum_size:
        raise SessionError(f"credential permissions or size are unsafe: {path}")
    value = path.read_bytes().rstrip(b"\r\n")
    if not value or b"\x00" in value:
        raise SessionError(f"credential is empty or malformed: {path}")
    return value


def _secure_directory(path: Path) -> None:
    if path.is_symlink():
        raise SessionError(f"runtime path is a symlink: {path}")
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    details = path.lstat()
    if not stat.S_ISDIR(details.st_mode) or details.st_uid != 0:
        raise SessionError(f"runtime directory metadata is unsafe: {path}")
    os.chmod(path, 0o700)
    if stat.S_IMODE(path.lstat().st_mode) != 0o700:
        raise SessionError(f"runtime directory permissions are unsafe: {path}")


def _decode_segment(value: str) -> dict[str, object]:
    try:
        raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
        decoded = json.loads(raw)
    except (ValueError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SessionError("GARM returned a malformed JWT") from exc
    if not isinstance(decoded, dict):
        raise SessionError("GARM returned a malformed JWT")
    return decoded


def validate_jwt(
    token: str,
    secret: bytes,
    *,
    now: int | None = None,
    minimum_valid: int = MIN_VALID_SECONDS,
) -> int:
    parts = token.split(".")
    if len(parts) != 3 or any(not part for part in parts):
        raise SessionError("GARM returned a malformed JWT")
    header = _decode_segment(parts[0])
    claims = _decode_segment(parts[1])
    if header.get("alg") != "HS256" or header.get("typ") not in (None, "JWT"):
        raise SessionError("GARM JWT algorithm is not HS256")
    try:
        signature = base64.urlsafe_b64decode(parts[2] + "=" * (-len(parts[2]) % 4))
    except ValueError as exc:
        raise SessionError("GARM returned a malformed JWT signature") from exc
    expected = hmac.new(
        secret, f"{parts[0]}.{parts[1]}".encode("ascii"), hashlib.sha256
    ).digest()
    if not hmac.compare_digest(signature, expected):
        raise SessionError("GARM JWT signature validation failed")
    current = int(time.time()) if now is None else now
    expires = claims.get("exp")
    if (
        type(expires) is not int
        or not current + minimum_valid < expires <= current + MAX_TOKEN_SECONDS
    ):
        raise SessionError(
            "GARM JWT is expired, expires too soon, or exceeds the configured lifetime"
        )
    if claims.get("iss") != "garm" or claims.get("is_admin") is not True:
        raise SessionError("GARM JWT issuer or admin authority is invalid")
    if not isinstance(claims.get("user"), str) or not claims["user"]:
        raise SessionError("GARM JWT user claim is invalid")
    if not isinstance(claims.get("token_id"), str) or not claims["token_id"]:
        raise SessionError("GARM JWT token ID is invalid")
    if type(claims.get("generation")) is not int or claims["generation"] < 0:
        raise SessionError("GARM JWT generation is invalid")
    return expires


def _token_from_config(path: Path, secret: bytes) -> str | None:
    try:
        details = path.lstat()
        if (
            not stat.S_ISREG(details.st_mode)
            or details.st_uid != 0
            or details.st_nlink != 1
        ):
            return None
        if stat.S_IMODE(details.st_mode) != 0o600 or details.st_size > 65536:
            return None
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return None
    match = re.fullmatch(
        r'active_manager = "loopback"\n\n\[\[manager\]\]\nname = "loopback"\n'
        r'base_url = "http://127\.0\.0\.1:9997"\nbearer_token = "([^"\\]+)"\n',
        text,
    )
    if match is None:
        return None
    token = match.group(1)
    try:
        validate_jwt(token, secret)
    except SessionError:
        return None
    return token


def _login(username: bytes, password: bytes, secret: bytes) -> str:
    try:
        username_text = username.decode("utf-8")
        password_text = password.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise SessionError("GARM credentials are not valid UTF-8") from exc
    if not re.fullmatch(r"[A-Za-z0-9]{1,64}", username_text):
        raise SessionError("GARM username credential is invalid")
    payload = json.dumps(
        {"username": username_text, "password": password_text},
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")
    request = urllib.request.Request(
        LOGIN_URL,
        data=payload,
        headers={"Content-Type": "application/json", "Accept": "application/json"},
        method="POST",
    )
    direct_opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with direct_opener.open(request, timeout=10) as response:
            if response.status != 200:
                raise SessionError("GARM loopback login was rejected")
            body = response.read(65537)
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise SessionError("GARM loopback login failed") from exc
    if len(body) > 65536:
        raise SessionError("GARM loopback login response is too large")
    try:
        value = json.loads(body)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SessionError("GARM loopback login returned invalid JSON") from exc
    if (
        not isinstance(value, dict)
        or set(value) != {"token"}
        or not isinstance(value["token"], str)
    ):
        raise SessionError("GARM loopback login response schema drifted")
    validate_jwt(value["token"], secret)
    return value["token"]


def _write_config(path: Path, token: str) -> None:
    parent = path.parent
    _secure_directory(parent)
    text = (
        'active_manager = "loopback"\n\n[[manager]]\nname = "loopback"\n'
        f'base_url = "{BASE_URL}"\nbearer_token = "{token}"\n'
    )
    fd, temporary = tempfile.mkstemp(prefix=".config.toml.", dir=parent)
    try:
        os.fchmod(fd, 0o600)
        os.fchown(fd, 0, 0)
        with os.fdopen(fd, "w", encoding="utf-8") as output:
            output.write(text)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
        directory_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except BaseException:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise


@contextmanager
def locked_session():
    if os.geteuid() != 0:
        raise SessionError("GARM CLI session helper must run as root")
    _secure_directory(RUNTIME_HOME)
    config_dir = RUNTIME_HOME / ".local" / "share" / "garm-cli"
    for directory in (
        RUNTIME_HOME / ".local",
        RUNTIME_HOME / ".local" / "share",
        config_dir,
    ):
        _secure_directory(directory)
    lock_path = RUNTIME_HOME / ".session.lock"
    lock_fd = os.open(
        lock_path, os.O_RDWR | os.O_CREAT | os.O_CLOEXEC | os.O_NOFOLLOW, 0o600
    )
    try:
        os.fchmod(lock_fd, 0o600)
        fcntl.flock(lock_fd, fcntl.LOCK_EX)
        config = config_dir / "config.toml"
        secret = _root_secret(JWT_SECRET_FILE)
        # A correctly signed, unexpired token can still be stale after GARM rolls
        # back or recreates its database because token generations are persisted.
        # Login on every invocation so the CLI never reuses a generation-stale JWT.
        token = _login(
            _root_secret(USERNAME_FILE), _root_secret(PASSWORD_FILE), secret
        )
        _write_config(config, token)
        yield config
    finally:
        os.close(lock_fd)


def ensure_session() -> Path:
    with locked_session() as config:
        return config


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("ensure", "run"))
    parser.add_argument("args", nargs=argparse.REMAINDER)
    arguments = parser.parse_args()
    try:
        if arguments.command == "ensure":
            if arguments.args:
                raise SessionError("ensure does not accept command arguments")
            config = ensure_session()
            print(
                json.dumps(
                    {"status": "ready", "config": str(config)}, separators=(",", ":")
                )
            )
            return 0
        command = arguments.args
        if command and command[0] == "--":
            command = command[1:]
        if not command or any("\x00" in item for item in command):
            raise SessionError("run requires a garm-cli command")
        if not GARM_CLI.is_file() or GARM_CLI.is_symlink():
            raise SessionError("pinned garm-cli binary is unavailable")
        with locked_session():
            completed = subprocess.run(
                [str(GARM_CLI), *command],
                check=False,
                env={
                    "HOME": str(RUNTIME_HOME),
                    "PATH": "/usr/local/bin:/usr/bin:/bin",
                },
            )
        return completed.returncode
    except SessionError as exc:
        print(f"garm-cli session blocked: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
