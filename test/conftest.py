import functools
import json
import os
import subprocess
import time
from base64 import b64decode
from collections.abc import Callable
from datetime import datetime, timedelta
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any

import pytest
from sigstore import oidc


def pytest_addoption(parser: pytest.Parser) -> None:
    parser.addoption(
        "--min-id-token-validity",
        action="store",
        help="Minimum validity of the identity token in seconds",
        type=lambda x: timedelta(seconds=int(x)),
        default=timedelta(seconds=20),
    )


def _jwt_cache() -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    def _decorator(
        fn: Callable[[pytest.Config], oidc.IdentityToken],
    ) -> Callable[[pytest.Config], oidc.IdentityToken]:
        @functools.wraps(fn)
        def _wrapped(pytestconfig: pytest.Config) -> oidc.IdentityToken:
            # Cache the token for the duration of the test run,
            # as long as the returned token is not yet expired
            if hasattr(_wrapped, "token"):
                assert isinstance(_wrapped.token, oidc.IdentityToken)
                min_validity = pytestconfig.getoption("--min-id-token-validity")
                if _is_valid_at(_wrapped.token, datetime.now() + min_validity):
                    return _wrapped.token

            token = fn(pytestconfig)
            setattr(_wrapped, "token", token)
            return token

        return _wrapped

    return _decorator


def _is_valid_at(token: oidc.IdentityToken, reference_time: datetime) -> bool:
    # split token, b64 decode (with padding), parse as json, validate expiry
    payload = str(token).split(".")[1]
    payload += "=" * (4 - len(payload) % 4)
    payload_json = json.loads(b64decode(payload))

    expiry = datetime.fromtimestamp(payload_json["exp"])
    return reference_time < expiry


@pytest.fixture
@_jwt_cache()
def id_token(pytestconfig: pytest.Config) -> oidc.IdentityToken:
    # following code is modified from extremely-dangerous-public-oidc-beacon download-token.py.
    # Caching can be made smarter (to return the cached token only if it is valid) if token
    # starts going invalid during runs
    MIN_VALIDITY = timedelta(seconds=20)
    MAX_RETRY_TIME = timedelta(minutes=5 if os.getenv("CI") else 1)
    RETRY_SLEEP_SECS = 30 if os.getenv("CI") else 5
    GIT_URL = "https://github.com/sigstore-conformance/extremely-dangerous-public-oidc-beacon.git"

    def git_clone(url: str, dir: str) -> None:
        base_cmd = ["git", "clone", "--quiet", "--branch", "current-token", "--depth", "1"]
        subprocess.run(base_cmd + [url, dir], check=True)

    start_time = datetime.now()
    while datetime.now() <= start_time + MAX_RETRY_TIME:
        with TemporaryDirectory() as tempdir:
            git_clone(GIT_URL, tempdir)

            with Path(tempdir, "oidc-token.txt").open() as f:
                token = oidc.IdentityToken(f.read().rstrip())

            if _is_valid_at(token, datetime.now() + MIN_VALIDITY):
                return token

        print(f"Current token expires too early, retrying in {RETRY_SLEEP_SECS} seconds.")
        time.sleep(RETRY_SLEEP_SECS)

    raise TimeoutError(f"Failed to find a valid token in {MAX_RETRY_TIME}")
