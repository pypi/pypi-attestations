import functools

import pytest
from sigstore import oidc
from urllib3 import request


@pytest.fixture
@functools.cache
def id_token() -> oidc.IdentityToken:
    resp = request(
        "GET",
        "https://storage.googleapis.com/sigstore-conformance-testing-token/untrusted-testing-token.txt",
        timeout=30.0,
    )
    return oidc.IdentityToken(resp.data.decode().rstrip())
