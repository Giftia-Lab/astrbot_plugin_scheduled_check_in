"""Shared fake curl_cffi session used by adapter and OAuth tests."""

from __future__ import annotations

import json
from typing import Any

from core.pow import POW_FAILED_CODE, POW_NONCE_HEADER, POW_TOKEN_HEADER

# A seed and the nonce vsllm.cc accepted for it, from a real check-in.
POW_SEED = "1f1f2045e9caa1bcf142ff1a4826bc61"
POW_NONCE = "4600"
# What vsllm.cc answers a missing, wrong or reused proof.
POW_REFUSED = json.dumps({"code": POW_FAILED_CODE, "message": "Security check failed.", "success": False})


def pow_challenge(token: str = "tok-1", **data: Any) -> str:
    """Render a ``/api/pow/challenge`` body; ``data`` overrides its fields."""
    fields = {"enabled": True, "difficulty": 18, "seed": POW_SEED, "token": token, **data}
    return json.dumps({"success": True, "data": fields})


def pow_proof(call: dict[str, Any]) -> tuple[str | None, str | None]:
    """The proof a recorded request presented, ``(None, None)`` for none."""
    headers = call.get("headers") or {}
    return headers.get(POW_TOKEN_HEADER), headers.get(POW_NONCE_HEADER)


class FakeResponse:
    """Minimal stand-in for a curl_cffi response."""

    def __init__(
        self,
        status: int = 200,
        text: str = "",
        cookies: dict[str, str] | None = None,
        headers: dict[str, str] | None = None,
    ) -> None:
        self.status_code = status
        self.text = text
        self.cookies = cookies or {}
        self.headers = headers or {}


class FakeSession:
    """Routes requests by ``(METHOD, url)`` and records every call.

    A route may map to a single response or to a list consumed in order, which
    is how "balance before and after check-in" scenarios are expressed. A route
    that maps to an exception raises it, as an unreachable host would.
    """

    impersonate = "chrome131"

    def __init__(self, routes: dict[Any, Any], default: FakeResponse | None = None) -> None:
        self.routes = routes
        self.default = default or FakeResponse(404, '{"success":false,"message":"not found"}')
        self.calls: list[dict[str, Any]] = []

    async def request(self, method: str, url: str, **kwargs: Any) -> FakeResponse:
        self.calls.append({"method": method, "url": url, **kwargs})
        response = self.routes.get((method.upper(), url))
        if response is None:
            response = self.routes.get(url, self.default)
        if isinstance(response, list):
            response = response.pop(0) if response else self.default
        if isinstance(response, BaseException):
            raise response
        return response

    # ------------------------------------------------------------------
    # Assertions helpers
    # ------------------------------------------------------------------
    def urls(self) -> list[str]:
        """Return every requested URL in order."""
        return [call["url"] for call in self.calls]

    def calls_to(self, suffix: str) -> list[dict[str, Any]]:
        """Return the calls whose URL ends with ``suffix``."""
        return [call for call in self.calls if call["url"].endswith(suffix)]

    def count_to(self, suffix: str) -> int:
        """Return how many calls targeted a URL ending with ``suffix``."""
        return len(self.calls_to(suffix))


def carries_mldsa(call: dict[str, Any]) -> bool:
    """Whether a recorded request added ML-DSA to its TLS handshake."""
    extra_fp = call.get("extra_fp") or {}
    return "mldsa44" in (extra_fp.get("tls_signature_algorithms") or [])
