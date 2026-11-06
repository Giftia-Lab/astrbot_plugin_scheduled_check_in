"""vsllm.cc's proof of work ("Vs PoW"), solved before the requests it guards.

Read from vsllm.cc's own client and nothing else: no other station is known
to hand these out, and one that does may use another algorithm. So it runs
only for a site whose "求解 Vs PoW" switch is on, and no request touches the
challenge endpoint otherwise.

``GET /api/pow/challenge?purpose=…`` hands out a seed, a difficulty and a
signed token; the guarded request then carries the token and a nonce proving
the work. A token lasts five minutes and is good for one request of its own
purpose only, so every attempt needs its own challenge.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import re
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlencode

CHALLENGE_PATH = "/api/pow/challenge"
# The purposes the plugin solves by itself. vsllm.cc's own client also asks
# for login, register, reset_password and verification; anything else it
# answers with "invalid purpose".
POW_PURPOSE_CHECKIN = "checkin"
POW_PURPOSE_OAUTH = "oauth"
_PURPOSE_LIMIT = 32
_PURPOSE_STRIP = re.compile(r"[^a-z0-9_-]")

# The ``code`` of a refusal, and how many challenges the station's own client
# goes through before giving up.
POW_FAILED_CODE = "pow_failed"
POW_MAX_ATTEMPTS = 3
# The limit the station's own client puts on one solve.
POW_SOLVE_TIMEOUT_SECONDS = 20.0

POW_TOKEN_HEADER = "X-Pow-Token"
POW_NONCE_HEADER = "X-Pow-Nonce"

# Only the first 32 bits of the hash are tested, so nothing harder can exist.
_MAX_DIFFICULTY = 32
# Bound synchronous seed encoding and prefix hashing before the solve timer starts.
_MAX_SEED_CHARS = 1024
# Nonces hashed between yields to the event loop: about a millisecond's work.
_BATCH = 1024

# Issues the challenge GET with the caller's session, answering (status, body).
Fetch = Callable[[str], Awaitable[tuple[int, str]]]
# The caller's trace, called as ``record(step, method, url, **fields)`` like
# core.cloudflare's Recorder.
Record = Callable[..., None]
# Sends the guarded request with the given proof headers.
Send = Callable[[dict[str, str]], Awaitable[Any]]


class PowTimeout(Exception):
    """A solve ran out of time."""


@dataclass(frozen=True)
class PowChallenge:
    """One challenge from ``/api/pow/challenge``."""

    seed: str
    difficulty: int
    token: str

    async def solve(self, timeout: float = POW_SOLVE_TIMEOUT_SECONDS) -> str:
        """Find the first nonce whose hash starts with enough zero bits.

        Hashed on the event loop in short batches, yielding between them:
        hashlib keeps the GIL for inputs this small, so a worker thread would
        stall the loop all the same, and could not be cancelled.

        Returns:
            The nonce, as the decimal string the station expects.

        Raises:
            PowTimeout: No nonce was found within ``timeout`` seconds.
        """
        prefix = hashlib.sha256(f"{self.seed}:".encode())
        limit = 1 << (_MAX_DIFFICULTY - self.difficulty)
        deadline = time.monotonic() + timeout
        start = 0
        while True:
            for nonce in range(start, start + _BATCH):
                digest = prefix.copy()
                digest.update(str(nonce).encode())
                if int.from_bytes(digest.digest()[:4], "big") < limit:
                    return str(nonce)
            if time.monotonic() >= deadline:
                raise PowTimeout
            start += _BATCH
            await asyncio.sleep(0)

    def headers(self, nonce: str) -> dict[str, str]:
        """Return the headers that present this challenge solved by ``nonce``."""
        return {POW_TOKEN_HEADER: self.token, POW_NONCE_HEADER: nonce}


def read_challenge(payload: Any) -> tuple[PowChallenge | None, str]:
    """Read a challenge out of the endpoint's JSON response.

    Returns:
        Tuple of the challenge, None when there is nothing to solve, and the
        reason when the station gave one: the feature is off, or the request
        was refused, as vsllm.cc refuses a check-in challenge without a
        session. Empty for a response that is not understood.
    """
    if not isinstance(payload, dict):
        return None, ""
    data = payload.get("data")
    if payload.get("success") is not True or not isinstance(data, dict):
        return None, str(payload.get("message") or "").strip()
    if not data.get("enabled"):
        return None, "站点未启用 PoW"
    seed, difficulty, token = data.get("seed"), data.get("difficulty"), data.get("token")
    if not (seed and token and isinstance(seed, str) and isinstance(token, str)):
        return None, ""
    if len(seed) > _MAX_SEED_CHARS:
        return None, f"PoW 题目 seed 超过 {_MAX_SEED_CHARS} 字符限制"
    if type(difficulty) is not int or not 0 <= difficulty <= _MAX_DIFFICULTY:
        return None, ""
    return PowChallenge(seed, difficulty, token), ""


def challenge_url(base_url: str, purpose: str) -> str:
    """Where a station hands out challenges for ``purpose``."""
    return f"{base_url.rstrip('/')}{CHALLENGE_PATH}?{urlencode({'purpose': purpose})}"


def normalize_pow_purpose(raw: Any) -> str:
    """Normalize a configured purpose; empty means no proof is solved.

    A purpose names which guarded request the token is for, and a station
    refuses a token presented to another one, so it is kept as typed bar case
    and anything a query string would have to escape.
    """
    return _PURPOSE_STRIP.sub("", str(raw or "").strip().lower())[:_PURPOSE_LIMIT]


def _json_object(text: str) -> dict[str, Any] | None:
    """Parse a JSON object, None for any other body."""
    try:
        payload = json.loads(text)
    except (TypeError, ValueError):
        return None
    return payload if isinstance(payload, dict) else None


def is_refusal(text: str) -> bool:
    """Whether a response body refuses a missing or wrong proof.

    Says nothing about the credential: the station checks the proof first.
    """
    # Asked of every response, so all the others are spared a parse.
    if POW_FAILED_CODE not in (text or ""):
        return False
    payload = _json_object(text)
    return payload is not None and payload.get("code") == POW_FAILED_CODE


def refusal_message(enabled: bool, proof_sent: bool) -> str:
    """Why a request was refused over its proof of work, and what to change.

    Args:
        enabled: Whether the site's Vs PoW switch is on.
        proof_sent: Whether the refused request carried a proof. A refused
            proof clears the credential; a missing challenge does not, since
            the station hands out some purposes to live sessions only.
    """
    if not enabled:
        return "站点要求 Vs PoW，并非凭据失效：请在站点「基本」页开启「求解 Vs PoW」"
    if proof_sent:
        return "站点拒绝了 PoW 解答，并非凭据失效"
    return "站点要求 PoW，但未取到可用的题目"


async def obtain_proof(
    base_url: str,
    purpose: str,
    fetch: Fetch,
    record: Record,
) -> tuple[dict[str, str], str]:
    """Ask the station for a challenge and solve it.

    Only called when the user turned Vs PoW on, so every outcome is traced:
    a station that answers anything but a usable challenge is one the switch
    should probably be off for. Short of a challenge the caller goes ahead
    without a proof, as the station's own client does, and the station's
    answer says whether that was wrong.

    Returns:
        Tuple of ``(headers, error)``. The error means a challenge could not be
        solved in time, which another attempt would not change.
    """
    step = "获取 PoW 题目"
    url = challenge_url(base_url, purpose)
    try:
        status, text = await fetch(url)
    except Exception as exc:
        record(step, "GET", url, message=f"请求异常，本次不带 PoW：{exc}")
        return {}, ""
    challenge, reason = read_challenge(_json_object(text))
    if challenge is None:
        reason = reason or f"响应不是 Vs PoW 题目（HTTP {status}）"
        record(step, "GET", url, status=status, message=f"{reason}，本次不带 PoW")
        return {}, ""

    started = time.monotonic()
    try:
        nonce = await challenge.solve()
    except PowTimeout:
        error = f"PoW 难度 {challenge.difficulty} 过高：{POW_SOLVE_TIMEOUT_SECONDS:g} 秒内未能算出"
        record("PoW 求解", "GET", url, status=status, message=error)
        return {}, error
    # The response stays out of the trace: it holds the token.
    record(
        "PoW 求解",
        "GET",
        url,
        status=status,
        success=True,
        message=f"用途 {purpose}，难度 {challenge.difficulty}，用时 {time.monotonic() - started:.2f} 秒",
    )
    return challenge.headers(nonce), ""


async def send_with_proof(
    base_url: str,
    purpose: str,
    fetch: Fetch,
    record: Record,
    send: Send,
    refused: Callable[[Any], bool],
) -> tuple[Any, dict[str, str], str]:
    """Send a guarded request with a solved challenge, as the station's client does.

    A refused proof is retried on a new challenge, up to POW_MAX_ATTEMPTS
    requests in all. Short of a usable challenge the request goes out without
    a proof, and the station's answer says whether that was wrong; once it
    was, it is not sent bare again, which would change nothing.

    Args:
        send: Sends the request with the given proof headers.
        refused: Whether a response refuses its proof.

    Returns:
        Tuple of the last response, the proof it carried, and an error when a
        challenge could not be solved in time; the response is then None.
    """
    response: Any = None
    carried: dict[str, str] = {}
    for _ in range(POW_MAX_ATTEMPTS):
        proof, error = await obtain_proof(base_url, purpose, fetch, record)
        if error:
            return None, {}, error
        if response is not None and not proof:
            break
        response, carried = await send(proof), proof
        if not refused(response):
            break
    return response, carried, ""
