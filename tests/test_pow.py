"""Tests for the proof of work some New-API forks ask for before a request."""

from __future__ import annotations

import asyncio
import hashlib
import json
import unittest
from unittest import mock

import tests  # noqa: F401
from core.pow import (
    POW_MAX_ATTEMPTS,
    POW_NONCE_HEADER,
    POW_TOKEN_HEADER,
    PowChallenge,
    PowTimeout,
    challenge_url,
    is_refusal,
    normalize_pow_purpose,
    obtain_proof,
    read_challenge,
    send_with_proof,
)
from tests.fakes import POW_NONCE, POW_REFUSED, POW_SEED, pow_challenge

BASE = "https://relay.example.com"


def leading_zero_bits(seed: str, nonce: str) -> int:
    """Count them as the station's worker does, on the hash's first 32 bits."""
    digest = hashlib.sha256(f"{seed}:{nonce}".encode()).digest()
    return 32 - int.from_bytes(digest[:4], "big").bit_length()


def payload(**fields) -> dict:
    """A ``/api/pow/challenge`` response, parsed."""
    return json.loads(pow_challenge(**{"token": "tok", **fields}))


class SolveTests(unittest.IsolatedAsyncioTestCase):
    async def test_finds_the_nonce_the_station_accepted(self) -> None:
        self.assertEqual(await PowChallenge(POW_SEED, 18, "tok").solve(), POW_NONCE)

    def test_stops_at_the_first_match(self) -> None:
        for nonce in range(int(POW_NONCE)):
            self.assertLess(leading_zero_bits(POW_SEED, str(nonce)), 18)

    async def test_the_answer_meets_the_difficulty_of_other_seeds(self) -> None:
        for seed in ("a", "6222a1bf048ff94c8118d7210d22e7e2"):
            nonce = await PowChallenge(seed, 12, "tok").solve()
            self.assertGreaterEqual(leading_zero_bits(seed, nonce), 12)

    async def test_no_difficulty_is_met_by_the_first_nonce(self) -> None:
        self.assertEqual(await PowChallenge(POW_SEED, 0, "tok").solve(), "0")

    async def test_gives_up_at_the_deadline(self) -> None:
        # Mock only the solver's clock, leaving asyncio's own clock untouched.
        with mock.patch("core.pow.time") as clock:
            clock.monotonic.side_effect = [100.0, 100.0]
            with self.assertRaises(PowTimeout):
                await PowChallenge(POW_SEED, 32, "tok").solve(timeout=0)

    async def test_the_loop_keeps_running_during_a_solve(self) -> None:
        """Hashed on the loop in batches, so other work is not stalled."""
        ticks = 0

        async def tick() -> None:
            nonlocal ticks
            while True:
                ticks += 1
                await asyncio.sleep(0)

        ticker = asyncio.create_task(tick())
        await PowChallenge(POW_SEED, 18, "tok").solve()
        ticker.cancel()
        self.assertGreater(ticks, 1)

    async def test_a_cancelled_solve_stops(self) -> None:
        solve = asyncio.create_task(PowChallenge(POW_SEED, 32, "tok").solve())
        await asyncio.sleep(0)
        solve.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await solve

    def test_presents_the_token_and_nonce(self) -> None:
        self.assertEqual(
            PowChallenge(POW_SEED, 18, "tok").headers(POW_NONCE),
            {POW_TOKEN_HEADER: "tok", POW_NONCE_HEADER: POW_NONCE},
        )


class ReadChallengeTests(unittest.TestCase):
    def test_reads_a_challenge(self) -> None:
        self.assertEqual(read_challenge(payload()), (PowChallenge(POW_SEED, 18, "tok"), ""))

    def test_a_seed_at_the_documented_limit_is_accepted(self) -> None:
        seed = "x" * 1024
        self.assertEqual(
            read_challenge(payload(seed=seed)), (PowChallenge(seed, 18, "tok"), "")
        )

    def test_an_oversized_seed_is_rejected(self) -> None:
        challenge, reason = read_challenge(payload(seed="x" * 1025))
        self.assertIsNone(challenge)
        self.assertIn("1024", reason)

    def test_nothing_to_solve_when_it_is_off(self) -> None:
        for enabled in (False, None):
            self.assertEqual(read_challenge(payload(enabled=enabled)), (None, "站点未启用 PoW"))

    def test_a_refusal_gives_its_reason(self) -> None:
        """What vsllm.cc answers a request without a session."""
        self.assertEqual(read_challenge({"message": "未登录", "success": False}), (None, "未登录"))

    def test_a_response_it_cannot_read_is_ignored(self) -> None:
        for broken in (
            None,
            ["x"],
            {"success": True, "data": "x"},
            payload(seed=""),
            payload(seed=7),
            payload(token=""),
            payload(difficulty="18"),
            payload(difficulty=True),
            payload(difficulty=None),
            payload(difficulty=-1),
            payload(difficulty=33),
        ):
            with self.subTest(broken=broken):
                self.assertEqual(read_challenge(broken), (None, ""))


class HelperTests(unittest.TestCase):
    def test_the_challenge_url_names_the_purpose(self) -> None:
        self.assertEqual(
            challenge_url(f"{BASE}/", "reset_password"),
            f"{BASE}/api/pow/challenge?purpose=reset_password",
        )

    def test_a_refusal_is_told_apart_from_other_failures(self) -> None:
        self.assertTrue(is_refusal(POW_REFUSED))
        for other in ('{"success":false,"message":"未登录"}', "<html>", "", '["pow_failed"]',
                      '{"message":"pow_failed"}'):
            self.assertFalse(is_refusal(other), other)

    def test_a_purpose_is_reduced_to_what_a_query_can_carry(self) -> None:
        self.assertEqual(normalize_pow_purpose(" CheckIn "), "checkin")
        self.assertEqual(normalize_pow_purpose(" reset_password "), "reset_password")
        self.assertEqual(normalize_pow_purpose("a b&c"), "abc")
        self.assertEqual(normalize_pow_purpose("x" * 40), "x" * 32)
        self.assertEqual(normalize_pow_purpose(None), "")


class ObtainProofTests(unittest.IsolatedAsyncioTestCase):
    """The shared step: ask for a challenge, solve it, say what happened."""

    async def _obtain(self, status: int, text: str, purpose: str = "checkin"):
        asked, trace = [], []

        async def fetch(url):
            asked.append(url)
            return status, text

        def record(step, method, url, **fields):
            trace.append({"step": step, "method": method, "url": url, **fields})

        headers, error = await obtain_proof(BASE, purpose, fetch, record)
        return headers, error, asked, trace

    async def test_solves_what_the_station_hands_out(self) -> None:
        headers, error, asked, trace = await self._obtain(200, pow_challenge("tok"), "oauth")
        self.assertEqual((headers, error), ({POW_TOKEN_HEADER: "tok", POW_NONCE_HEADER: POW_NONCE}, ""))
        self.assertEqual(asked, [f"{BASE}/api/pow/challenge?purpose=oauth"])
        self.assertEqual([(t["step"], t["method"], t["success"]) for t in trace], [("PoW 求解", "GET", True)])
        self.assertIn("用途 oauth", trace[0]["message"])

    async def test_no_usable_challenge_is_traced_with_its_reason(self) -> None:
        """Asked for only because the user switched Vs PoW on, so a miss is worth showing."""
        for status, body, reason in (
            (404, '{"success":false,"message":"not found"}', "not found"),
            (200, '{"message":"invalid purpose","success":false}', "invalid purpose"),
            (200, pow_challenge(enabled=False), "站点未启用 PoW"),
            (200, "<html>maintenance</html>", "响应不是 Vs PoW 题目（HTTP 200）"),
        ):
            with self.subTest(body=body):
                headers, error, _asked, trace = await self._obtain(status, body)
                self.assertEqual((headers, error), ({}, ""))
                self.assertEqual([(t["step"], t["message"]) for t in trace],
                                 [("获取 PoW 题目", f"{reason}，本次不带 PoW")])

    async def test_an_unreachable_station_is_not_an_error(self) -> None:
        async def fetch(url):
            raise ConnectionError("reset")

        trace = []
        result = await obtain_proof(BASE, "checkin", fetch, lambda *a, **k: trace.append(k))
        self.assertEqual(result, ({}, ""))
        self.assertIn("reset", trace[0]["message"])

    async def test_a_challenge_too_hard_says_so(self) -> None:
        with mock.patch.object(PowChallenge, "solve", side_effect=PowTimeout):
            headers, error, _asked, trace = await self._obtain(200, pow_challenge(difficulty=30))
        self.assertEqual(headers, {})
        self.assertIn("难度 30", error)
        self.assertFalse(trace[0].get("success", False))

    async def test_an_oversized_seed_is_never_solved(self) -> None:
        with mock.patch.object(PowChallenge, "solve") as solve:
            headers, error, _asked, trace = await self._obtain(
                200, pow_challenge(seed="x" * 1025)
            )
        solve.assert_not_awaited()
        self.assertEqual((headers, error), ({}, ""))
        self.assertIn("1024", trace[0]["message"])


class SendWithProofTests(unittest.IsolatedAsyncioTestCase):
    """The station's own retry: a refused proof is retried on a new challenge."""

    async def _send(self, challenges: list[str], answers: list[str]):
        challenges, answers, sent = list(challenges), list(answers), []

        async def fetch(url):
            return 200, challenges.pop(0)

        async def send(proof):
            sent.append(proof.get(POW_TOKEN_HEADER))
            return answers.pop(0)

        response, proof, error = await send_with_proof(
            BASE, "checkin", fetch, lambda *a, **k: None, send, is_refusal
        )
        return response, proof, error, sent

    async def test_a_refused_proof_is_retried_on_a_new_challenge(self) -> None:
        response, proof, error, sent = await self._send(
            [pow_challenge("tok-1"), pow_challenge("tok-2")], [POW_REFUSED, "ok"]
        )
        self.assertEqual((response, error, sent), ("ok", "", ["tok-1", "tok-2"]))
        self.assertEqual(proof[POW_TOKEN_HEADER], "tok-2")

    async def test_it_gives_up_after_the_stations_own_limit(self) -> None:
        response, _proof, _error, sent = await self._send(
            [pow_challenge(f"tok-{i}") for i in range(5)], [POW_REFUSED] * 5
        )
        self.assertEqual(response, POW_REFUSED)
        self.assertEqual(len(sent), POW_MAX_ATTEMPTS)

    async def test_a_bare_request_is_not_repeated_once_refused(self) -> None:
        """Without a challenge another bare request would only be refused again."""
        response, proof, _error, sent = await self._send(
            ['{"message":"未登录","success":false}'] * 2, [POW_REFUSED] * 2
        )
        self.assertEqual((response, proof, sent), (POW_REFUSED, {}, [None]))

    async def test_a_challenge_too_hard_sends_nothing(self) -> None:
        with mock.patch.object(PowChallenge, "solve", side_effect=PowTimeout):
            response, _proof, error, sent = await self._send([pow_challenge()], ["ok"])
        self.assertIsNone(response)
        self.assertIn("难度 18", error)
        self.assertEqual(sent, [])


if __name__ == "__main__":
    unittest.main()
