"""Unit tests for the credential- and action-driven check-in adapters."""

from __future__ import annotations

import json
import unittest
from unittest import mock

import tests  # noqa: F401
from core.adapters import (
    MAX_ATTEMPTS_PER_RUN,
    QUOTA_CONVERSION_FACTOR,
    BaseCheckInAdapter,
    GenericRestAdapter,
    NewApiAdapter,
    SiteWriteback,
    create_adapter,
    persist_writeback,
)
from core.cloudflare import Resolution
from core.http_client import RequestOptions
from core.pow import POW_MAX_ATTEMPTS, PowChallenge, PowTimeout
from core.site_schema import ACTION_BALANCE, ACTION_CHECKIN, NEW_API_USER_HEADER, find_header
from tests.fakes import (
    POW_NONCE,
    POW_REFUSED,
    FakeResponse,
    FakeSession,
    carries_mldsa,
    pow_challenge,
    pow_proof,
)

BASE = "https://relay.example.com"
POW_URL = f"{BASE}/api/pow/challenge?purpose=checkin"
CHECKED_IN = '{"success":true,"message":"签到成功"}'


def self_payload(quota: float, user_id: int = 7) -> str:
    """Render a New-API ``/api/user/self`` body."""
    return json.dumps({"success": True, "data": {"id": user_id, "quota": quota}})


def make_site(**overrides) -> dict:
    """Build a site config with the new credential/action shape."""
    site = {
        "id": "s1",
        "name": "Relay",
        "type": "new-api",
        "base_url": BASE,
        "proxy": "",
        "credentials": [{"id": "c1", "type": "token", "value": "sk-a"}],
        "checkin": {},
        "balance": {},
        "enabled": True,
    }
    site.update(overrides)
    return site


class CredentialHeaderTests(unittest.IsolatedAsyncioTestCase):
    async def _auth_headers(self, credential: dict, balance: dict | None = None) -> dict:
        session = FakeSession({("GET", f"{BASE}/api/user/self"): FakeResponse(200, self_payload(0))})
        site = make_site(credentials=[credential], balance=balance or {"protocol": "get"})
        await create_adapter(site, session).query_balance()
        return session.calls[0]["headers"]

    async def test_token_gets_a_bearer_prefix(self) -> None:
        headers = await self._auth_headers({"id": "c", "type": "token", "value": "sk-plain"})
        self.assertEqual(headers["Authorization"], "Bearer sk-plain")

    async def test_existing_bearer_prefix_is_not_doubled(self) -> None:
        headers = await self._auth_headers({"id": "c", "type": "token", "value": "Bearer sk-plain"})
        self.assertEqual(headers["Authorization"], "Bearer sk-plain")

    async def test_auto_bearer_off_sends_the_value_verbatim(self) -> None:
        headers = await self._auth_headers(
            {"id": "c", "type": "token", "value": "Basic abc", "auto_bearer": False}
        )
        self.assertEqual(headers["Authorization"], "Basic abc")

    async def test_cookie_credential_becomes_a_cookie_header(self) -> None:
        headers = await self._auth_headers({"id": "c", "type": "cookie", "value": "session=abc"})
        self.assertEqual(headers["Cookie"], "session=abc")
        self.assertNotIn("Authorization", headers)

    async def test_pasted_newlines_are_stripped(self) -> None:
        headers = await self._auth_headers({"id": "c", "type": "token", "value": " sk-a\n"})
        self.assertEqual(headers["Authorization"], "Bearer sk-a")

    async def test_custom_headers_override_the_credential(self) -> None:
        headers = await self._auth_headers(
            {"id": "c", "type": "token", "value": "sk-a"},
            balance={
                "protocol": "get",
                "headers": [
                    {"key": "Authorization", "value": "Bearer override"},
                    {"key": "X-Custom", "value": "1"},
                ],
            },
        )
        self.assertEqual(headers["Authorization"], "Bearer override")
        self.assertEqual(headers["X-Custom"], "1")

    async def test_missing_credential_fails_before_any_request(self) -> None:
        session = FakeSession({})
        result = await create_adapter(make_site(credentials=[]), session).check_in()
        self.assertFalse(result.success)
        self.assertIn("凭据", result.message)
        self.assertEqual(session.calls, [])

    async def test_blank_credential_value_is_reported(self) -> None:
        session = FakeSession({})
        site = make_site(credentials=[{"id": "c", "type": "token", "value": ""}])
        result = await create_adapter(site, session).check_in()
        self.assertFalse(result.success)
        self.assertIn("未填写", result.message)

    async def test_token_is_preferred_over_cookie(self) -> None:
        headers = await self._auth_headers({"id": "tk", "type": "token", "value": "sk-tok"})
        self.assertIn("Authorization", headers)

    async def test_explicit_credential_id_wins(self) -> None:
        session = FakeSession({("GET", f"{BASE}/api/user/self"): FakeResponse(200, self_payload(0))})
        site = make_site(
            credentials=[
                {"id": "ck", "type": "cookie", "value": "session=ck"},
                {"id": "tk", "type": "token", "value": "sk-tok"},
            ],
            balance={"protocol": "get", "credential_id": "ck"},
        )
        await create_adapter(site, session).query_balance()
        headers = session.calls[0]["headers"]
        self.assertEqual(headers["Cookie"], "session=ck")
        self.assertNotIn("Authorization", headers)


class BalanceQueryTests(unittest.IsolatedAsyncioTestCase):
    async def _quota(self, body: str, site_overrides: dict | None = None) -> tuple[float, str]:
        session = FakeSession(
            {
                ("GET", f"{BASE}/api/user/self"): FakeResponse(200, body),
                ("GET", f"{BASE}/me"): FakeResponse(200, body),
            }
        )
        site = make_site(**(site_overrides or {}))
        return await create_adapter(site, session).query_balance()

    async def test_raw_quota_is_converted_to_currency(self) -> None:
        quota, error = await self._quota(self_payload(QUOTA_CONVERSION_FACTOR))
        self.assertEqual((quota, error), (1.0, ""))

    async def test_currency_fields_are_used_as_is(self) -> None:
        quota, _ = await self._quota(
            '{"data":{"balance":12.5}}',
            {"type": "generic_rest", "balance": {"path": "/me", "protocol": "get"}},
        )
        self.assertEqual(quota, 12.5)

    async def test_top_level_quota_is_accepted(self) -> None:
        quota, _ = await self._quota('{"quota":250000}')
        self.assertEqual(quota, 0.5)

    async def test_booleans_are_not_treated_as_amounts(self) -> None:
        _, error = await self._quota('{"data":{"quota":true}}')
        self.assertIn("未找到额度", error)

    async def test_missing_amount_is_reported(self) -> None:
        _, error = await self._quota('{"data":{"username":"x"}}')
        self.assertIn("未找到额度", error)

    async def test_non_json_is_reported(self) -> None:
        _, error = await self._quota("not json at all")
        self.assertIn("非 JSON", error)

    async def test_html_body_is_reported_as_a_page(self) -> None:
        _, error = await self._quota("<html><body>login</body></html>")
        self.assertIn("HTML", error)

    async def test_unadapted_framework_skips_the_query(self) -> None:
        """A generic site with no balance path must not guess an endpoint."""
        session = FakeSession({})
        site = make_site(type="generic_rest")
        quota, error = await create_adapter(site, session).query_balance()
        self.assertEqual((quota, error), (0.0, ""))
        self.assertEqual(session.calls, [])

    async def test_absolute_custom_path_is_used_verbatim(self) -> None:
        session = FakeSession(
            {("GET", "https://other.test/api/me"): FakeResponse(200, '{"balance":3}')}
        )
        site = make_site(balance={"path": "https://other.test/api/me", "protocol": "get"})
        quota, error = await create_adapter(site, session).query_balance()
        self.assertEqual((quota, error), (3.0, ""))


class NewApiCheckInTests(unittest.IsolatedAsyncioTestCase):
    async def test_a_failed_final_read_keeps_the_known_balance(self) -> None:
        """A confirmed balance must not be overwritten with zero.

        The opening read succeeded, so the closing failure means "unknown", not
        "empty" — reporting 0 would blank a correct last_quota and its calendar
        cell.
        """
        session = FakeSession(
            {
                ("GET", f"{BASE}/api/user/self"): [
                    FakeResponse(200, self_payload(5_000_000)),
                    FakeResponse(503, "service unavailable"),
                ],
                ("POST", f"{BASE}/api/user/checkin"): FakeResponse(
                    200, '{"success":true,"message":"签到成功"}'
                ),
            }
        )
        result = await create_adapter(make_site(), session).check_in()

        self.assertTrue(result.success)
        self.assertFalse(result.expired)
        self.assertEqual(result.total_quota, 10.0)
        self.assertEqual(result.gained_quota, 0.0)
        self.assertIn("查询最终余额", result.error_detail)

    async def test_the_two_balance_reads_are_traced_separately(self) -> None:
        session = FakeSession(
            {
                ("GET", f"{BASE}/api/user/self"): FakeResponse(200, self_payload(0)),
                ("POST", f"{BASE}/api/user/checkin"): FakeResponse(200, '{"success":true}'),
            }
        )
        result = await create_adapter(make_site(), session).check_in()
        self.assertEqual(
            [attempt["step"] for attempt in result.attempts],
            ["查询余额", "签到", "查询最终余额"],
        )

    async def test_a_failed_opening_read_leaves_the_balance_unknown(self) -> None:
        """With no confirmed opening value there is nothing to fall back to."""
        session = FakeSession(
            {
                ("GET", f"{BASE}/api/user/self"): FakeResponse(503, "unavailable"),
                ("POST", f"{BASE}/api/user/checkin"): FakeResponse(
                    200, '{"success":true,"message":"签到成功"}'
                ),
            }
        )
        result = await create_adapter(make_site(), session).check_in()
        self.assertEqual(result.total_quota, 0.0)

    async def test_framework_check_in_and_quota_delta(self) -> None:
        session = FakeSession(
            {
                ("GET", f"{BASE}/api/user/self"): [
                    FakeResponse(200, self_payload(500000, 42)),
                    FakeResponse(200, self_payload(1500000, 42)),
                ],
                ("POST", f"{BASE}/api/user/checkin"): FakeResponse(
                    200, '{"success":true,"message":"签到成功"}'
                ),
            }
        )
        adapter = create_adapter(make_site(credentials=[{"id": "c", "type": "cookie", "value": "s=1"}]), session)
        result = await adapter.check_in()

        self.assertTrue(result.success)
        self.assertEqual(result.total_quota, 3.0)
        self.assertEqual(result.gained_quota, 2.0)

    async def test_new_api_user_is_probed_and_written_back(self) -> None:
        session = FakeSession(
            {
                ("GET", f"{BASE}/api/user/self"): FakeResponse(200, self_payload(0, 42)),
                ("POST", f"{BASE}/api/user/checkin"): FakeResponse(200, '{"success":true}'),
            }
        )
        adapter = create_adapter(make_site(), session)
        await adapter.check_in()

        self.assertEqual(find_header(adapter.writeback.checkin_headers, NEW_API_USER_HEADER), "42")
        checkin_calls = session.calls_to("/api/user/checkin")
        self.assertEqual(checkin_calls[0]["headers"][NEW_API_USER_HEADER], "42")

    async def test_the_user_id_is_harvested_without_an_extra_request(self) -> None:
        """The balance response already carries the id, so no probe is needed."""
        session = FakeSession(
            {
                ("GET", f"{BASE}/api/user/self"): FakeResponse(200, self_payload(0, 42)),
                ("POST", f"{BASE}/api/user/checkin"): FakeResponse(200, '{"success":true}'),
            }
        )
        await create_adapter(make_site(), session).check_in()
        # Exactly two: the opening and closing balance reads.
        self.assertEqual(session.count_to("/api/user/self"), 2)

    async def test_explicit_protocol_skips_the_probe(self) -> None:
        session = FakeSession(
            {
                ("GET", f"{BASE}/api/user/self"): FakeResponse(200, self_payload(0, 42)),
                ("POST", f"{BASE}/sign"): FakeResponse(200, '{"success":true}'),
            }
        )
        adapter = create_adapter(make_site(checkin={"path": "/sign", "protocol": "post"}), session)
        await adapter.check_in()
        self.assertIsNone(adapter.writeback.checkin_headers)

    async def test_a_rejected_post_does_not_fall_back_to_the_status_get(self) -> None:
        """Upstream's GET /api/user/checkin is the status read: it answers
        success:true without checking in, so a fallback to it is a false pass."""
        session = FakeSession(
            {
                ("GET", f"{BASE}/api/user/self"): FakeResponse(200, self_payload(500000)),
                ("POST", f"{BASE}/api/user/checkin"): FakeResponse(405, "method not allowed"),
                ("GET", f"{BASE}/api/user/checkin"): FakeResponse(
                    200, '{"success":true,"data":{"enabled":true}}'
                ),
            }
        )
        result = await create_adapter(make_site(), session).check_in()
        self.assertFalse(result.success)
        self.assertEqual(
            [c["method"] for c in session.calls_to("/api/user/checkin")], ["POST"]
        )

    async def test_a_missing_endpoint_is_not_probed_elsewhere(self) -> None:
        session = FakeSession(
            {("GET", f"{BASE}/api/user/self"): FakeResponse(200, self_payload(0))},
            default=FakeResponse(404, "nope"),
        )
        result = await create_adapter(make_site(), session).check_in()
        self.assertFalse(result.success)
        self.assertIn("404", result.message)
        self.assertEqual(
            [c["url"] for c in session.calls if "/api/user/self" not in c["url"]],
            [f"{BASE}/api/user/checkin"],
        )

    async def test_already_signed_in_counts_as_success(self) -> None:
        session = FakeSession(
            {
                ("GET", f"{BASE}/api/user/self"): FakeResponse(200, self_payload(0)),
                ("POST", f"{BASE}/api/user/checkin"): FakeResponse(
                    200, '{"success":false,"message":"今日已签到"}'
                ),
            }
        )
        result = await create_adapter(make_site(), session).check_in()
        self.assertTrue(result.success)
        self.assertIn("已签到", result.message)

    async def test_english_already_checked_in_counts_as_success(self) -> None:
        """What vsllm.cc answers a repeat check-in."""
        session = FakeSession(
            {
                ("GET", f"{BASE}/api/user/self"): FakeResponse(200, self_payload(0)),
                ("POST", f"{BASE}/api/user/checkin"): FakeResponse(
                    200, '{"message":"Already checked in today","success":false}'
                ),
            }
        )
        result = await create_adapter(make_site(), session).check_in()
        self.assertTrue(result.success)
        self.assertIn("Already checked in today", result.message)

    async def test_401_marks_the_credential_expired(self) -> None:
        session = FakeSession({}, default=FakeResponse(401, '{"success":false,"message":"unauthorized"}'))
        result = await create_adapter(make_site(), session).check_in()
        self.assertFalse(result.success)
        self.assertTrue(result.expired)

    async def test_negated_english_checkin_messages_are_failures(self) -> None:
        for message in (
            "Not already checked in",
            "You have not already signed in today",
        ):
            with self.subTest(message=message):
                session = FakeSession(
                    {
                        ("GET", f"{BASE}/api/user/self"): FakeResponse(
                            200, self_payload(0)
                        ),
                        ("POST", f"{BASE}/api/user/checkin"): FakeResponse(
                            200, json.dumps({"success": False, "message": message})
                        ),
                    }
                )
                result = await create_adapter(make_site(), session).check_in()
                self.assertFalse(result.success)
                self.assertEqual(result.message, message)

    async def test_a_missing_new_api_user_is_not_an_expired_credential(self) -> None:
        """What vsllm.cc answers a good token without the header, on every route."""
        session = FakeSession({}, default=FakeResponse(
            401, '{"success":false,"message":"无权进行此操作，未提供 New-Api-User"}'))
        result = await create_adapter(make_site(), session).check_in()
        self.assertFalse(result.success)
        self.assertFalse(result.expired)
        self.assertIn("New-Api-User", result.message)

    async def test_a_custom_path_replaces_the_framework_one(self) -> None:
        session = FakeSession(
            {
                ("GET", f"{BASE}/api/user/self"): FakeResponse(200, self_payload(0)),
                ("POST", f"{BASE}/custom/sign"): FakeResponse(200, '{"success":true,"message":"ok"}'),
            }
        )
        site = make_site(checkin={"path": "/custom/sign", "protocol": "post"})
        result = await create_adapter(site, session).check_in()
        self.assertTrue(result.success)
        self.assertEqual(session.count_to("/api/user/checkin"), 0)


class NewApiTestConnectionTests(unittest.IsolatedAsyncioTestCase):
    async def test_reports_the_balance_on_success(self) -> None:
        session = FakeSession(
            {("GET", f"{BASE}/api/user/self"): FakeResponse(200, self_payload(500000))}
        )
        result = await create_adapter(make_site(), session).test_connection()
        self.assertTrue(result.success)
        self.assertEqual(result.total_quota, 1.0)

    async def test_never_performs_a_check_in(self) -> None:
        session = FakeSession(
            {("GET", f"{BASE}/api/user/self"): FakeResponse(200, self_payload(0))}
        )
        await create_adapter(make_site(), session).test_connection()
        self.assertEqual(session.count_to("/api/user/checkin"), 0)

    async def test_falls_back_to_the_models_endpoint(self) -> None:
        """A blocked management API is still distinguishable from a dead key."""
        session = FakeSession(
            {
                ("GET", f"{BASE}/api/user/self"): FakeResponse(403, "denied"),
                ("GET", f"{BASE}/v1/models"): FakeResponse(200, '{"data":[{"id":"model-x"}]}'),
            }
        )
        result = await create_adapter(make_site(), session).test_connection()
        self.assertFalse(result.success)
        self.assertIn("模型接口可用", result.message)

    async def test_a_waf_block_is_not_reported_as_an_expired_key(self) -> None:
        """The key works, so flagging it expired would send the user to
        regenerate a perfectly good credential."""
        session = FakeSession(
            {
                ("GET", f"{BASE}/api/user/self"): FakeResponse(200, "<html>WAF challenge</html>"),
                ("GET", f"{BASE}/v1/models"): FakeResponse(200, '{"data":[{"model":"gpt-test"}]}'),
            }
        )
        result = await create_adapter(make_site(), session).test_connection()

        self.assertFalse(result.success)
        self.assertFalse(result.expired)
        self.assertIn("API Key 有效", result.message)
        self.assertIn("API 接口兜底探测", result.error_detail)

    async def test_a_dead_key_is_still_reported_as_expired(self) -> None:
        session = FakeSession(
            {
                ("GET", f"{BASE}/api/user/self"): FakeResponse(401, '{"success":false}'),
                ("GET", f"{BASE}/v1/models"): FakeResponse(401, "unauthorized"),
            }
        )
        result = await create_adapter(make_site(), session).test_connection()
        self.assertFalse(result.success)
        self.assertTrue(result.expired)


class ProviderCookieRotationTests(unittest.IsolatedAsyncioTestCase):
    """The provider cookie must follow the provider's rotation, or the stored
    value goes stale and the next run replays a retired session."""

    HELD = "user_session=OLD; _gh_sess=G1; logged_in=yes"

    def _site(self):
        return make_site(
            credentials=[{"id": "gh", "type": "github_oauth", "label": "Github",
                          "value": self.HELD}],
            checkin={"protocol": "oauth"},
        )

    def _routes(self, authorize):
        return {
            ("GET", f"{BASE}/api/status"): FakeResponse(
                200, '{"data":{"github_oauth":true,"github_client_id":"cid"}}'
            ),
            ("GET", f"{BASE}/api/oauth/state"): FakeResponse(200, '{"data":"st"}'),
            ("GET", "https://github.com/login/oauth/authorize"): authorize,
            ("GET", f"{BASE}/api/oauth/github"): FakeResponse(
                200, "{}", cookies={"session": "fresh"}
            ),
            ("GET", f"{BASE}/api/user/self"): FakeResponse(200, self_payload(0)),
        }

    async def test_a_rotation_is_captured_for_writeback(self) -> None:
        session = FakeSession(self._routes(FakeResponse(
            302, "", headers={"location": f"{BASE}/cb?code=C&state=st"},
            cookies={"_gh_sess": "G2"},
        )))
        adapter = create_adapter(self._site(), session)
        result = await adapter.check_in()
        self.assertTrue(result.success)
        self.assertIn("_gh_sess=G2", adapter.writeback.credential_values["gh"])

    async def test_the_other_cookies_are_preserved(self) -> None:
        session = FakeSession(self._routes(FakeResponse(
            302, "", headers={"location": f"{BASE}/cb?code=C&state=st"},
            cookies={"_gh_sess": "G2"},
        )))
        adapter = create_adapter(self._site(), session)
        await adapter.check_in()
        stored = adapter.writeback.credential_values["gh"]
        self.assertIn("user_session=OLD", stored)
        self.assertIn("logged_in=yes", stored)

    async def test_no_rotation_writes_nothing(self) -> None:
        session = FakeSession(self._routes(FakeResponse(
            302, "", headers={"location": f"{BASE}/cb?code=C&state=st"},
        )))
        adapter = create_adapter(self._site(), session)
        await adapter.check_in()
        self.assertEqual(adapter.writeback.credential_values, {})

    async def test_a_scoped_cookie_update_is_written_back_with_its_header(self) -> None:
        response = FakeResponse(
            302, "", headers={"location": f"{BASE}/cb?code=C&state=st"}
        )
        response.provider_cookies = [
            {
                "name": "user_session",
                "value": "rotated",
                "domain": "github.com",
                "path": "/",
            },
        ]
        adapter = create_adapter(self._site(), FakeSession(self._routes(response)))
        self.assertTrue((await adapter.check_in()).success)
        scoped = adapter.writeback.provider_cookies["gh"]
        self.assertTrue(
            any(c["value"] == "rotated" and c["domain"] == "github.com" for c in scoped)
        )
        self.assertEqual(adapter.writeback.credential_values["gh"], self.HELD)
        calls = []

        class Db:
            def update_action_headers(self, *args):
                pass

            def update_credential_session(self, *args):
                pass

            def update_credential_value(self, site, credential, value, **kwargs):
                calls.append((site, credential, value, kwargs))

        persist_writeback(Db(), "s1", adapter.writeback)
        self.assertEqual(calls, [("s1", "gh", self.HELD, {"provider_cookies": scoped})])

    async def test_a_rotation_is_kept_even_when_the_login_fails(self) -> None:
        """The provider may move the session on before rejecting; replaying the
        retired value would guarantee the next failure too."""
        session = FakeSession(self._routes(FakeResponse(
            302, "", headers={"location": "https://github.com/login"},
            cookies={"_gh_sess": "G2"},
        )))
        adapter = create_adapter(self._site(), session)
        result = await adapter.check_in()
        self.assertFalse(result.success)
        self.assertIn("_gh_sess=G2", adapter.writeback.credential_values["gh"])

    async def test_the_credential_in_memory_is_updated(self) -> None:
        """A later leg in the same run must use the rotated value."""
        site = self._site()
        session = FakeSession(self._routes(FakeResponse(
            302, "", headers={"location": f"{BASE}/cb?code=C&state=st"},
            cookies={"_gh_sess": "G2"},
        )))
        adapter = create_adapter(site, session)
        await adapter.check_in()
        self.assertIn("_gh_sess=G2", adapter.credentials[0]["value"])

    def test_the_writeback_reports_a_rotation_as_pending(self) -> None:
        self.assertTrue(SiteWriteback().is_empty())
        self.assertFalse(SiteWriteback(credential_values={"gh": "x"}).is_empty())

    def test_persist_writeback_routes_a_rotation(self) -> None:
        calls = []

        class Db:
            def update_action_headers(self, *a): calls.append(("headers", *a)); return True
            def update_credential_session(self, *a): calls.append(("session", *a)); return True
            def update_credential_value(self, *a): calls.append(("value", *a)); return True

        persist_writeback(Db(), "s1", SiteWriteback(credential_values={"gh": "new"}))
        self.assertEqual(calls, [("value", "s1", "gh", "new")])


class ProbeNewApiUserTests(unittest.IsolatedAsyncioTestCase):
    """The dashboard's fetch button needs a reason on failure, not silence."""

    async def test_it_returns_the_station_account_id(self) -> None:
        session = FakeSession(
            {("GET", f"{BASE}/api/user/self"): FakeResponse(200, self_payload(0, 2259))}
        )
        user_id, detail = await create_adapter(make_site(), session).probe_new_api_user_id()
        self.assertEqual(user_id, "2259")
        self.assertEqual(detail, "")

    async def test_a_response_without_an_id_explains_one_api(self) -> None:
        """One-API has no such field, which is not an error worth alarming about."""
        session = FakeSession(
            {("GET", f"{BASE}/api/user/self"): FakeResponse(200, '{"data":{"quota":5},"success":true}')}
        )
        user_id, detail = await create_adapter(make_site(), session).probe_new_api_user_id()
        self.assertEqual(user_id, "")
        self.assertIn("One-API", detail)

    async def test_an_auth_failure_is_reported(self) -> None:
        session = FakeSession(
            {("GET", f"{BASE}/api/user/self"): FakeResponse(401, '{"success":false}')}
        )
        user_id, detail = await create_adapter(make_site(), session).probe_new_api_user_id()
        self.assertEqual(user_id, "")
        self.assertTrue(detail)

    async def test_a_station_demanding_the_header_first_is_explained(self) -> None:
        """vsllm.cc asks for New-Api-User on /api/user/self too, with a token
        (2026-09-27): the id cannot be probed, and the token is fine."""
        session = FakeSession({("GET", f"{BASE}/api/user/self"): FakeResponse(
            401, '{"message":"Unauthorized, New-Api-User header not provided","success":false}')})
        user_id, detail = await create_adapter(make_site(), session).probe_new_api_user_id()
        self.assertEqual(user_id, "")
        self.assertIn("手动填写", detail)
        self.assertIn("New-Api-User header not provided", detail)
        self.assertNotIn("已过期", detail)

    async def test_a_missing_credential_is_reported(self) -> None:
        session = FakeSession({})
        user_id, detail = await create_adapter(make_site(credentials=[]), session).probe_new_api_user_id()
        self.assertEqual(user_id, "")
        self.assertIn("凭据", detail)

    async def test_an_oauth_credential_needs_no_manual_fetch(self) -> None:
        """/api/user/self refuses the cookie without the header, so the id comes from the login."""
        site = make_site(credentials=[{"id": "gh", "type": "github_oauth", "value": "user_session=x",
                                      "session_cookie": "session=live"}])
        user_id, detail = await create_adapter(site, FakeSession({})).probe_new_api_user_id()
        self.assertEqual(user_id, "")
        self.assertIn("无需", detail)

    async def test_the_probe_never_logs_in(self) -> None:
        """Fetching a header must not consume an OAuth station's daily sign-in."""
        site = make_site(credentials=[{"id": "gh", "type": "github_oauth", "value": "user_session=x"}])
        session = FakeSession({})
        await create_adapter(site, session).probe_new_api_user_id()
        self.assertEqual(session.count_to("/api/oauth/github"), 0)

    async def test_it_appears_in_the_request_trace(self) -> None:
        session = FakeSession(
            {("GET", f"{BASE}/api/user/self"): FakeResponse(200, self_payload(0, 7))}
        )
        adapter = create_adapter(make_site(), session)
        await adapter.probe_new_api_user_id()
        self.assertIn("探测 new-api-user", [a["step"] for a in adapter.attempts])


class GenericRestTests(unittest.IsolatedAsyncioTestCase):
    async def test_empty_path_gets_the_base_url(self) -> None:
        session = FakeSession({("GET", BASE): FakeResponse(200, '{"success":true,"message":"ok"}')})
        site = make_site(type="generic_rest", credentials=[{"id": "c", "type": "cookie", "value": "s=1"}])
        result = await create_adapter(site, session).check_in()
        self.assertTrue(result.success)
        self.assertEqual(session.calls[0]["url"], BASE)
        self.assertEqual(session.calls[0]["method"], "GET")

    async def test_custom_path_and_balance(self) -> None:
        session = FakeSession(
            {
                ("POST", f"{BASE}/sign"): FakeResponse(200, '{"success":true,"message":"done"}'),
                ("GET", f"{BASE}/me"): FakeResponse(200, '{"data":{"balance":12.5}}'),
            }
        )
        site = make_site(
            type="generic_rest",
            checkin={"path": "sign", "protocol": "post"},
            balance={"path": "/me", "protocol": "get"},
        )
        result = await create_adapter(site, session).check_in()
        self.assertTrue(result.success)
        self.assertEqual(result.total_quota, 12.5)

    async def test_a_success_body_cannot_rescue_a_failed_status(self) -> None:
        session = FakeSession({("GET", BASE): FakeResponse(401, '{"success":"true"}')})
        result = await create_adapter(make_site(type="generic_rest"), session).check_in()
        self.assertFalse(result.success)
        self.assertTrue(result.expired)

    async def test_a_failure_body_overrides_a_2xx_status(self) -> None:
        session = FakeSession({("GET", BASE): FakeResponse(200, '{"success":false}')})
        result = await create_adapter(make_site(type="generic_rest"), session).check_in()
        self.assertFalse(result.success)

    async def test_non_json_body_follows_the_http_status(self) -> None:
        session = FakeSession({("GET", BASE): FakeResponse(200, "plain ok")})
        result = await create_adapter(make_site(type="generic_rest"), session).check_in()
        self.assertTrue(result.success)
        self.assertIn("plain ok", result.message)

    async def test_test_connection_does_not_hit_the_checkin_path(self) -> None:
        session = FakeSession(
            {
                ("GET", f"{BASE}/me"): FakeResponse(200, '{"data":{"balance":3}}'),
                ("POST", f"{BASE}/sign"): FakeResponse(200, '{"success":true}'),
            }
        )
        site = make_site(
            type="generic_rest",
            checkin={"path": "/sign", "protocol": "post"},
            balance={"path": "/me", "protocol": "get"},
        )
        result = await create_adapter(site, session).test_connection()
        self.assertTrue(result.success)
        self.assertEqual(session.count_to("/sign"), 0)

    async def test_test_connection_probes_the_base_url_without_a_balance_path(self) -> None:
        session = FakeSession({("GET", BASE): FakeResponse(200, '{"success":true}')})
        site = make_site(type="generic_rest", checkin={"path": "/sign", "protocol": "post"})
        result = await create_adapter(site, session).test_connection()
        self.assertTrue(result.success)
        self.assertEqual(result.message, "连接成功")
        self.assertEqual(session.urls(), [BASE])


class OAuthCheckInTests(unittest.IsolatedAsyncioTestCase):
    @staticmethod
    def _github_routes(extra: dict | None = None) -> dict:
        routes = {
            ("GET", f"{BASE}/api/status"): FakeResponse(
                200, '{"data":{"github_oauth":true,"github_client_id":"cid"}}'
            ),
            ("POST", f"{BASE}/api/oauth/state"): FakeResponse(200, '{"data":{"flow_token":"flow-1"}}'),
            ("GET", "https://github.com/login/oauth/authorize"): FakeResponse(
                302, "", headers={"location": f"{BASE}/oauth/github?code=CODE1&state=flow-1"}
            ),
            ("GET", f"{BASE}/api/oauth/github"): FakeResponse(
                200, "{}", cookies={"session": "fresh-session"}
            ),
            ("POST", f"{BASE}/api/user/checkin"): FakeResponse(200, '{"success":true,"message":"ok"}'),
        }
        routes.update(extra or {})
        return routes

    async def test_logs_in_when_no_session_is_stored(self) -> None:
        session = FakeSession(
            self._github_routes({("GET", f"{BASE}/api/user/self"): FakeResponse(200, self_payload(0))})
        )
        site = make_site(
            credentials=[{"id": "gh", "type": "github_oauth", "value": "user_session=gh"}],
            checkin={"protocol": "oauth"},
        )
        adapter = create_adapter(site, session)
        result = await adapter.check_in()

        self.assertTrue(result.success)
        self.assertEqual(adapter.writeback.oauth_sessions["gh"], "session=fresh-session")

    async def test_a_stale_session_triggers_exactly_one_relogin(self) -> None:
        session = FakeSession(
            self._github_routes(
                {
                    ("GET", f"{BASE}/api/user/self"): [
                        FakeResponse(401, '{"success":false}'),
                        FakeResponse(200, self_payload(1000000)),
                        FakeResponse(200, self_payload(1000000)),
                    ]
                }
            )
        )
        site = make_site(
            proxy="http://127.0.0.1:7890",
            credentials=[
                {
                    "id": "gh",
                    "type": "github_oauth",
                    "value": "user_session=gh",
                    "session_cookie": "session=stale",
                }
            ],
            checkin={"protocol": "oauth"},
        )
        adapter = create_adapter(site, session)
        result = await adapter.check_in()

        self.assertTrue(result.success)
        self.assertEqual(adapter.writeback.oauth_sessions["gh"], "session=fresh-session")
        self.assertEqual(session.count_to("/api/oauth/github"), 1)

    async def test_the_refreshed_session_reaches_the_check_in_request(self) -> None:
        session = FakeSession(
            self._github_routes(
                {
                    ("GET", f"{BASE}/api/user/self"): [
                        FakeResponse(401, '{"success":false}'),
                        FakeResponse(200, self_payload(0)),
                        FakeResponse(200, self_payload(0)),
                    ]
                }
            )
        )
        site = make_site(
            credentials=[
                {
                    "id": "gh",
                    "type": "github_oauth",
                    "value": "user_session=gh",
                    "session_cookie": "session=stale",
                }
            ],
            checkin={"protocol": "oauth"},
        )
        await create_adapter(site, session).check_in()
        # Under the OAuth protocol no check-in endpoint is called, so the
        # refreshed session shows up on the balance read instead.
        reads = session.calls_to("/api/user/self")
        self.assertEqual(reads[-1]["headers"]["Cookie"], "session=fresh-session")

    async def test_the_site_proxy_covers_the_third_party_leg(self) -> None:
        session = FakeSession(
            self._github_routes({("GET", f"{BASE}/api/user/self"): FakeResponse(200, self_payload(0))})
        )
        site = make_site(
            proxy="http://127.0.0.1:7890",
            credentials=[{"id": "gh", "type": "github_oauth", "value": "user_session=gh"}],
            checkin={"protocol": "oauth"},
        )
        await create_adapter(site, session).check_in()
        github_calls = [c for c in session.calls if "github.com" in c["url"]]
        self.assertTrue(github_calls)
        self.assertTrue(all(c["proxy"] == "http://127.0.0.1:7890" for c in session.calls))

    async def test_an_expired_third_party_cookie_is_reported(self) -> None:
        routes = self._github_routes(
            {
                ("GET", f"{BASE}/api/user/self"): FakeResponse(200, self_payload(0)),
                ("GET", "https://github.com/login/oauth/authorize"): FakeResponse(
                    302, "", headers={"location": "https://github.com/login"}
                ),
            }
        )
        site = make_site(
            credentials=[{"id": "gh", "type": "github_oauth", "value": "user_session=dead"}],
            checkin={"protocol": "oauth"},
        )
        result = await create_adapter(site, FakeSession(routes)).check_in()
        self.assertFalse(result.success)
        self.assertIn("Cookie", result.message)

    async def test_oauth_protocol_without_an_oauth_credential_fails(self) -> None:
        session = FakeSession({("GET", f"{BASE}/api/user/self"): FakeResponse(200, self_payload(0))})
        site = make_site(checkin={"protocol": "oauth"})
        result = await create_adapter(site, session).check_in()
        self.assertFalse(result.success)
        self.assertIn("OAuth", result.message)

    async def test_linuxdo_authorize_matches_the_browser_flow(self) -> None:
        session = FakeSession(
            {
                ("GET", f"{BASE}/api/status"): FakeResponse(
                    200, '{"data":{"linuxdo_oauth":true,"linuxdo_client_id":"cid"}}'
                ),
                ("POST", f"{BASE}/api/oauth/state"): FakeResponse(200, '{"data":{"flow_token":"f"}}'),
                ("GET", "https://connect.linux.do/oauth2/authorize"): FakeResponse(
                    302, "", headers={"location": f"{BASE}/api/oauth/linuxdo?code=C&state=f"}
                ),
                ("GET", f"{BASE}/api/oauth/linuxdo"): FakeResponse(
                    200, "{}", cookies={"session": "new-sess"}
                ),
                ("GET", f"{BASE}/api/user/self"): FakeResponse(200, self_payload(0)),
                ("POST", f"{BASE}/api/user/checkin"): FakeResponse(200, '{"success":true}'),
            }
        )
        site = make_site(
            credentials=[{"id": "ld", "type": "linuxdo_oauth", "value": "_t=ld"}],
            checkin={"protocol": "oauth"},
        )
        adapter = create_adapter(site, session)
        await adapter.check_in()

        authorize = [c for c in session.calls if "connect.linux.do" in c["url"]][0]
        self.assertNotIn("redirect_uri", authorize["params"])
        self.assertEqual(authorize["params"]["response_type"], "code")
        self.assertEqual(adapter.writeback.oauth_sessions["ld"], "session=new-sess")

    async def test_no_provider_sends_a_redirect_uri(self) -> None:
        """Both providers reject a redirect_uri that misses the registration.

        connect.linux.do answers a guessed one with a flat 403, so the authorize
        leg has to send exactly what the station's own login page sends.
        """
        session = FakeSession(
            self._github_routes({("GET", f"{BASE}/api/user/self"): FakeResponse(200, self_payload(0))})
        )
        site = make_site(
            credentials=[{"id": "gh", "type": "github_oauth", "value": "user_session=gh"}],
            checkin={"protocol": "oauth"},
        )
        await create_adapter(site, session).check_in()
        authorize = [c for c in session.calls if "github.com" in c["url"]][0]
        self.assertNotIn("redirect_uri", authorize["params"])


class LoginAsCheckInTests(unittest.IsolatedAsyncioTestCase):
    """Stations that disabled their check-in endpoint credit the bonus on login.

    For these the OAuth login *is* the signing action, so it has to run on every
    check-in — reusing a stored session would silently do nothing while still
    reporting success.
    """

    @staticmethod
    def _routes(self_responses) -> dict:
        return {
            ("GET", f"{BASE}/api/status"): FakeResponse(
                200, '{"data":{"github_oauth":true,"github_client_id":"cid"}}'
            ),
            ("POST", f"{BASE}/api/oauth/state"): FakeResponse(200, '{"data":{"flow_token":"f"}}'),
            ("GET", "https://github.com/login/oauth/authorize"): FakeResponse(
                302, "", headers={"location": f"{BASE}/cb?code=C&state=f"}
            ),
            ("GET", f"{BASE}/api/oauth/github"): FakeResponse(
                200, "{}", cookies={"session": "fresh"}
            ),
            ("GET", f"{BASE}/api/user/self"): self_responses,
        }

    @staticmethod
    def _site(**overrides) -> dict:
        credential = {
            "id": "gh",
            "type": "github_oauth",
            "value": "user_session=gh",
            "session_cookie": "session=yesterday",
        }
        credential.update(overrides.pop("credential", {}))
        return make_site(credentials=[credential], checkin={"protocol": "oauth"}, **overrides)

    async def test_a_stored_session_does_not_skip_the_login(self) -> None:
        """The whole point: yesterday's cookie must not stand in for today's login."""
        session = FakeSession(
            self._routes([FakeResponse(200, self_payload(0)), FakeResponse(200, self_payload(500000))])
        )
        adapter = create_adapter(self._site(), session)
        await adapter.check_in()
        self.assertEqual(session.count_to("/api/oauth/github"), 1)

    async def test_the_login_counts_as_the_check_in(self) -> None:
        session = FakeSession(
            self._routes([FakeResponse(200, self_payload(0)), FakeResponse(200, self_payload(0))])
        )
        result = await create_adapter(self._site(), session).check_in()
        self.assertTrue(result.success)
        self.assertIn("登录即签到", result.message)

    async def test_a_bonus_credited_on_login_is_reported(self) -> None:
        session = FakeSession(
            self._routes([FakeResponse(200, self_payload(0)), FakeResponse(200, self_payload(12500000))])
        )
        result = await create_adapter(self._site(), session).check_in()
        self.assertTrue(result.success)
        self.assertEqual(result.gained_quota, 25.0)
        self.assertIn("25.0", result.message)

    async def test_the_opening_balance_read_does_not_log_in(self) -> None:
        """The opening read reuses the old cookie; only the check-in signs in."""
        session = FakeSession(
            self._routes([FakeResponse(200, self_payload(0)), FakeResponse(200, self_payload(0))])
        )
        await create_adapter(self._site(), session).check_in()
        opening_read = session.calls_to("/api/user/self")[0]
        self.assertEqual(opening_read["headers"]["Cookie"], "session=yesterday")
        # No login had happened by the time that read was issued.
        self.assertEqual(session.urls().index(f"{BASE}/api/user/self"), 0)

    async def test_an_expired_stored_cookie_still_logs_in_only_once(self) -> None:
        """A 401 on the opening read refreshes the session; the check-in reuses it."""
        session = FakeSession(
            self._routes(
                [
                    FakeResponse(401, '{"success":false}'),  # yesterday's cookie is dead
                    FakeResponse(200, self_payload(0)),      # retried after the login
                    FakeResponse(200, self_payload(500000)),  # closing read
                ]
            )
        )
        result = await create_adapter(self._site(), session).check_in()
        self.assertTrue(result.success)
        self.assertEqual(session.count_to("/api/oauth/github"), 1)

    async def test_exactly_one_login_per_run(self) -> None:
        """Two balance reads bracket the check-in; neither may re-login."""
        session = FakeSession(
            self._routes([FakeResponse(200, self_payload(0)), FakeResponse(200, self_payload(0))])
        )
        await create_adapter(self._site(), session).check_in()
        self.assertEqual(session.count_to("/api/status"), 1)
        self.assertEqual(session.count_to("/api/oauth/github"), 1)

    async def test_the_fresh_session_is_written_back(self) -> None:
        session = FakeSession(
            self._routes([FakeResponse(200, self_payload(0)), FakeResponse(200, self_payload(0))])
        )
        adapter = create_adapter(self._site(), session)
        await adapter.check_in()
        self.assertEqual(adapter.writeback.oauth_sessions["gh"], "session=fresh")

    async def test_a_failed_login_is_not_reported_as_a_check_in(self) -> None:
        routes = self._routes([FakeResponse(200, self_payload(0))])
        routes[("GET", "https://github.com/login/oauth/authorize")] = FakeResponse(
            302, "", headers={"location": "https://github.com/login"}
        )
        result = await create_adapter(self._site(), FakeSession(routes)).check_in()
        self.assertFalse(result.success)
        self.assertNotIn("登录即签到", result.message)

    async def test_no_checkin_endpoint_is_contacted(self) -> None:
        """The login already signed in, so probing endpoints afterwards would
        only add 404/401 noise to the trace."""
        session = FakeSession(
            self._routes(
                [FakeResponse(200, self_payload(0)), FakeResponse(200, self_payload(0))],
            )
        )
        # Even a *working* endpoint must be left alone under this protocol.
        session.routes[("POST", f"{BASE}/api/user/checkin")] = FakeResponse(
            200, '{"success":true,"message":"签到成功"}'
        )
        result = await create_adapter(self._site(), session).check_in()
        self.assertTrue(result.success)
        self.assertEqual(session.count_to("/api/user/checkin"), 0)

    async def test_the_fresh_cookie_is_used_for_the_closing_balance(self) -> None:
        """The new session must be reused rather than logging in twice."""
        session = FakeSession(
            self._routes([FakeResponse(200, self_payload(0)), FakeResponse(200, self_payload(0))])
        )
        await create_adapter(self._site(), session).check_in()
        closing_read = session.calls_to("/api/user/self")[-1]
        self.assertEqual(closing_read["headers"]["Cookie"], "session=fresh")
        self.assertEqual(session.count_to("/api/oauth/github"), 1)

    async def test_balance_reads_alone_reuse_the_stored_session(self) -> None:
        """Only the check-in forces a login; a plain balance read must not."""
        session = FakeSession(self._routes(FakeResponse(200, self_payload(0))))
        quota, error = await create_adapter(self._site(), session).query_balance()
        self.assertEqual((quota, error), (0.0, ""))
        self.assertEqual(session.count_to("/api/oauth/github"), 0)
        self.assertEqual(session.calls_to("/api/user/self")[0]["headers"]["Cookie"], "session=yesterday")

    async def test_test_connection_does_not_log_in(self) -> None:
        """Testing a site must never consume the day's sign-in."""
        session = FakeSession(self._routes(FakeResponse(200, self_payload(0))))
        await create_adapter(self._site(), session).test_connection()
        self.assertEqual(session.count_to("/api/oauth/github"), 0)

    async def test_a_first_run_with_no_stored_session_still_works(self) -> None:
        session = FakeSession(
            self._routes([FakeResponse(200, self_payload(0)), FakeResponse(200, self_payload(0))])
        )
        site = self._site(credential={"session_cookie": ""})
        result = await create_adapter(site, session).check_in()
        self.assertTrue(result.success)
        self.assertEqual(session.count_to("/api/oauth/github"), 1)

    async def test_generic_sites_also_treat_the_login_as_the_check_in(self) -> None:
        routes = self._routes(FakeResponse(404, "nope"))
        routes[("GET", BASE)] = FakeResponse(404, "not found")
        site = self._site(type="generic_rest")
        session = FakeSession(routes)
        result = await create_adapter(site, session).check_in()
        self.assertTrue(result.success)
        self.assertIn("登录即签到", result.message)
        # Consistent with New-API: nothing is requested after the login.
        self.assertEqual(session.count_to(BASE), 0)


class _StrictNewApiSession(FakeSession):
    """Answers ``/api/user/self`` the way released New-API does for a session
    cookie: 401 unless ``New-Api-User`` names the logged-in account."""

    USER_ID = "2259"

    def __init__(self, routes: dict, quotas: list[int]) -> None:
        super().__init__(routes)
        self.quotas = list(quotas)

    async def request(self, method, url, **kwargs):
        if not url.endswith("/api/user/self"):
            return await super().request(method, url, **kwargs)
        self.calls.append({"method": method, "url": url, **kwargs})
        sent = [v for k, v in (kwargs.get("headers") or {}).items() if k.lower() == NEW_API_USER_HEADER]
        if sent != [self.USER_ID]:
            return FakeResponse(401, '{"success":false,"message":"无权进行此操作，未提供 New-Api-User"}')
        return FakeResponse(200, self_payload(self.quotas.pop(0), int(self.USER_ID)))


class OAuthNewApiUserTests(unittest.IsolatedAsyncioTestCase):
    """An OAuth session cookie reads the balance only with New-Api-User beside it,
    and the id can only be learned from the login response."""

    @staticmethod
    def _session(quotas: list[int]) -> _StrictNewApiSession:
        routes = LoginAsCheckInTests._routes(None)
        routes[("GET", f"{BASE}/api/oauth/github")] = FakeResponse(
            200, '{"success":true,"data":{"id":2259,"username":"u"}}', cookies={"session": "fresh"}
        )
        return _StrictNewApiSession(routes, quotas)

    async def test_a_login_check_in_reports_the_balance(self) -> None:
        """The reported bug: the check-in succeeded but the balance stayed unknown."""
        session = self._session([500000, 500000])
        result = await create_adapter(LoginAsCheckInTests._site(), session).check_in()
        self.assertTrue(result.success)
        self.assertEqual(result.total_quota, 1.0)
        self.assertEqual(session.count_to("/api/oauth/github"), 1)

    async def test_the_id_is_written_back_for_later_runs(self) -> None:
        adapter = create_adapter(LoginAsCheckInTests._site(), self._session([0, 0]))
        await adapter.check_in()
        self.assertEqual(find_header(adapter.writeback.balance_headers, NEW_API_USER_HEADER), "2259")

    async def test_a_stored_id_reads_the_balance_without_logging_in(self) -> None:
        session = self._session([1500000])
        site = LoginAsCheckInTests._site(balance={"headers": [{"key": NEW_API_USER_HEADER, "value": "2259"}]})
        quota, error = await create_adapter(site, session).query_balance()
        self.assertEqual((quota, error), (3.0, ""))
        self.assertEqual(session.count_to("/api/oauth/github"), 0)

    async def test_the_later_run_measures_the_login_bonus(self) -> None:
        """With the id stored, the opening read precedes the login, so the gain shows."""
        session = self._session([500000, 1500000])
        site = LoginAsCheckInTests._site(balance={"headers": [{"key": NEW_API_USER_HEADER, "value": "2259"}]})
        result = await create_adapter(site, session).check_in()
        self.assertEqual((result.total_quota, result.gained_quota), (3.0, 2.0))

    async def test_a_stale_id_is_replaced_by_the_login(self) -> None:
        """A header from another account would only ever fail as a mismatch."""
        session = self._session([0, 0])
        site = LoginAsCheckInTests._site(balance={"headers": [{"key": "New-Api-User", "value": "1"}]})
        adapter = create_adapter(site, session)
        result = await adapter.check_in()
        self.assertEqual(result.error_detail, "")
        self.assertEqual(find_header(adapter.writeback.balance_headers, NEW_API_USER_HEADER), "2259")
        self.assertEqual(len(adapter.writeback.balance_headers), 1)

    async def test_a_first_run_without_a_session_reads_both_balances(self) -> None:
        session = self._session([500000, 1000000])
        site = LoginAsCheckInTests._site(credential={"session_cookie": ""})
        result = await create_adapter(site, session).check_in()
        self.assertEqual((result.total_quota, result.gained_quota), (2.0, 1.0))
        self.assertEqual(session.count_to("/api/oauth/github"), 1)

    async def test_generic_sites_get_no_header(self) -> None:
        session = self._session([])
        adapter = create_adapter(LoginAsCheckInTests._site(type="generic_rest"), session)
        await adapter.check_in()
        self.assertIsNone(adapter.writeback.balance_headers)


class _TokenNewApiSession(FakeSession):
    """Behaves like New-API ``main``: the dashboard reads only a bearer token,
    and ``/api/user/auth/refresh`` trades the refresh cookie for a new token,
    rotating the cookie and revoking the session if a retired one comes back."""

    def __init__(self, quotas: list[int], refresh: str = "sid.r1", valid_token: str = "") -> None:
        routes = LoginAsCheckInTests._routes(None)
        super().__init__(routes)
        self.quotas = list(quotas)
        self.refresh = refresh
        self.valid_token = valid_token
        self.issued = 0
        self.revoked = False

    def _issue(self) -> FakeResponse:
        self.issued += 1
        self.valid_token = f"at-{self.issued}"
        self.refresh = f"sid.r{self.issued + 1}"
        body = json.dumps({"success": True, "data": {
            "access_token": self.valid_token, "token_type": "Bearer",
            "access_expires_at": 4102444800, "user": {"id": 2259}}})
        return FakeResponse(200, body, cookies={"new_api_refresh": self.refresh, "new_api_has_session": "1"})

    async def request(self, method, url, **kwargs):
        headers = kwargs.get("headers") or {}
        if url.endswith("/api/oauth/github"):
            self.calls.append({"method": method, "url": url, **kwargs})
            self.revoked = False
            return self._issue()
        if url.endswith("/api/user/auth/refresh"):
            self.calls.append({"method": method, "url": url, **kwargs})
            if self.revoked or f"new_api_refresh={self.refresh}" not in headers.get("Cookie", ""):
                self.revoked = True
                return FakeResponse(401, '{"success":false,"code":"AUTH_SESSION_REVOKED"}')
            return self._issue()
        if url.endswith("/api/user/self"):
            self.calls.append({"method": method, "url": url, **kwargs})
            if not self.valid_token or headers.get("Authorization") != f"Bearer {self.valid_token}":
                return FakeResponse(401, '{"success":false,"code":"AUTH_UNAUTHORIZED"}')
            return FakeResponse(200, self_payload(self.quotas.pop(0), 2259))
        return await super().request(method, url, **kwargs)


class OAuthTokenSessionTests(unittest.IsolatedAsyncioTestCase):
    """Stations that authenticate with an access token plus a refresh cookie."""

    @staticmethod
    def _site(**credential) -> dict:
        return LoginAsCheckInTests._site(credential={
            "session_cookie": "new_api_refresh=sid.r1; new_api_has_session=1",
            "access_token": "at-old", "access_expires_at": 1_000_000_000,  # long expired
            **credential,
        })

    async def test_a_login_writes_back_both_tokens(self) -> None:
        session = _TokenNewApiSession([500000, 500000])
        adapter = create_adapter(LoginAsCheckInTests._site(credential={"session_cookie": ""}), session)
        result = await adapter.check_in()
        self.assertEqual(result.total_quota, 1.0)
        self.assertEqual(adapter.writeback.oauth_tokens["gh"], ("at-1", 4102444800))
        self.assertIn("new_api_refresh=sid.r2", adapter.writeback.oauth_sessions["gh"])

    async def test_an_expired_token_is_refreshed_instead_of_logging_in(self) -> None:
        session = _TokenNewApiSession([1500000])
        adapter = create_adapter(self._site(), session)
        quota, error = await adapter.query_balance()
        self.assertEqual((quota, error), (3.0, ""))
        self.assertEqual(session.count_to("/api/oauth/github"), 0)
        self.assertEqual(session.count_to("/api/user/auth/refresh"), 1)

    async def test_the_rotated_refresh_cookie_is_written_back(self) -> None:
        """The presented one is retired; replaying it would revoke the session."""
        session = _TokenNewApiSession([0])
        adapter = create_adapter(self._site(), session)
        await adapter.query_balance()
        self.assertEqual(session.count_to("/api/oauth/github"), 0)
        self.assertIn("new_api_refresh=sid.r2", adapter.writeback.oauth_sessions["gh"])
        self.assertEqual(adapter.writeback.oauth_tokens["gh"][0], "at-1")

    async def test_a_valid_token_is_used_as_is(self) -> None:
        session = _TokenNewApiSession([0], valid_token="at-live")
        site = self._site(access_token="at-live", access_expires_at=4102444800)
        quota, error = await create_adapter(site, session).query_balance()
        self.assertEqual(error, "")
        self.assertEqual(session.count_to("/api/user/auth/refresh"), 0)

    async def test_the_login_check_in_measures_the_bonus(self) -> None:
        """The refresh lets the opening read happen before the login."""
        session = _TokenNewApiSession([500000, 1500000])
        result = await create_adapter(self._site(), session).check_in()
        self.assertEqual((result.total_quota, result.gained_quota), (3.0, 2.0))
        sequence = [url.rsplit("/", 1)[-1] for url in session.urls()
                    if url.endswith(("/refresh", "/api/oauth/github", "/self"))]
        self.assertEqual(sequence, ["refresh", "self", "github", "self"])

    async def test_a_revoked_session_falls_back_to_a_login(self) -> None:
        session = _TokenNewApiSession([0], refresh="sid.other")
        adapter = create_adapter(self._site(), session)
        quota, error = await adapter.query_balance()
        self.assertEqual(error, "")
        self.assertEqual(session.count_to("/api/user/auth/refresh"), 1)
        self.assertEqual(session.count_to("/api/oauth/github"), 1)

    async def test_a_rejected_token_of_unknown_expiry_refreshes_first(self) -> None:
        session = _TokenNewApiSession([0])
        site = self._site(access_expires_at=0)
        quota, error = await create_adapter(site, session).query_balance()
        self.assertEqual(error, "")
        self.assertEqual(session.count_to("/api/user/auth/refresh"), 1)
        self.assertEqual(session.count_to("/api/oauth/github"), 0)

    async def test_the_opening_read_refreshes_even_where_login_is_not_allowed(self) -> None:
        session = _TokenNewApiSession([0])
        quota, error = await create_adapter(self._site(), session).query_balance(allow_login=False)
        self.assertEqual(error, "")
        self.assertEqual(session.count_to("/api/oauth/github"), 0)

    async def test_a_legacy_login_clears_a_stale_token(self) -> None:
        """A cookie-session station issues no token; an old one must not linger."""
        session = OAuthNewApiUserTests._session([0, 0])
        adapter = create_adapter(LoginAsCheckInTests._site(credential={"access_token": "at-stale"}), session)
        await adapter.check_in()
        self.assertEqual(adapter.writeback.oauth_tokens["gh"], ("", 0))
        self.assertNotIn("Authorization", session.calls_to("/api/user/self")[-1]["headers"])


class MldsaRequestTests(unittest.IsolatedAsyncioTestCase):
    """The global ML-DSA option covers every request of every site."""

    MLDSA = RequestOptions(tls_mldsa=True)

    async def test_check_in_and_its_balance_query_carry_it(self) -> None:
        session = FakeSession({
            ("GET", f"{BASE}/api/user/self"): FakeResponse(200, self_payload(0)),
            ("POST", f"{BASE}/api/user/checkin"): FakeResponse(200, '{"success":true,"message":"ok"}'),
        })
        result = await create_adapter(make_site(), session, options=self.MLDSA).check_in()
        self.assertTrue(result.success, result.message)
        self.assertTrue(session.calls_to("/api/user/checkin") and session.calls_to("/api/user/self"))
        self.assertTrue(all(carries_mldsa(call) for call in session.calls))

    async def test_a_new_api_user_probe_carries_it(self) -> None:
        session = FakeSession({
            ("GET", f"{BASE}/api/quota"): FakeResponse(200, '{"data":{"quota":500000}}'),
            ("GET", f"{BASE}/api/user/self"): FakeResponse(200, self_payload(0)),
        })
        site = make_site(balance={"path": "/api/quota"})
        quota, error = await create_adapter(site, session, options=self.MLDSA).query_balance()
        self.assertEqual((quota, error), (1.0, ""))
        self.assertEqual(len(session.calls), 2)
        self.assertTrue(all(carries_mldsa(call) for call in session.calls))

    async def test_nothing_is_altered_by_default(self) -> None:
        session = FakeSession({("GET", f"{BASE}/api/user/self"): FakeResponse(200, self_payload(0))})
        await create_adapter(make_site(), session).query_balance()
        self.assertIsNone(session.calls[0]["extra_fp"])

    async def test_every_leg_of_an_oauth_login_carries_it(self) -> None:
        session = FakeSession(OAuthCheckInTests._github_routes({
            ("GET", f"{BASE}/api/user/self"): FakeResponse(200, self_payload(0)),
        }))
        site = make_site(
            credentials=[{"id": "gh", "type": "github_oauth", "value": "user_session=gh"}],
            checkin={"protocol": "oauth"},
        )
        result = await create_adapter(site, session, options=self.MLDSA).check_in()
        self.assertTrue(result.success, result.message)
        login = [call for call in session.calls
                 if "/oauth" in call["url"] or call["url"].endswith("/api/status")]
        self.assertEqual(len(login), 5)
        self.assertTrue(all(carries_mldsa(call) for call in session.calls))

    def test_per_site_flags_of_earlier_versions_are_dropped(self) -> None:
        site = make_site(
            credentials=[{"id": "gh", "type": "github_oauth", "value": "v", "tls_mldsa": True}],
            checkin={"tls_mldsa": True, "solve_acw_sc_v2": True},
        )
        adapter = create_adapter(site, FakeSession({}))
        self.assertNotIn("tls_mldsa", adapter.checkin)
        self.assertNotIn("solve_acw_sc_v2", adapter.checkin)
        self.assertNotIn("tls_mldsa", adapter.credentials[0])


class PowCheckInTests(unittest.IsolatedAsyncioTestCase):
    """Sites with the Vs PoW switch on solve vsllm.cc's challenge before a check-in."""

    @staticmethod
    def _routes(challenge, checkin=None) -> dict:
        return {
            ("GET", f"{BASE}/api/user/self"): FakeResponse(200, self_payload(0)),
            ("GET", POW_URL): challenge,
            ("POST", f"{BASE}/api/user/checkin"): checkin or FakeResponse(200, CHECKED_IN),
        }

    @staticmethod
    def _proofs(session: FakeSession) -> list[tuple]:
        """What each check-in request presented."""
        return [pow_proof(call) for call in session.calls_to("/api/user/checkin")]

    @staticmethod
    def _site(**overrides) -> dict:
        return make_site(vs_pow=True, **overrides)

    async def test_off_by_default_the_challenge_is_never_requested(self) -> None:
        """Explicit over implicit: a site that never said it is vsllm.cc gets nothing extra."""
        session = FakeSession(self._routes(FakeResponse(200, pow_challenge())))
        result = await create_adapter(make_site(), session).check_in()
        self.assertTrue(result.success, result.message)
        self.assertNotIn(POW_URL, session.urls())
        self.assertEqual(self._proofs(session), [(None, None)])

    async def test_off_a_refusal_points_at_the_switch(self) -> None:
        session = FakeSession(self._routes(FakeResponse(200, pow_challenge()), FakeResponse(200, POW_REFUSED)))
        result = await create_adapter(make_site(), session).check_in()
        self.assertFalse(result.success)
        self.assertFalse(result.expired)
        self.assertIn("「求解 Vs PoW」", result.message)
        self.assertEqual(session.count_to("/api/user/checkin"), 1)

    async def test_the_solved_challenge_goes_with_the_check_in(self) -> None:
        session = FakeSession(self._routes(FakeResponse(200, pow_challenge())))
        result = await create_adapter(self._site(), session).check_in()
        self.assertTrue(result.success, result.message)
        self.assertEqual(self._proofs(session), [("tok-1", POW_NONCE)])
        # The token names the account, so the station refuses an anonymous one.
        challenge = next(call for call in session.calls if call["url"] == POW_URL)
        self.assertEqual(challenge["headers"]["Authorization"], "Bearer sk-a")
        for call in session.calls_to("/api/user/self"):
            self.assertEqual(pow_proof(call), (None, None))

    async def test_the_trace_names_the_solve_without_the_token(self) -> None:
        session = FakeSession(self._routes(FakeResponse(200, pow_challenge())))
        result = await create_adapter(self._site(), session).check_in()
        self.assertEqual(
            [attempt["step"] for attempt in result.attempts],
            ["查询余额", "PoW 求解", "签到", "查询最终余额"],
        )
        self.assertNotIn("tok-1", json.dumps(result.attempts, ensure_ascii=False))

    async def test_no_usable_challenge_lets_the_check_in_go_ahead(self) -> None:
        """The switch is on, so a station that hands out nothing usable is worth showing."""
        for challenge in (FakeResponse(200, '{"message":"未登录","success":false}'), ConnectionError("reset")):
            with self.subTest(challenge=challenge):
                session = FakeSession(self._routes(challenge))
                result = await create_adapter(self._site(), session).check_in()
                self.assertTrue(result.success, result.message)
                self.assertEqual(self._proofs(session), [(None, None)])
                self.assertIn("获取 PoW 题目", [attempt["step"] for attempt in result.attempts])

    async def test_a_refused_proof_is_retried_on_a_new_challenge(self) -> None:
        session = FakeSession(
            self._routes(
                [FakeResponse(200, pow_challenge("tok-1")), FakeResponse(200, pow_challenge("tok-2"))],
                [FakeResponse(200, POW_REFUSED), FakeResponse(200, CHECKED_IN)],
            )
        )
        result = await create_adapter(self._site(), session).check_in()
        self.assertTrue(result.success, result.message)
        self.assertEqual(self._proofs(session), [("tok-1", POW_NONCE), ("tok-2", POW_NONCE)])

    async def test_repeated_refusals_stop_without_blaming_the_credential(self) -> None:
        session = FakeSession(
            self._routes(FakeResponse(200, pow_challenge()), FakeResponse(200, POW_REFUSED))
        )
        result = await create_adapter(self._site(), session).check_in()
        self.assertFalse(result.success)
        self.assertFalse(result.expired)
        self.assertIn("拒绝了 PoW 解答", result.message)
        self.assertIn("并非凭据失效", result.message)
        self.assertEqual(session.count_to("/api/user/checkin"), POW_MAX_ATTEMPTS)

    async def test_a_refusal_without_a_challenge_does_not_clear_the_credential(self) -> None:
        """No challenge may well mean a dead session, so the run must not deny it."""
        session = FakeSession(
            self._routes(
                FakeResponse(200, '{"message":"未登录","success":false}'),
                FakeResponse(200, POW_REFUSED),
            )
        )
        site = self._site(credentials=[{"id": "c1", "type": "cookie", "value": "session=s"}])
        result = await create_adapter(site, session).check_in()
        self.assertFalse(result.success)
        self.assertFalse(result.expired)
        self.assertIn("未取到可用的题目", result.message)
        self.assertNotIn("并非凭据失效", result.message)
        # Sent bare once: without a challenge a resend would only be refused again.
        self.assertEqual(session.count_to("/api/user/checkin"), 1)

    async def test_a_token_without_a_challenge_points_at_another_credential(self) -> None:
        """vsllm.cc hands check-in challenges to session cookies only, never to a token."""
        session = FakeSession(
            self._routes(
                FakeResponse(200, '{"message":"未登录","success":false}'),
                FakeResponse(200, POW_REFUSED),
            )
        )
        result = await create_adapter(self._site(), session).check_in()
        self.assertFalse(result.success)
        self.assertFalse(result.expired)
        self.assertIn("请改用 Cookie 或 OAuth 凭据", result.message)
        self.assertEqual(session.count_to("/api/user/checkin"), 1)

    async def test_a_challenge_too_hard_to_solve_never_reaches_the_check_in(self) -> None:
        session = FakeSession(self._routes(FakeResponse(200, pow_challenge())))
        with mock.patch.object(PowChallenge, "solve", side_effect=PowTimeout):
            result = await create_adapter(self._site(), session).check_in()
        self.assertFalse(result.success)
        self.assertFalse(result.expired)
        self.assertIn("难度 18", result.message)
        self.assertEqual(session.count_to("/api/user/checkin"), 0)

    async def test_a_relogin_resends_the_proof(self) -> None:
        routes = OAuthCheckInTests._github_routes(
            self._routes(
                FakeResponse(200, pow_challenge()),
                [FakeResponse(401, '{"success":false}'), FakeResponse(200, CHECKED_IN)],
            )
        )
        site = self._site(
            credentials=[
                {
                    "id": "gh",
                    "type": "github_oauth",
                    "value": "user_session=gh",
                    "session_cookie": "session=stale",
                }
            ]
        )
        session = FakeSession(routes)
        result = await create_adapter(site, session).check_in()
        self.assertTrue(result.success, result.message)
        self.assertEqual(self._proofs(session), [("tok-1", POW_NONCE)] * 2)

    async def test_a_browser_retry_carries_the_proof(self) -> None:
        """vsllm.cc challenges this very path, so the proof has to reach the browser."""
        seen = []

        class Recording:
            async def resolve(self, *, response, record=None, browser_request=None):
                seen.append(browser_request)
                return Resolution(response)

        session = FakeSession(self._routes(FakeResponse(200, pow_challenge())))
        await create_adapter(self._site(), session, None, Recording()).check_in()
        request = next(item for item in seen if item.method == "POST")
        self.assertEqual(pow_proof({"headers": request.headers}), ("tok-1", POW_NONCE))

    async def test_the_login_presents_its_own_proof_for_the_state(self) -> None:
        """vsllm.cc guards /api/oauth/state with a challenge of its own purpose."""
        oauth_pow = f"{BASE}/api/pow/challenge?purpose=oauth"
        routes = LoginAsCheckInTests._routes(
            [FakeResponse(200, self_payload(0)), FakeResponse(200, self_payload(0))]
        )
        routes[("GET", oauth_pow)] = FakeResponse(200, pow_challenge("tok-oauth"))
        session = FakeSession(routes)
        result = await create_adapter(LoginAsCheckInTests._site(vs_pow=True), session).check_in()
        self.assertTrue(result.success, result.message)
        self.assertNotIn(POW_URL, session.urls())
        self.assertEqual(pow_proof(session.calls_to("/api/oauth/state")[0]), ("tok-oauth", POW_NONCE))
        # Asked for anonymously, as the state itself is.
        challenge = next(call for call in session.calls if call["url"] == oauth_pow)
        self.assertNotIn("Cookie", challenge["headers"])

    async def test_off_a_login_never_asks_for_a_challenge(self) -> None:
        session = FakeSession(
            LoginAsCheckInTests._routes(
                [FakeResponse(200, self_payload(0)), FakeResponse(200, self_payload(0))]
            )
        )
        await create_adapter(LoginAsCheckInTests._site(), session).check_in()
        self.assertFalse(any("/api/pow/challenge" in url for url in session.urls()))

    async def test_a_login_refused_over_its_proof_does_not_blame_the_credential(self) -> None:
        """The state is refused before the third-party cookie is ever sent."""
        refused = {("POST", f"{BASE}/api/oauth/state"): FakeResponse(200, POW_REFUSED)}
        for vs_pow in (False, True):
            with self.subTest(vs_pow=vs_pow):
                routes = LoginAsCheckInTests._routes([FakeResponse(200, self_payload(0))] * 2)
                routes.update(refused)
                routes[("GET", f"{BASE}/api/pow/challenge?purpose=oauth")] = FakeResponse(200, pow_challenge())
                result = await create_adapter(LoginAsCheckInTests._site(vs_pow=vs_pow), FakeSession(routes)).check_in()
                self.assertFalse(result.success)
                self.assertFalse(result.expired)
                self.assertIn("并非凭据失效", result.message)

    async def test_a_relogin_refused_over_its_proof_does_not_blame_the_credential(self) -> None:
        """The same through the re-login a stale session sets off."""
        for vs_pow in (False, True):
            with self.subTest(vs_pow=vs_pow):
                oauth_pow = f"{BASE}/api/pow/challenge?purpose=oauth"
                routes = OAuthCheckInTests._github_routes(
                    {
                        ("GET", f"{BASE}/api/user/self"): FakeResponse(
                            401, '{"success":false}'
                        ),
                        ("GET", f"{BASE}/api/oauth/state"): FakeResponse(
                            200, POW_REFUSED
                        ),
                        ("GET", oauth_pow): FakeResponse(
                            200, pow_challenge("tok-oauth")
                        ),
                    }
                )
                site = make_site(
                    vs_pow=vs_pow,
                    credentials=[
                        {
                            "id": "gh",
                            "type": "github_oauth",
                            "value": "user_session=gh",
                            "session_cookie": "session=stale",
                        }
                    ],
                )
                session = FakeSession(routes)
                result = await create_adapter(site, session).test_connection()
                self.assertFalse(result.success)
                self.assertFalse(result.expired)
                self.assertIn("并非凭据失效", result.message)
                state_calls = session.calls_to("/api/oauth/state")
                self.assertTrue(state_calls)
                expected = ("tok-oauth", POW_NONCE) if vs_pow else (None, None)
                self.assertTrue(
                    all(pow_proof(call) == expected for call in state_calls)
                )
                self.assertEqual(
                    session.count_to("/api/pow/challenge?purpose=oauth"),
                    len(state_calls) if vs_pow else 0,
                )

    async def test_an_inconclusive_login_does_not_hide_a_later_expired_cookie(
        self,
    ) -> None:
        """A balance login failure must not suppress the check-in's cookie error."""
        for vs_pow in (False, True):
            for checkin_credential in ("balance", "checkin"):
                with self.subTest(vs_pow=vs_pow, credential=checkin_credential):
                    refusals = POW_MAX_ATTEMPTS if vs_pow else 1
                    states = [FakeResponse(200, POW_REFUSED)] * refusals + [
                        FakeResponse(404, "")
                    ]
                    routes = OAuthCheckInTests._github_routes(
                        {
                            ("GET", f"{BASE}/api/oauth/state"): states,
                            (
                                "GET",
                                f"{BASE}/api/pow/challenge?purpose=oauth",
                            ): FakeResponse(200, pow_challenge()),
                            (
                                "GET",
                                "https://github.com/login/oauth/authorize",
                            ): FakeResponse(
                                302,
                                "",
                                headers={"location": "https://github.com/login"},
                            ),
                        }
                    )
                    site = make_site(
                        vs_pow=vs_pow,
                        credentials=[
                            {
                                "id": name,
                                "type": "github_oauth",
                                "value": f"user_session={name}",
                            }
                            for name in ("balance", "checkin")
                        ],
                        balance={"credential_id": "balance"},
                        checkin={"credential_id": checkin_credential},
                    )
                    session = FakeSession(routes)
                    result = await create_adapter(site, session).check_in()
                    self.assertFalse(result.success)
                    self.assertTrue(result.expired, result.message)
                    self.assertEqual(session.count_to("/login/oauth/authorize"), 1)

    async def test_a_login_with_a_dead_cookie_still_blames_it(self) -> None:
        routes = LoginAsCheckInTests._routes([FakeResponse(200, self_payload(0))] * 2)
        routes[("GET", "https://github.com/login/oauth/authorize")] = FakeResponse(
            302, "", headers={"location": "https://github.com/login"}
        )
        result = await create_adapter(LoginAsCheckInTests._site(vs_pow=True), FakeSession(routes)).check_in()
        self.assertFalse(result.success)
        self.assertTrue(result.expired)

    async def test_the_balance_never_solves(self) -> None:
        """The station asks for no proof on its balance route."""
        session = FakeSession({("GET", f"{BASE}/api/user/self"): FakeResponse(200, self_payload(1500000))})
        quota, error = await create_adapter(self._site(), session).query_balance()
        self.assertEqual((quota, error), (3.0, ""))
        self.assertEqual(session.urls(), [f"{BASE}/api/user/self"])


class AdapterFactoryTests(unittest.TestCase):
    def test_new_api_types_select_the_new_api_adapter(self) -> None:
        for site_type in ("new-api", "one-api", "", None, "mystery"):
            adapter = create_adapter(make_site(type=site_type), FakeSession({}))
            self.assertIsInstance(adapter, NewApiAdapter, msg=site_type)

    def test_generic_types_select_the_generic_adapter(self) -> None:
        for site_type in ("generic_rest", "generic", "custom"):
            adapter = create_adapter(make_site(type=site_type), FakeSession({}))
            self.assertIsInstance(adapter, GenericRestAdapter, msg=site_type)

    def test_trailing_slash_is_trimmed_from_the_base_url(self) -> None:
        adapter = create_adapter(make_site(base_url=f"{BASE}/"), FakeSession({}))
        self.assertEqual(adapter.base_url, BASE)


class WritebackTests(unittest.TestCase):
    class _FakeDb:
        def __init__(self) -> None:
            self.headers: list[tuple] = []
            self.sessions: list[tuple] = []

        def update_action_headers(self, site_id, action, headers):
            self.headers.append((site_id, action, headers))
            return True

        def update_credential_session(self, site_id, credential_id, cookie):
            self.sessions.append((site_id, credential_id, cookie))
            return True

    def test_empty_writeback_is_a_no_op(self) -> None:
        db = self._FakeDb()
        persist_writeback(db, "s", SiteWriteback())
        persist_writeback(db, "s", None)
        self.assertEqual((db.headers, db.sessions), ([], []))

    def test_writes_both_actions_and_sessions(self) -> None:
        db = self._FakeDb()
        writeback = SiteWriteback(
            checkin_headers=[{"key": NEW_API_USER_HEADER, "value": "9"}],
            balance_headers=[],
            oauth_sessions={"gh": "session=a"},
        )
        persist_writeback(db, "s", writeback)
        self.assertEqual([entry[1] for entry in db.headers], [ACTION_CHECKIN, ACTION_BALANCE])
        self.assertEqual(db.sessions, [("s", "gh", "session=a")])

    def test_tokens_travel_with_their_session(self) -> None:
        calls = []

        class Db:
            def update_credential_session(self, *a): calls.append(a); return True

        persist_writeback(Db(), "s", SiteWriteback(
            oauth_sessions={"gh": "new_api_refresh=r"}, oauth_tokens={"gh": ("at", 123)},
        ))
        self.assertEqual(calls, [("s", "gh", "new_api_refresh=r", "at", 123)])

    def test_storage_errors_do_not_escape(self) -> None:
        """A locked vault must not turn a successful check-in into a crash."""

        class BrokenDb:
            def update_action_headers(self, *_):
                raise RuntimeError("locked")

            def update_credential_session(self, *_):
                raise RuntimeError("locked")

        writeback = SiteWriteback(checkin_headers=[], oauth_sessions={"gh": "s"})
        with self.assertLogs("astrbot", level="WARNING"):
            persist_writeback(BrokenDb(), "s", writeback)


class RequestTraceTests(unittest.IsolatedAsyncioTestCase):
    """The per-run request trace that makes a failure diagnosable."""

    async def test_a_successful_run_records_each_step(self) -> None:
        session = FakeSession(
            {
                ("GET", f"{BASE}/api/user/self"): [
                    FakeResponse(200, self_payload(500000)),
                    FakeResponse(200, self_payload(1500000)),
                ],
                ("POST", f"{BASE}/api/user/checkin"): FakeResponse(200, '{"success":true}'),
            }
        )
        result = await create_adapter(make_site(), session).check_in()
        steps = [attempt["step"] for attempt in result.attempts]
        self.assertIn("查询余额", steps)
        self.assertIn("签到", steps)
        self.assertTrue(all(attempt["status"] == 200 for attempt in result.attempts))

    async def test_success_leaves_error_detail_empty(self) -> None:
        session = FakeSession(
            {
                ("GET", f"{BASE}/api/user/self"): FakeResponse(200, self_payload(0)),
                ("POST", f"{BASE}/api/user/checkin"): FakeResponse(200, '{"success":true}'),
            }
        )
        result = await create_adapter(make_site(), session).check_in()
        self.assertTrue(result.success)
        self.assertEqual(result.error_detail, "")

    async def test_failure_fills_a_readable_error_detail(self) -> None:
        session = FakeSession({}, default=FakeResponse(401, '{"message":"unauthorized"}'))
        result = await create_adapter(make_site(), session).check_in()
        self.assertFalse(result.success)
        self.assertIn("HTTP 401", result.error_detail)
        self.assertIn("查询余额", result.error_detail)

    async def test_the_trace_travels_in_to_dict(self) -> None:
        """History stores the dict form, so the trace has to survive it."""
        session = FakeSession({}, default=FakeResponse(500, "boom"))
        result = await create_adapter(make_site(), session).check_in()
        payload = result.to_dict()
        self.assertIn("attempts", payload)
        self.assertIn("error_detail", payload)
        self.assertTrue(payload["attempts"])

    async def test_query_strings_are_stripped_from_traced_urls(self) -> None:
        """A URL could carry a token, so only scheme/host/path is recorded."""
        session = FakeSession(
            {("GET", f"{BASE}/me"): FakeResponse(200, '{"balance":1}')}
        )
        site = make_site(balance={"path": "/me?token=secret", "protocol": "get"})
        adapter = create_adapter(site, session)
        await adapter.query_balance()
        self.assertTrue(adapter.attempts)
        self.assertNotIn("secret", adapter.attempts[0]["url"])

    async def test_long_responses_are_truncated(self) -> None:
        session = FakeSession({("GET", f"{BASE}/api/user/self"): FakeResponse(500, "x" * 9000)})
        adapter = create_adapter(make_site(balance={"protocol": "get"}), session)
        await adapter.query_balance()
        attempt = adapter.attempts[0]
        self.assertIn("已截断", attempt["response"])
        self.assertEqual(attempt["response_length"], 9000)

    async def test_the_trace_is_bounded(self) -> None:
        adapter = create_adapter(make_site(), FakeSession({}))
        for _ in range(MAX_ATTEMPTS_PER_RUN + 10):
            adapter._record_attempt(step="s", method="GET", endpoint=f"{BASE}/x", status=200)
        self.assertEqual(len(adapter.attempts), MAX_ATTEMPTS_PER_RUN + 1)
        self.assertEqual(sum(1 for a in adapter.attempts if a.get("truncated")), 1)

    async def test_a_transport_error_is_traced(self) -> None:
        class BoomSession(FakeSession):
            async def request(self, method, url, **kwargs):
                raise ConnectionError("dns failure")

        adapter = create_adapter(make_site(balance={"protocol": "get"}), BoomSession({}))
        quota, error = await adapter.query_balance()
        self.assertEqual(quota, 0.0)
        self.assertIn("dns failure", error)
        self.assertIn("dns failure", adapter.attempts[0]["error"])


class CheckInMessageTests(unittest.TestCase):
    """Recognizing station messages without broad false positives."""

    def test_accepts_explicit_success(self) -> None:
        for message in ("签到成功", "今日已签到", "已经签到过了", "重复签到"):
            self.assertTrue(BaseCheckInAdapter._message_indicates_checkin(message), message)

    def test_accepts_english_already_checked_in(self) -> None:
        for message in (
            "Already checked in today",
            "already checked-in",
            "You have already signed in today",
            "Already checked in today. Do not repeat.",
        ):
            self.assertTrue(BaseCheckInAdapter._message_indicates_checkin(message), message)

    def test_rejects_negated_english_checkin_messages(self) -> None:
        for message in (
            "Not already checked in",
            "Not already checked-in today",
            "You have not already signed in today",
            "You haven't already checked in today",
            "You have never already checked in",
            "You have not been checked in; already checked in is false",
        ):
            with self.subTest(message=message):
                self.assertFalse(
                    BaseCheckInAdapter._message_indicates_checkin(message), message
                )

    def test_rejects_explicit_failure(self) -> None:
        for message in ("签到失败", "未签到", "未成功", "未触发签到"):
            self.assertFalse(BaseCheckInAdapter._message_indicates_checkin(message), message)

    def test_rejects_unrelated_text(self) -> None:
        for message in ("", "ok", "quota updated"):
            self.assertFalse(BaseCheckInAdapter._message_indicates_checkin(message), message)

    def test_extracts_a_message_from_json(self) -> None:
        self.assertEqual(
            BaseCheckInAdapter._response_message(None, '{"message":"额度不足"}'), "额度不足"
        )
        self.assertEqual(
            BaseCheckInAdapter._response_message({"msg": "ok"}), "ok"
        )
        self.assertEqual(
            BaseCheckInAdapter._response_message({"error": {"message": "bad token"}}), "bad token"
        )
        self.assertEqual(BaseCheckInAdapter._response_message(None, "plain text"), "")


if __name__ == "__main__":
    unittest.main()
