"""Unit tests for the relay-station OAuth login flow."""

from __future__ import annotations

import unittest
from unittest import mock

import tests  # noqa: F401
from curl_cffi.requests import Cookies
from core.cloudflare import CloudflareContext, CloudflareOptions
from core.oauth import (
    GITHUB_OAUTH,
    LINUXDO_OAUTH,
    PROVIDERS,
    OAuthLoginClient,
    _extract_flow_token,
    _extract_login_fields,
    _missing_cookies,
    _safe_location,
    get_provider,
    is_cloudflare_challenge,
    merge_rotated_cookies,
    parse_cookie_header,
)
from core.pow import PowChallenge, PowTimeout
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
GITHUB_AUTHORIZE = "https://github.com/login/oauth/authorize"
LINUXDO_AUTHORIZE = "https://connect.linux.do/oauth2/authorize"


def github_routes(overrides: dict | None = None) -> dict:
    """Build a happy-path Github route table."""
    routes = {
        ("GET", f"{BASE}/api/status"): FakeResponse(
            200, '{"data":{"github_oauth":true,"github_client_id":"cid-1"}}'
        ),
        ("GET", f"{BASE}/api/oauth/state"): FakeResponse(
            200, '{"success":true,"data":"flow-1"}', cookies={"session": "srv"}
        ),
        ("GET", GITHUB_AUTHORIZE): FakeResponse(
            302, "", headers={"location": f"{BASE}/oauth/github?code=CODE-1&state=flow-1"}
        ),
        ("GET", f"{BASE}/api/oauth/github"): FakeResponse(
            200, "{}", cookies={"session": "sess-1", "extra": "e"}
        ),
    }
    routes.update(overrides or {})
    return routes


def make_client(session: FakeSession, proxy: str | None = None) -> OAuthLoginClient:
    return OAuthLoginClient(session, BASE, "chrome131", proxy)


class ProviderTests(unittest.TestCase):
    def test_lookup_by_credential_type(self) -> None:
        self.assertEqual(get_provider(GITHUB_OAUTH).slug, "github")
        self.assertEqual(get_provider(LINUXDO_OAUTH).slug, "linuxdo")

    def test_unknown_type_returns_none(self) -> None:
        self.assertIsNone(get_provider("gitlab"))
        self.assertIsNone(get_provider(""))

    def test_no_provider_sends_a_redirect_uri(self) -> None:
        """Both providers infer the callback from the registered application.

        The station's own browser flow sends none, and a guessed one that does
        not match the registration is grounds for refusal.
        """
        for credential_type in (GITHUB_OAUTH, LINUXDO_OAUTH):
            params = PROVIDERS[credential_type].extra_authorize_params
            self.assertNotIn("redirect_uri", params)

    def test_authorize_params_match_the_station_browser_flow(self) -> None:
        self.assertEqual(
            PROVIDERS[GITHUB_OAUTH].extra_authorize_params, {"scope": "user:email"}
        )
        self.assertEqual(
            PROVIDERS[LINUXDO_OAUTH].extra_authorize_params, {"response_type": "code"}
        )

    def test_cookie_hints_name_the_provider_cookie(self) -> None:
        self.assertEqual(PROVIDERS[GITHUB_OAUTH].cookie_hint, "user_session")
        self.assertEqual(PROVIDERS[LINUXDO_OAUTH].cookie_hint, "_t")


class SuccessfulLoginTests(unittest.IsolatedAsyncioTestCase):
    async def test_returns_the_station_session_cookie(self) -> None:
        session = FakeSession(github_routes())
        result = await make_client(session).login(GITHUB_OAUTH, "user_session=abc")
        self.assertTrue(result.success)
        self.assertEqual(result.session_cookie, "session=sess-1; extra=e")

    async def test_returns_the_account_id_from_the_callback(self) -> None:
        """New-API needs it as New-Api-User beside the cookie; nothing else reveals it."""
        session = FakeSession(github_routes({
            ("GET", f"{BASE}/api/oauth/github"): FakeResponse(
                200, '{"success":true,"data":{"id":2259,"username":"u"}}', cookies={"session": "s"}
            ),
        }))
        result = await make_client(session).login(GITHUB_OAUTH, "user_session=abc")
        self.assertEqual(result.user_id, "2259")

    async def test_a_callback_without_an_id_leaves_it_empty(self) -> None:
        result = await make_client(FakeSession(github_routes())).login(GITHUB_OAUTH, "user_session=abc")
        self.assertTrue(result.success)
        self.assertEqual(result.user_id, "")

    async def test_walks_all_four_legs_in_order(self) -> None:
        session = FakeSession(github_routes())
        await make_client(session).login(GITHUB_OAUTH, "user_session=abc")
        self.assertEqual(
            session.urls(),
            [
                f"{BASE}/api/status",
                f"{BASE}/api/oauth/state",
                GITHUB_AUTHORIZE,
                f"{BASE}/api/oauth/github",
            ],
        )

    async def test_sends_the_third_party_cookie_to_the_provider(self) -> None:
        session = FakeSession(github_routes())
        await make_client(session).login(GITHUB_OAUTH, "user_session=abc")
        authorize = session.calls_to("/login/oauth/authorize")[0]
        self.assertEqual(authorize["headers"]["Cookie"], "user_session=abc")

    async def test_the_query_string_matches_the_station_login_page(self) -> None:
        """Pinned to new-api's own buildGitHubOAuthUrl.

        The provider validates the request against the registered application,
        so an extra parameter is not free: a guessed redirect_uri that misses
        the registration is refused outright.
        """
        session = FakeSession(github_routes())
        await make_client(session).login(GITHUB_OAUTH, "user_session=abc")
        authorize = session.calls_to("/login/oauth/authorize")[0]
        self.assertEqual(
            authorize["params"], {"client_id": "cid-1", "state": "flow-1", "scope": "user:email"}
        )

    async def test_does_not_follow_the_provider_redirect(self) -> None:
        """The authorization code lives in the Location header, not the target."""
        session = FakeSession(github_routes())
        await make_client(session).login(GITHUB_OAUTH, "user_session=abc")
        authorize = session.calls_to("/login/oauth/authorize")[0]
        self.assertFalse(authorize["allow_redirects"])

    async def test_forwards_the_flow_token_as_state(self) -> None:
        session = FakeSession(github_routes())
        await make_client(session).login(GITHUB_OAUTH, "user_session=abc")
        authorize = session.calls_to("/login/oauth/authorize")[0]
        self.assertEqual(authorize["params"]["state"], "flow-1")
        self.assertEqual(authorize["params"]["client_id"], "cid-1")

    async def test_exchanges_the_code_it_extracted(self) -> None:
        session = FakeSession(github_routes())
        await make_client(session).login(GITHUB_OAUTH, "user_session=abc")
        exchange = session.calls_to("/api/oauth/github")[0]
        self.assertEqual(exchange["params"], {"code": "CODE-1", "state": "flow-1"})

    async def test_the_state_request_names_the_provider(self) -> None:
        session = FakeSession(github_routes())
        await make_client(session).login(GITHUB_OAUTH, "user_session=abc")
        state_call = session.calls_to("/api/oauth/state")[0]
        self.assertEqual(state_call["method"], "GET")
        self.assertEqual(state_call["params"], {"provider": "github"})

    async def test_the_proxy_applies_to_every_leg(self) -> None:
        session = FakeSession(github_routes())
        await make_client(session, "http://127.0.0.1:7890").login(GITHUB_OAUTH, "user_session=abc")
        self.assertTrue(all(call["proxy"] == "http://127.0.0.1:7890" for call in session.calls))

    async def test_the_impersonation_applies_to_every_leg(self) -> None:
        session = FakeSession(github_routes())
        await make_client(session).login(GITHUB_OAUTH, "user_session=abc")
        self.assertTrue(all(call["impersonate"] == "chrome131" for call in session.calls))

    async def test_pasted_newlines_are_stripped_from_the_cookie(self) -> None:
        session = FakeSession(github_routes())
        await make_client(session).login(GITHUB_OAUTH, " user_session=abc\n")
        authorize = session.calls_to("/login/oauth/authorize")[0]
        self.assertEqual(authorize["headers"]["Cookie"], "user_session=abc")

    async def test_linuxdo_sends_its_callback_and_response_type(self) -> None:
        session = FakeSession(
            {
                ("GET", f"{BASE}/api/status"): FakeResponse(
                    200, '{"data":{"linuxdo_oauth":true,"linuxdo_client_id":"cid-2"}}'
                ),
                ("GET", f"{BASE}/api/oauth/state"): FakeResponse(200, '{"data":"f"}'),
                ("GET", LINUXDO_AUTHORIZE): FakeResponse(
                    302, "", headers={"location": f"{BASE}/api/oauth/linuxdo?code=C&state=f"}
                ),
                ("GET", f"{BASE}/api/oauth/linuxdo"): FakeResponse(
                    200, "{}", cookies={"session": "s"}
                ),
            }
        )
        result = await make_client(session).login(LINUXDO_OAUTH, "_t=abc")
        self.assertTrue(result.success)
        authorize = session.calls_to("/oauth2/authorize")[0]
        self.assertNotIn("redirect_uri", authorize["params"])
        self.assertEqual(authorize["params"]["response_type"], "code")
        # A browser reaches the authorize page from the station's login page.
        self.assertEqual(authorize["headers"]["Referer"], f"{BASE}/")


class StatePowTests(unittest.IsolatedAsyncioTestCase):
    """vsllm.cc answers a state request without a solved challenge with pow_failed."""

    CHALLENGE = f"{BASE}/api/pow/challenge?purpose=oauth"

    @staticmethod
    def _challenge(token: str) -> FakeResponse:
        return FakeResponse(200, pow_challenge(token))

    @staticmethod
    def _client(session: FakeSession, trace: list | None = None) -> OAuthLoginClient:
        recorder = (lambda **kw: trace.append(kw)) if trace is not None else None
        return OAuthLoginClient(session, BASE, "chrome131", None, on_attempt=recorder, vs_pow=True)

    async def test_off_by_default_no_challenge_is_requested(self) -> None:
        session = FakeSession(github_routes({("GET", self.CHALLENGE): self._challenge("tok-1")}))
        result = await make_client(session).login(GITHUB_OAUTH, "user_session=abc")
        self.assertTrue(result.success, result.message)
        self.assertNotIn(self.CHALLENGE, session.urls())
        self.assertEqual(pow_proof(session.calls_to("/api/oauth/state")[0]), (None, None))

    async def test_off_a_refusal_points_at_the_switch(self) -> None:
        session = FakeSession(github_routes({("GET", f"{BASE}/api/oauth/state"): FakeResponse(200, POW_REFUSED)}))
        result = await make_client(session).login(GITHUB_OAUTH, "user_session=abc")
        self.assertFalse(result.success)
        self.assertFalse(result.blames_credential)
        self.assertIn("「求解 Vs PoW」", result.message)
        self.assertEqual(session.count_to("/api/oauth/state"), 1)

    async def test_the_state_carries_a_solved_challenge(self) -> None:
        session = FakeSession(github_routes({("GET", self.CHALLENGE): self._challenge("tok-1")}))
        result = await self._client(session).login(GITHUB_OAUTH, "user_session=abc")
        self.assertTrue(result.success, result.message)
        self.assertEqual(pow_proof(session.calls_to("/api/oauth/state")[0]), ("tok-1", POW_NONCE))

    async def test_a_refused_proof_is_retried_on_a_new_challenge(self) -> None:
        session = FakeSession(github_routes({
            ("GET", self.CHALLENGE): [self._challenge("tok-1"), self._challenge("tok-2")],
            ("GET", f"{BASE}/api/oauth/state"): [
                FakeResponse(200, POW_REFUSED),
                FakeResponse(200, '{"success":true,"data":"flow-1"}', cookies={"session": "srv"}),
            ],
        }))
        result = await self._client(session).login(GITHUB_OAUTH, "user_session=abc")
        self.assertTrue(result.success, result.message)
        tokens = [pow_proof(call)[0] for call in session.calls_to("/api/oauth/state")]
        self.assertEqual(tokens, ["tok-1", "tok-2"])

    async def test_repeated_refusals_stop_the_login_without_trying_post(self) -> None:
        trace = []
        session = FakeSession(github_routes({
            ("GET", self.CHALLENGE): self._challenge("tok"),
            ("GET", f"{BASE}/api/oauth/state"): FakeResponse(200, POW_REFUSED),
        }))
        result = await self._client(session, trace).login(GITHUB_OAUTH, "user_session=abc")
        self.assertFalse(result.success)
        self.assertIn("拒绝了 PoW 解答", result.message)
        self.assertEqual([c["method"] for c in session.calls_to("/api/oauth/state")], ["GET"] * 3)
        self.assertNotIn(GITHUB_AUTHORIZE, session.urls())
        self.assertIn("PoW 求解", [entry["step"] for entry in trace])

    async def test_a_challenge_too_hard_stops_before_the_state(self) -> None:
        session = FakeSession(github_routes({("GET", self.CHALLENGE): self._challenge("tok")}))
        with mock.patch.object(PowChallenge, "solve", side_effect=PowTimeout):
            result = await self._client(session).login(GITHUB_OAUTH, "user_session=abc")
        self.assertFalse(result.success)
        self.assertFalse(result.blames_credential)
        self.assertIn("难度 18", result.message)
        self.assertEqual(session.count_to("/api/oauth/state"), 0)


class FailedLoginTests(unittest.IsolatedAsyncioTestCase):
    async def test_unsupported_credential_type(self) -> None:
        result = await make_client(FakeSession({})).login("gitlab_oauth", "c")
        self.assertFalse(result.success)
        self.assertIn("不支持", result.message)

    async def test_empty_cookie_names_the_expected_cookie(self) -> None:
        result = await make_client(FakeSession({})).login(GITHUB_OAUTH, "  ")
        self.assertFalse(result.success)
        self.assertIn("user_session", result.message)

    async def test_provider_disabled_on_the_station(self) -> None:
        session = FakeSession(
            github_routes(
                {
                    ("GET", f"{BASE}/api/status"): FakeResponse(
                        200, '{"data":{"github_oauth":false}}'
                    )
                }
            )
        )
        result = await make_client(session).login(GITHUB_OAUTH, "user_session=abc")
        self.assertFalse(result.success)
        self.assertIn("未启用", result.message)

    async def test_missing_client_id(self) -> None:
        session = FakeSession(
            github_routes(
                {("GET", f"{BASE}/api/status"): FakeResponse(200, '{"data":{"github_oauth":true}}')}
            )
        )
        result = await make_client(session).login(GITHUB_OAUTH, "user_session=abc")
        self.assertFalse(result.success)
        self.assertIn("client_id", result.message)

    async def test_status_endpoint_returning_html(self) -> None:
        session = FakeSession(
            github_routes({("GET", f"{BASE}/api/status"): FakeResponse(200, "<html></html>")})
        )
        result = await make_client(session).login(GITHUB_OAUTH, "user_session=abc")
        self.assertFalse(result.success)
        self.assertIn("JSON", result.message)

    async def test_status_endpoint_without_a_data_field(self) -> None:
        session = FakeSession(
            github_routes({("GET", f"{BASE}/api/status"): FakeResponse(200, '{"success":true}')})
        )
        result = await make_client(session).login(GITHUB_OAUTH, "user_session=abc")
        self.assertFalse(result.success)
        self.assertIn("data", result.message)

    async def test_missing_flow_token_surfaces_the_station_message(self) -> None:
        session = FakeSession(
            github_routes(
                {
                    ("GET", f"{BASE}/api/oauth/state"): FakeResponse(
                        200, '{"success":false,"message":"频率过高"}'
                    )
                }
            )
        )
        result = await make_client(session).login(GITHUB_OAUTH, "user_session=abc")
        self.assertFalse(result.success)
        self.assertIn("频率过高", result.message)

    async def test_expired_cookie_redirecting_to_login(self) -> None:
        session = FakeSession(
            github_routes(
                {
                    ("GET", GITHUB_AUTHORIZE): FakeResponse(
                        302, "", headers={"location": "https://github.com/login?return_to=x"}
                    )
                }
            )
        )
        result = await make_client(session).login(GITHUB_OAUTH, "user_session=stale")
        self.assertFalse(result.success)
        self.assertTrue(result.blames_credential)
        self.assertIn("user_session", result.message)

    async def test_unauthorized_authorize_response(self) -> None:
        session = FakeSession(
            github_routes({("GET", GITHUB_AUTHORIZE): FakeResponse(401, "unauthorized")})
        )
        result = await make_client(session).login(GITHUB_OAUTH, "user_session=stale")
        self.assertFalse(result.success)
        # A flat 401 carries no redirect to reason from, so the message lists the
        # plausible causes — including the incomplete cookie — rather than
        # asserting one. A bounce to the login page is what reads as expiry.
        self.assertIn("401", result.message)
        self.assertIn("缺少", result.message)

    async def test_a_login_page_redirect_reports_the_cookie(self) -> None:
        session = FakeSession(
            github_routes({
                ("GET", GITHUB_AUTHORIZE): FakeResponse(
                    302, "", headers={"location": "https://github.com/login?return_to=x"}
                )
            })
        )
        result = await make_client(session).login(GITHUB_OAUTH, "user_session=stale")
        self.assertFalse(result.success)
        self.assertIn("未接受该会话 Cookie", result.message)

    async def test_consent_page_instead_of_a_redirect(self) -> None:
        """The user has to approve the OAuth app in a browser once."""
        session = FakeSession(
            github_routes(
                {("GET", GITHUB_AUTHORIZE): FakeResponse(200, "<html>Authorize app?</html>")}
            )
        )
        result = await make_client(session).login(GITHUB_OAUTH, "user_session=abc")
        self.assertFalse(result.success)
        self.assertIn("浏览器", result.message)

    async def test_provider_reported_error_is_surfaced(self) -> None:
        session = FakeSession(
            github_routes(
                {
                    ("GET", GITHUB_AUTHORIZE): FakeResponse(
                        302, "", headers={"location": f"{BASE}/cb?error=access_denied"}
                    )
                }
            )
        )
        result = await make_client(session).login(GITHUB_OAUTH, "user_session=abc")
        self.assertFalse(result.success)
        self.assertIn("access_denied", result.message)

    async def test_callback_without_a_session_cookie(self) -> None:
        session = FakeSession(
            github_routes(
                {
                    ("GET", f"{BASE}/api/oauth/github"): FakeResponse(
                        403, '{"success":false,"message":"该账号未绑定"}', cookies={}
                    )
                }
            )
        )
        result = await make_client(session).login(GITHUB_OAUTH, "user_session=abc")
        self.assertFalse(result.success)
        self.assertIn("未绑定", result.message)

    async def test_transport_errors_are_wrapped(self) -> None:
        class BoomSession(FakeSession):
            async def request(self, method, url, **kwargs):
                raise ConnectionError("dns failure")

        result = await make_client(BoomSession({})).login(GITHUB_OAUTH, "user_session=abc")
        self.assertFalse(result.success)
        self.assertIn("dns failure", result.message)


# What newer New-API answers a login with: a bearer token in the body, the
# user nested beside it, and the refresh token as a cookie.
TOKEN_LOGIN_BODY = (
    '{"success":true,"data":{"access_token":"at-1","token_type":"Bearer",'
    '"access_expires_at":1900000000,"user":{"id":7,"username":"u"}}}'
)
REFRESH_URL = f"{BASE}/api/user/auth/refresh"


class TokenLoginTests(unittest.IsolatedAsyncioTestCase):
    """Newer New-API issues an access token and a refresh cookie instead of a session."""

    def _session(self) -> FakeSession:
        return FakeSession(github_routes({
            ("GET", f"{BASE}/api/oauth/github"): FakeResponse(
                200, TOKEN_LOGIN_BODY,
                cookies={"new_api_refresh": "sid.r1", "new_api_has_session": "1"},
            ),
        }))

    async def test_the_login_returns_both_tokens(self) -> None:
        result = await make_client(self._session()).login(GITHUB_OAUTH, "user_session=abc")
        self.assertTrue(result.success)
        self.assertEqual((result.access_token, result.access_expires_at), ("at-1", 1900000000))
        self.assertIn("new_api_refresh=sid.r1", result.session_cookie)
        self.assertEqual(result.user_id, "7")

    async def test_the_token_body_is_kept_out_of_the_trace(self) -> None:
        trace: list[dict] = []
        client = OAuthLoginClient(self._session(), BASE, "chrome131",
                                  on_attempt=lambda **kw: trace.append(kw))
        await client.login(GITHUB_OAUTH, "user_session=abc")
        callback = [t for t in trace if t["step"] == "OAuth 回调"][0]
        self.assertNotIn("at-1", callback["response_text"])
        self.assertIn("访问令牌", callback["message"])

    def test_milliseconds_are_normalized(self) -> None:
        fields = _extract_login_fields('{"data":{"access_token":"t","access_expires_at":1900000000000}}')
        self.assertEqual(fields.access_expires_at, 1900000000)

    def test_a_legacy_body_carries_no_token(self) -> None:
        fields = _extract_login_fields('{"success":true,"data":{"id":9,"username":"u"}}')
        self.assertEqual((fields.user_id, fields.access_token, fields.access_expires_at), ("9", "", 0))


class TokenRefreshTests(unittest.IsolatedAsyncioTestCase):
    HELD = "new_api_refresh=sid.r1; new_api_has_session=1"

    async def test_a_refresh_returns_the_token_and_the_rotated_cookie(self) -> None:
        session = FakeSession({("POST", REFRESH_URL): FakeResponse(
            200, TOKEN_LOGIN_BODY.replace("at-1", "at-2"), cookies={"new_api_refresh": "sid.r2"},
        )})
        result = await make_client(session).refresh(self.HELD)
        self.assertTrue(result.success)
        self.assertEqual(result.access_token, "at-2")
        self.assertEqual(result.session_cookie, "new_api_refresh=sid.r2; new_api_has_session=1")

    async def test_the_refresh_presents_the_cookie_from_the_station_origin(self) -> None:
        session = FakeSession({("POST", REFRESH_URL): FakeResponse(200, TOKEN_LOGIN_BODY)})
        await make_client(session).refresh(self.HELD)
        headers = session.calls[0]["headers"]
        self.assertEqual(headers["Cookie"], self.HELD)
        self.assertEqual(headers["Origin"], BASE)

    async def test_a_revoked_session_is_reported(self) -> None:
        session = FakeSession({("POST", REFRESH_URL): FakeResponse(
            401, '{"success":false,"code":"AUTH_SESSION_REVOKED","message":"Unauthorized"}',
        )})
        result = await make_client(session).refresh(self.HELD)
        self.assertFalse(result.success)
        self.assertIn("AUTH_SESSION_REVOKED", result.message)
        self.assertEqual(result.session_cookie, self.HELD)


class FlowTokenShapeTests(unittest.TestCase):
    """Forks disagree on where the OAuth state token lives."""

    def test_nested_flow_token(self) -> None:
        self.assertEqual(_extract_flow_token({"data": {"flow_token": "T"}}), "T")

    def test_nested_aliases(self) -> None:
        for key in ("state", "token", "oauth_state", "flowToken"):
            self.assertEqual(_extract_flow_token({"data": {key: "T"}}), "T", key)

    def test_data_as_a_plain_string(self) -> None:
        self.assertEqual(_extract_flow_token({"success": True, "data": "T"}), "T")

    def test_top_level_keys(self) -> None:
        self.assertEqual(_extract_flow_token({"flow_token": "T"}), "T")
        self.assertEqual(_extract_flow_token({"state": "T"}), "T")

    def test_bare_string_response(self) -> None:
        self.assertEqual(_extract_flow_token("T"), "T")

    def test_unrecognised_shapes_yield_nothing(self) -> None:
        for payload in ({}, {"data": None}, {"data": {}}, {"data": {"foo": "bar"}}, None, 5, []):
            self.assertEqual(_extract_flow_token(payload), "", repr(payload))

    def test_blank_values_are_ignored(self) -> None:
        self.assertEqual(_extract_flow_token({"data": {"flow_token": "   "}}), "")


class SafeLocationTests(unittest.TestCase):
    def test_code_and_state_are_redacted(self) -> None:
        """A redirect carries the authorization code; it must not be logged."""
        safe = _safe_location("https://x.test/cb?code=SECRET&state=ALSOSECRET&keep=1")
        self.assertNotIn("SECRET", safe)
        self.assertNotIn("ALSOSECRET", safe)
        self.assertIn("code=***", safe)
        self.assertIn("state=***", safe)
        self.assertIn("keep=1", safe)

    def test_plain_url_is_preserved(self) -> None:
        self.assertEqual(_safe_location("https://x.test/login"), "https://x.test/login")

    def test_empty_input(self) -> None:
        self.assertEqual(_safe_location(""), "")


class FlowTokenFallbackTests(unittest.IsolatedAsyncioTestCase):
    """Diagnostics and tolerance around the /api/oauth/state endpoint."""

    def _client(self, state_response, trace=None):
        routes = {
            ("GET", f"{BASE}/api/status"): FakeResponse(
                200, '{"data":{"github_oauth":true,"github_client_id":"cid"}}'
            ),
            ("GET", f"{BASE}/api/oauth/state"): state_response,
            ("GET", GITHUB_AUTHORIZE): FakeResponse(
                302, "", headers={"location": f"{BASE}/api/oauth/github?code=C&state=S"}
            ),
            ("GET", f"{BASE}/api/oauth/github"): FakeResponse(
                200, "{}", cookies={"session": "live"}
            ),
        }
        session = FakeSession(routes)
        recorder = (lambda **kw: trace.append(kw)) if trace is not None else None
        return session, OAuthLoginClient(session, BASE, "chrome131", None, on_attempt=recorder)

    async def test_a_string_data_field_still_logs_in(self) -> None:
        _, client = self._client(FakeResponse(200, '{"success":true,"data":"ABC"}'))
        result = await client.login(GITHUB_OAUTH, "user_session=x")
        self.assertTrue(result.success)

    async def test_a_missing_state_endpoint_falls_back_to_a_local_state(self) -> None:
        """Older stations have no state endpoint and accept a client-chosen one."""
        for status in (404, 405):
            session, client = self._client(FakeResponse(status, "not found"))
            session.routes[("POST", f"{BASE}/api/oauth/state")] = FakeResponse(status, "not found")
            result = await client.login(GITHUB_OAUTH, "user_session=x")
            self.assertTrue(result.success, status)
            authorize = session.calls_to("/login/oauth/authorize")[0]
            self.assertTrue(authorize["params"]["state"])

    async def test_an_unknown_shape_reports_the_body(self) -> None:
        """The station's own response is the only clue, so surface it."""
        _, client = self._client(FakeResponse(200, '{"success":true,"data":{"foo":"bar"}}'))
        result = await client.login(GITHUB_OAUTH, "user_session=x")
        self.assertFalse(result.success)
        self.assertIn("state", result.message)
        self.assertIn('"foo"', result.message)

    async def test_a_station_message_is_preferred_over_the_body(self) -> None:
        _, client = self._client(FakeResponse(200, '{"success":false,"message":"请求过于频繁"}'))
        result = await client.login(GITHUB_OAUTH, "user_session=x")
        self.assertIn("请求过于频繁", result.message)

    async def test_every_leg_is_traced_on_success(self) -> None:
        trace: list[dict] = []
        _, client = self._client(FakeResponse(200, '{"data":{"flow_token":"T"}}'), trace)
        # A complete cookie skips the pre-flight completeness warning, leaving
        # exactly the four request legs.
        full = "; ".join(f"{name}=v" for name in PROVIDERS[GITHUB_OAUTH].all_cookies)
        await client.login(GITHUB_OAUTH, full)
        self.assertEqual(
            [item["step"] for item in trace],
            ["探测 OAuth 配置", "获取 OAuth state", "Github OAuth 授权", "OAuth 回调"],
        )
        self.assertTrue(all(item["success"] for item in trace))

    async def test_the_failing_leg_is_traced(self) -> None:
        trace: list[dict] = []
        _, client = self._client(FakeResponse(200, '{"data":{"foo":"bar"}}'), trace)
        await client.login(GITHUB_OAUTH, "user_session=x")
        failed = [item for item in trace if item.get("error")]
        self.assertEqual(len(failed), 1)
        self.assertEqual(failed[0]["step"], "获取 OAuth state")
        self.assertEqual(failed[0]["status"], 200)
        self.assertIn('"foo"', failed[0]["response_text"])

    async def test_the_traced_authorize_leg_hides_the_code(self) -> None:
        trace: list[dict] = []
        _, client = self._client(FakeResponse(200, '{"data":{"flow_token":"T"}}'), trace)
        await client.login(GITHUB_OAUTH, "user_session=x")
        joined = " ".join(str(item) for item in trace)
        self.assertNotIn("code=C&", joined)

    async def test_tracing_failures_do_not_break_the_login(self) -> None:
        def boom(**_kwargs):
            raise RuntimeError("recorder exploded")

        session = FakeSession(
            {
                ("GET", f"{BASE}/api/status"): FakeResponse(
                    200, '{"data":{"github_oauth":true,"github_client_id":"cid"}}'
                ),
                ("POST", f"{BASE}/api/oauth/state"): FakeResponse(200, '{"data":{"flow_token":"T"}}'),
                ("GET", GITHUB_AUTHORIZE): FakeResponse(
                    302, "", headers={"location": f"{BASE}/api/oauth/github?code=C&state=T"}
                ),
                ("GET", f"{BASE}/api/oauth/github"): FakeResponse(
                    200, "{}", cookies={"session": "live"}
                ),
            }
        )
        client = OAuthLoginClient(session, BASE, "chrome131", None, on_attempt=boom)
        result = await client.login(GITHUB_OAUTH, "user_session=x")
        self.assertTrue(result.success)


class CookieCompletenessTests(unittest.TestCase):
    """Github rejects an authorize request carrying only user_session."""

    def test_github_lists_its_companion_cookies(self) -> None:
        provider = PROVIDERS[GITHUB_OAUTH]
        self.assertEqual(provider.cookie_hint, "user_session")
        self.assertIn("__Host-user_session_same_site", provider.all_cookies)
        self.assertIn("_gh_sess", provider.all_cookies)
        self.assertEqual(provider.all_cookies[0], "user_session")

    def test_authorize_host_is_the_cookie_domain(self) -> None:
        self.assertEqual(PROVIDERS[GITHUB_OAUTH].authorize_host, "github.com")
        self.assertEqual(PROVIDERS[LINUXDO_OAUTH].authorize_host, "connect.linux.do")

    def test_missing_cookies_are_detected(self) -> None:
        provider = PROVIDERS[GITHUB_OAUTH]
        self.assertEqual(
            _missing_cookies(provider, "user_session=a"),
            ["__Host-user_session_same_site", "_gh_sess", "logged_in"],
        )

    def test_a_complete_cookie_reports_nothing_missing(self) -> None:
        provider = PROVIDERS[GITHUB_OAUTH]
        full = "; ".join(f"{name}=v" for name in provider.all_cookies)
        self.assertEqual(_missing_cookies(provider, full), [])

    def test_whitespace_and_ordering_do_not_matter(self) -> None:
        provider = PROVIDERS[GITHUB_OAUTH]
        jumbled = "  logged_in=yes ;_gh_sess=c;  __Host-user_session_same_site=b ; user_session=a  "
        self.assertEqual(_missing_cookies(provider, jumbled), [])


class RejectedSessionMessageTests(unittest.IsolatedAsyncioTestCase):
    """A login-page redirect must not be blamed on expiry alone."""

    def _routes(self) -> dict:
        return {
            ("GET", f"{BASE}/api/status"): FakeResponse(
                200, '{"data":{"github_oauth":true,"github_client_id":"cid"}}'
            ),
            ("POST", f"{BASE}/api/oauth/state"): FakeResponse(
                404, '{"error":{"message":"Invalid URL (POST /api/oauth/state)"}}'
            ),
            ("GET", GITHUB_AUTHORIZE): FakeResponse(
                302, "", headers={"location": "https://github.com/login?client_id=cid&return_to=/x"}
            ),
        }

    async def test_a_partial_cookie_names_what_is_missing(self) -> None:
        client = make_client(FakeSession(self._routes()))
        result = await client.login(GITHUB_OAUTH, "user_session=abc")
        self.assertFalse(result.success)
        self.assertIn("缺少", result.message)
        self.assertIn("__Host-user_session_same_site", result.message)
        self.assertIn("github.com", result.message)

    async def test_a_complete_cookie_reports_rejection_not_omission(self) -> None:
        full = "; ".join(f"{n}=v" for n in PROVIDERS[GITHUB_OAUTH].all_cookies)
        client = make_client(FakeSession(self._routes()))
        result = await client.login(GITHUB_OAUTH, full)
        self.assertFalse(result.success)
        self.assertNotIn("缺少", result.message)
        self.assertIn("失效或被拒绝", result.message)

    async def test_a_partial_cookie_is_warned_about_before_the_request(self) -> None:
        trace: list[dict] = []
        session = FakeSession(self._routes())
        client = OAuthLoginClient(session, BASE, "chrome131", None,
                                  on_attempt=lambda **kw: trace.append(kw))
        await client.login(GITHUB_OAUTH, "user_session=abc")
        checks = [item for item in trace if "凭据检查" in item["step"]]
        self.assertEqual(len(checks), 1)
        self.assertIn("_gh_sess", checks[0]["message"])

    async def test_a_partial_cookie_is_still_attempted(self) -> None:
        """Refusing outright would block a provider that happens to accept it."""
        session = FakeSession(self._routes())
        await make_client(session).login(GITHUB_OAUTH, "user_session=abc")
        self.assertTrue(session.calls_to("/login/oauth/authorize"))

    async def test_an_empty_cookie_names_the_whole_set(self) -> None:
        result = await make_client(FakeSession({})).login(GITHUB_OAUTH, "   ")
        self.assertFalse(result.success)
        self.assertIn("完整 Cookie", result.message)
        self.assertIn("__Host-user_session_same_site", result.message)


class StateEndpointMethodTests(unittest.IsolatedAsyncioTestCase):
    """The state endpoint's verb and its session cookie both matter."""

    @staticmethod
    def _routes(state_routes: dict) -> dict:
        routes = {
            ("GET", f"{BASE}/api/status"): FakeResponse(
                200, '{"data":{"github_oauth":true,"github_client_id":"cid"}}'
            ),
            ("GET", GITHUB_AUTHORIZE): FakeResponse(
                302, "", headers={"location": f"{BASE}/api/oauth/github?code=C&state=S"}
            ),
            ("GET", f"{BASE}/api/oauth/github"): FakeResponse(
                200, "{}", cookies={"session": "final"}
            ),
        }
        routes.update(state_routes)
        return routes

    async def test_get_is_tried_before_post(self) -> None:
        """Classic one-api registers the state route under GET only."""
        session = FakeSession(self._routes({
            ("GET", f"{BASE}/api/oauth/state"): FakeResponse(200, '{"data":"S"}'),
        }))
        result = await make_client(session).login(GITHUB_OAUTH, "user_session=abc")
        self.assertTrue(result.success)
        self.assertEqual(session.calls_to("/api/oauth/state")[0]["method"], "GET")
        self.assertEqual(session.count_to("/api/oauth/state"), 1)

    async def test_post_is_used_when_get_is_not_registered(self) -> None:
        session = FakeSession(self._routes({
            ("GET", f"{BASE}/api/oauth/state"): FakeResponse(
                404, '{"error":{"message":"Invalid URL (GET /api/oauth/state)"}}'
            ),
            ("POST", f"{BASE}/api/oauth/state"): FakeResponse(200, '{"data":{"flow_token":"S"}}'),
        }))
        result = await make_client(session).login(GITHUB_OAUTH, "user_session=abc")
        self.assertTrue(result.success)
        methods = [call["method"] for call in session.calls_to("/api/oauth/state")]
        self.assertEqual(methods, ["GET", "POST"])

    async def test_the_state_session_cookie_reaches_the_callback(self) -> None:
        """Without it the station compares against an empty session and answers
        "state is empty or not same"."""
        session = FakeSession(self._routes({
            ("GET", f"{BASE}/api/oauth/state"): FakeResponse(
                200, '{"data":"S"}', cookies={"session": "srv-side"}
            ),
        }))
        await make_client(session).login(GITHUB_OAUTH, "user_session=abc")
        callback = session.calls_to("/api/oauth/github")[0]
        self.assertEqual(callback["headers"]["Cookie"], "session=srv-side")

    async def test_the_same_state_is_sent_to_provider_and_callback(self) -> None:
        session = FakeSession(self._routes({
            ("GET", f"{BASE}/api/oauth/state"): FakeResponse(200, '{"data":"THE-STATE"}'),
        }))
        await make_client(session).login(GITHUB_OAUTH, "user_session=abc")
        authorize = session.calls_to("/login/oauth/authorize")[0]
        callback = session.calls_to("/api/oauth/github")[0]
        self.assertEqual(authorize["params"]["state"], "THE-STATE")
        self.assertEqual(callback["params"]["state"], "THE-STATE")

    async def test_no_cookie_header_when_the_station_sets_none(self) -> None:
        session = FakeSession(self._routes({
            ("GET", f"{BASE}/api/oauth/state"): FakeResponse(200, '{"data":"S"}', cookies={}),
        }))
        await make_client(session).login(GITHUB_OAUTH, "user_session=abc")
        callback = session.calls_to("/api/oauth/github")[0]
        self.assertNotIn("Cookie", callback["headers"] or {})

    async def test_a_rejected_state_is_reported_verbatim(self) -> None:
        """The station's own wording is the clearest diagnosis."""
        session = FakeSession(self._routes({
            ("GET", f"{BASE}/api/oauth/state"): FakeResponse(200, '{"data":"S"}'),
            ("GET", f"{BASE}/api/oauth/github"): FakeResponse(
                403, '{"message":"state is empty or not same","success":false}', cookies={}
            ),
        }))
        result = await make_client(session).login(GITHUB_OAUTH, "user_session=abc")
        self.assertFalse(result.success)
        self.assertIn("state is empty or not same", result.message)

    async def test_both_verbs_missing_falls_back_to_a_local_state(self) -> None:
        session = FakeSession(self._routes({
            ("GET", f"{BASE}/api/oauth/state"): FakeResponse(404, "nope"),
            ("POST", f"{BASE}/api/oauth/state"): FakeResponse(404, "nope"),
        }))
        result = await make_client(session).login(GITHUB_OAUTH, "user_session=abc")
        self.assertTrue(result.success)
        authorize = session.calls_to("/login/oauth/authorize")[0]
        self.assertTrue(authorize["params"]["state"])


class CookieRotationTests(unittest.TestCase):
    """A provider rotates session cookies as they are used. Replaying one frozen
    snapshot is what makes a stored cookie appear to expire on its own."""

    HELD = "user_session=OLD; __Host-user_session_same_site=SS; _gh_sess=G1; logged_in=yes"

    def test_a_rotated_cookie_is_merged(self) -> None:
        merged = merge_rotated_cookies(self.HELD, {"_gh_sess": "G2"})
        self.assertIn("_gh_sess=G2", merged)

    def test_the_rest_of_the_jar_survives(self) -> None:
        merged = merge_rotated_cookies(self.HELD, {"_gh_sess": "G2"})
        jar = parse_cookie_header(merged)
        self.assertEqual(jar["user_session"], "OLD")
        self.assertEqual(jar["__Host-user_session_same_site"], "SS")
        self.assertEqual(jar["logged_in"], "yes")

    def test_several_cookies_rotate_at_once(self) -> None:
        merged = merge_rotated_cookies(self.HELD, {"_gh_sess": "G2", "user_session": "NEW"})
        jar = parse_cookie_header(merged)
        self.assertEqual(jar["_gh_sess"], "G2")
        self.assertEqual(jar["user_session"], "NEW")

    def test_an_unchanged_value_reports_no_rotation(self) -> None:
        """Empty means "unchanged", so a caller never writes a pointless update."""
        self.assertEqual(merge_rotated_cookies(self.HELD, {"_gh_sess": "G1"}), "")

    def test_unrelated_cookies_are_ignored(self) -> None:
        """Analytics and flash cookies add noise and no value."""
        self.assertEqual(merge_rotated_cookies(self.HELD, {"_octo": "GH1.1"}), "")

    def test_a_deletion_never_blanks_a_held_cookie(self) -> None:
        for sentinel in ("", "deleted", '""'):
            self.assertEqual(merge_rotated_cookies(self.HELD, {"_gh_sess": sentinel}), "", sentinel)

    def test_no_response_cookies(self) -> None:
        self.assertEqual(merge_rotated_cookies(self.HELD, {}), "")

    def test_an_empty_stored_cookie_cannot_be_seeded(self) -> None:
        """Rotation refreshes what we hold; it never invents a credential."""
        self.assertEqual(merge_rotated_cookies("", {"_gh_sess": "G2"}), "")

    def test_a_broken_jar_is_survived(self) -> None:
        class Boom:
            def items(self):
                raise RuntimeError("no cookies here")

        self.assertEqual(merge_rotated_cookies(self.HELD, Boom()), "")

    def test_cookie_objects_are_unwrapped(self) -> None:
        class Cookie:
            def __init__(self, value): self.value = value

        merged = merge_rotated_cookies(self.HELD, {"_gh_sess": Cookie("G9")})
        self.assertIn("_gh_sess=G9", merged)


class RotationReportingTests(unittest.IsolatedAsyncioTestCase):
    HELD = "user_session=OLD; __Host-user_session_same_site=SS; _gh_sess=G1; logged_in=yes"

    def _routes(self, authorize_cookies=None, authorize=None):
        return github_routes({
            ("GET", GITHUB_AUTHORIZE): authorize or FakeResponse(
                302, "",
                headers={"location": f"{BASE}/oauth/github?code=CODE-1&state=flow-1"},
                cookies=authorize_cookies or {},
            )
        })

    async def test_a_rotation_is_reported_on_success(self) -> None:
        session = FakeSession(self._routes({"_gh_sess": "G2"}))
        result = await make_client(session).login(GITHUB_OAUTH, self.HELD)
        self.assertTrue(result.success)
        self.assertIn("_gh_sess=G2", result.rotated_provider_cookie)

    async def test_no_rotation_reports_nothing(self) -> None:
        session = FakeSession(self._routes())
        result = await make_client(session).login(GITHUB_OAUTH, self.HELD)
        self.assertTrue(result.success)
        self.assertEqual(result.rotated_provider_cookie, "")

    async def test_the_trace_mentions_the_rotation(self) -> None:
        trace: list[dict] = []
        session = FakeSession(self._routes({"_gh_sess": "G2"}))
        client = OAuthLoginClient(session, BASE, "chrome131", None,
                                  on_attempt=lambda **kw: trace.append(kw))
        await client.login(GITHUB_OAUTH, self.HELD)
        authorize = [item for item in trace if "授权" in item["step"] and item["success"]]
        self.assertTrue(any("轮换" in (item.get("message") or "") for item in authorize))


class LinuxdoAuthorizeHelpers:
    """Shared LinuxDO route table. A plain mixin, not a TestCase: subclassing a
    TestCase to borrow helpers would re-run all of its tests under the new name."""

    COOKIE = "_t=abc; _forum_session=fs"

    def _routes(self, authorize):
        return {
            ("GET", f"{BASE}/api/status"): FakeResponse(
                200, '{"data":{"linuxdo_oauth":true,"linuxdo_client_id":"cid"}}'
            ),
            ("GET", f"{BASE}/api/oauth/state"): FakeResponse(200, '{"data":"st"}'),
            ("GET", LINUXDO_AUTHORIZE): authorize,
            ("GET", f"{BASE}/api/oauth/linuxdo"): FakeResponse(
                200, "{}", cookies={"session": "fresh"}
            ),
        }

    async def _login(self, authorize, cookie=None, trace=None):
        session = FakeSession(self._routes(authorize))
        recorder = (lambda **kw: trace.append(kw)) if trace is not None else None
        client = OAuthLoginClient(session, BASE, "chrome131", None, on_attempt=recorder)
        return await client.login(LINUXDO_OAUTH, cookie or self.COOKIE)


class DiscourseRelayTests(LinuxdoAuthorizeHelpers, unittest.IsolatedAsyncioTestCase):
    """Without its own session connect.linux.do bounces through Discourse SSO
    on linux.do, as observed live on 2026-09-26; a browser follows that."""

    SSO = "https://linux.do/session/sso_provider?sso=A&sig=B"
    CALLBACK = "https://connect.linux.do/discourse/sso_callback?sso=C&sig=D"
    AGAIN = "https://connect.linux.do/oauth2/authorize?response_type=code&client_id=cid&state=st"

    def _relay_session(self, final):
        routes = self._routes(FakeResponse(
            302, "", headers={"location": self.SSO}, cookies={"auth.session-token": "pre"}))
        routes[self.SSO] = FakeResponse(
            302, "", headers={"location": self.CALLBACK}, cookies={"_t": "rotated"})
        routes[self.CALLBACK] = FakeResponse(
            302, "", headers={"location": self.AGAIN[len("https://connect.linux.do"):]},
            cookies={"auth.session-token": "tok"})
        routes[self.AGAIN] = final
        return FakeSession(routes)

    async def test_the_relay_is_followed_to_the_code(self) -> None:
        session = self._relay_session(FakeResponse(
            302, "", headers={"location": f"{BASE}/oauth/linuxdo?code=C&state=st"}))
        client = OAuthLoginClient(session, BASE, "chrome131", None)
        result = await client.login(LINUXDO_OAUTH, self.COOKIE)
        self.assertTrue(result.success, result.message)
        self.assertEqual(session.urls()[2:6], [LINUXDO_AUTHORIZE, self.SSO, self.CALLBACK, self.AGAIN])
        # The callback's session reaches the second authorize, and is kept.
        self.assertIn("auth.session-token=tok", session.calls[5]["headers"]["Cookie"])
        jar = parse_cookie_header(result.rotated_provider_cookie)
        self.assertEqual(jar["auth.session-token"], "tok")
        self.assertEqual(jar["_t"], "rotated")

    async def test_saved_cookie_scopes_are_used_for_each_curl_relay_host(self) -> None:
        session = self._relay_session(
            FakeResponse(
                302, "", headers={"location": f"{BASE}/oauth/linuxdo?code=C&state=st"}
            )
        )
        scoped = [
            {
                "name": "_t",
                "value": "connect",
                "domain": "connect.linux.do",
                "path": "/",
            },
            {
                "name": "_t",
                "value": "private",
                "domain": "connect.linux.do",
                "path": "/discourse",
            },
            {
                "name": "_t",
                "value": "wrong-path",
                "domain": "connect.linux.do",
                "path": "/discourse//",
            },
            {"name": "_t", "value": "root", "domain": "linux.do", "path": "/"},
        ]
        result = await OAuthLoginClient(session, BASE, "chrome131").login(
            LINUXDO_OAUTH, self.COOKIE, scoped
        )
        self.assertTrue(result.success, result.message)
        headers = [call["headers"]["Cookie"] for call in session.calls[2:6]]
        self.assertIn("_t=connect", headers[0])
        self.assertIn("_t=root", headers[1])
        self.assertTrue(headers[2].startswith("_t=private; _t=connect"), headers[2])
        self.assertIn("_t=connect", headers[3])
        self.assertNotIn("_t=rotated", headers[3])

    async def test_curl_cookie_jars_keep_duplicate_names_and_domain_attributes(
        self,
    ) -> None:
        response = FakeResponse(
            302, "", headers={"location": f"{BASE}/oauth/linuxdo?code=C&state=st"}
        )
        response.cookies = Cookies()
        response.cookies.set(
            "_t", "connect-new", domain="connect.linux.do", path="/oauth2"
        )
        response.cookies.set("_t", "root-new", domain=".linux.do", path="/")
        for item in response.cookies.jar:
            item.set_nonstandard_attr("http_only", "True")
            item.secure = True
            item.expires = 4102444800
        session = FakeSession(self._routes(response))
        result = await OAuthLoginClient(session, BASE, "chrome131").login(
            LINUXDO_OAUTH,
            self.COOKIE,
            [
                {
                    "name": "_t",
                    "value": "connect-old",
                    "domain": ".connect.linux.do",
                    "path": "/oauth2",
                },
                {"name": "_t", "value": "root-old", "domain": ".linux.do", "path": "/"},
            ],
        )
        self.assertTrue(result.success, result.message)
        values = {
            (c["domain"], c["path"]): c["value"]
            for c in result.provider_cookies
            if c["name"] == "_t"
        }
        self.assertEqual(
            values,
            {
                (".connect.linux.do", "/oauth2"): "connect-new",
                (".linux.do", "/"): "root-new",
            },
        )
        self.assertTrue(
            all(
                c["httpOnly"] and c["secure"] and c["expires"] == 4102444800
                for c in result.provider_cookies
                if c["name"] == "_t"
            )
        )

    async def test_a_deleted_browser_cookie_is_not_recreated_from_the_old_header(
        self,
    ) -> None:
        response = FakeResponse(403, "provider refused authorization")
        response.provider_cookies = [
            {
                "name": "_t",
                "value": "connect",
                "domain": "connect.linux.do",
                "path": "/",
            }
        ]
        first = await OAuthLoginClient(
            FakeSession(self._routes(response)), BASE, "chrome131"
        ).login(
            LINUXDO_OAUTH,
            self.COOKIE,
            [
                {
                    "name": "_t",
                    "value": "connect",
                    "domain": "connect.linux.do",
                    "path": "/",
                },
                {"name": "_t", "value": "root", "domain": "linux.do", "path": "/"},
            ],
        )
        self.assertFalse(first.success)
        self.assertTrue(
            any(
                c["domain"] == "linux.do" and c["expires"] == 1
                for c in first.provider_cookies
            )
        )
        session = self._relay_session(
            FakeResponse(302, "", headers={"location": f"{BASE}/cb?code=C&state=st"})
        )
        await OAuthLoginClient(session, BASE, "chrome131").login(
            LINUXDO_OAUTH, self.COOKIE, first.provider_cookies
        )
        self.assertNotIn("_t=", session.calls[3]["headers"]["Cookie"])

    async def test_a_redirect_off_the_relay_still_fails(self) -> None:
        session = self._relay_session(FakeResponse(
            302, "", headers={"location": "https://evil.example/x"}))
        client = OAuthLoginClient(session, BASE, "chrome131", None)
        result = await client.login(LINUXDO_OAUTH, self.COOKIE)
        self.assertFalse(result.success)
        self.assertNotIn("https://evil.example/x", session.urls())

    async def test_the_consent_page_is_approved_once(self) -> None:
        approve = "https://connect.linux.do/oauth2/approve/abc123"
        page = FakeResponse(200, '<a href="/oauth2/approve/abc123">允许</a><a href="/oauth2/decline/abc123">拒绝</a>')
        session = self._relay_session(page)
        session.routes[approve] = FakeResponse(
            302, "", headers={"location": f"{BASE}/oauth/linuxdo?code=C&state=st"})
        client = OAuthLoginClient(session, BASE, "chrome131", None)
        result = await client.login(LINUXDO_OAUTH, self.COOKIE)
        self.assertTrue(result.success, result.message)
        click = session.calls_to("/oauth2/approve/abc123")[0]["headers"]
        self.assertEqual(click["Sec-Fetch-Site"], "same-origin")
        self.assertEqual(click["Referer"], self.AGAIN)
        self.assertEqual(session.count_to("/oauth2/decline/abc123"), 0)

    async def test_a_consent_page_that_repeats_is_not_clicked_forever(self) -> None:
        page = FakeResponse(200, '<a href="/oauth2/approve/abc123">允许</a>')
        session = self._relay_session(page)
        session.routes["https://connect.linux.do/oauth2/approve/abc123"] = page
        result = await OAuthLoginClient(session, BASE, "chrome131", None).login(LINUXDO_OAUTH, self.COOKIE)
        self.assertFalse(result.success)
        self.assertEqual(session.count_to("/oauth2/approve/abc123"), 1)


class RefusedAuthorizeTests(LinuxdoAuthorizeHelpers, unittest.IsolatedAsyncioTestCase):
    """A flat refusal is a different failure from a bounce to the login page,
    and conflating them sends the user to re-copy a cookie that is fine."""

    async def test_a_403_does_not_claim_the_cookie_expired(self) -> None:
        result = await self._login(FakeResponse(403, '{"error":"forbidden"}'))
        self.assertFalse(result.success)
        self.assertNotIn("已失效或被拒绝", result.message)
        self.assertIn("403", result.message)

    async def test_a_403_lists_the_plausible_causes(self) -> None:
        result = await self._login(FakeResponse(403, "nope"))
        self.assertIn("尚未在浏览器中授权", result.message)
        self.assertIn("风控", result.message)

    async def test_a_403_quotes_the_site_message(self) -> None:
        """With no Location header the body is the only evidence available."""
        body = "<html><body><h1>Forbidden</h1><p>需要先授权该应用</p></body></html>"
        result = await self._login(FakeResponse(403, body))
        self.assertIn("需要先授权该应用", result.message)

    async def test_html_noise_is_stripped_from_the_quote(self) -> None:
        body = "<html><head><style>a{color:red}</style><script>var x=1;</script></head><body>拒绝</body></html>"
        result = await self._login(FakeResponse(403, body))
        self.assertIn("拒绝", result.message)
        self.assertNotIn("color:red", result.message)
        self.assertNotIn("var x", result.message)

    async def test_a_403_records_the_body_in_the_trace(self) -> None:
        trace: list[dict] = []
        await self._login(FakeResponse(403, '{"error":"forbidden"}'), trace=trace)
        failed = [item for item in trace if item.get("error")]
        self.assertTrue(failed)
        self.assertIn("forbidden", failed[-1]["response_text"])

    async def test_a_missing_cookie_is_listed_first(self) -> None:
        result = await self._login(FakeResponse(403, "nope"), cookie="_t=abc")
        self.assertIn("缺少 _forum_session", result.message)

    async def test_a_login_redirect_still_reads_as_expiry(self) -> None:
        result = await self._login(
            FakeResponse(302, "", headers={"location": "https://connect.linux.do/login"})
        )
        self.assertIn("已失效或被拒绝", result.message)

    async def test_a_login_redirect_records_no_body(self) -> None:
        """There the Location is the evidence; the body is a whole login page."""
        trace: list[dict] = []
        await self._login(
            FakeResponse(302, "<html>login page</html>",
                         headers={"location": "https://connect.linux.do/login"}),
            trace=trace,
        )
        failed = [item for item in trace if item.get("error")]
        self.assertFalse(failed[-1].get("response_text"))

    async def test_the_message_names_the_sso_host(self) -> None:
        """The authorize request goes to connect.linux.do, not the forum."""
        result = await self._login(FakeResponse(403, "nope"))
        self.assertIn("connect.linux.do", result.message)

    async def test_an_error_page_is_quoted_not_guessed_at(self) -> None:
        """What connect.linux.do showed when its SSO callback refused the relay."""
        page = ("<html><head><title>Error - LINUX DO Connect</title><style>p{}</style></head>"
                "<body><h1>Invalid state</h1><p>Please make sure you entered the information correctly.</p></body></html>")
        result = await self._login(FakeResponse(400, page))
        self.assertFalse(result.success)
        self.assertIn("HTTP 400", result.message)
        self.assertIn("Invalid state", result.message)
        self.assertNotIn("p{}", result.message)
        self.assertNotIn("完成一次 OAuth 授权", result.message)


# The page connect.linux.do actually returned, trimmed to its identifying parts.
CLOUDFLARE_PAGE = (
    '<html dir="ltr"> <head> <title>Just a moment...</title> '
    '<meta http-equiv="Content-Type" content="text/html; charset=utf-8"> '
    '<meta name="viewport" content="width=device-width, initial-scale=1"/> '
    '<link rel="icon" href="data:image/svg+xml;base64,PD94bWwg"/> </head> '
    "<body> Enable JavaScript and cookies to continue </body></html>"
)


class CloudflareDetectionTests(unittest.TestCase):
    """A challenge page is not a credential problem, and must not read as one."""

    def test_recognises_the_interstitial_body(self) -> None:
        self.assertTrue(is_cloudflare_challenge(403, CLOUDFLARE_PAGE))

    def test_recognises_the_mitigation_header_alone(self) -> None:
        """A localised page may match no body marker; the header still states it."""
        self.assertTrue(
            is_cloudflare_challenge(403, "denied", {"cf-mitigated": "challenge"})
        )

    def test_recognises_the_challenge_script_path(self) -> None:
        body = '<script src="/cdn-cgi/challenge-platform/h/b/orchestrate/chl_page/v1"></script>'
        self.assertTrue(is_cloudflare_challenge(503, body))

    def test_a_plain_refusal_is_not_a_challenge(self) -> None:
        self.assertFalse(is_cloudflare_challenge(403, "Forbidden: app not authorized"))

    def test_a_success_is_never_a_challenge(self) -> None:
        """Guards against reading a legitimate page that merely quotes the text."""
        self.assertFalse(is_cloudflare_challenge(200, CLOUDFLARE_PAGE))

    def test_unparsable_headers_fall_back_to_the_body(self) -> None:
        class Hostile:
            def get(self, key):
                raise RuntimeError("no mapping here")

        self.assertTrue(is_cloudflare_challenge(403, CLOUDFLARE_PAGE, Hostile()))
        self.assertFalse(is_cloudflare_challenge(403, "plain", Hostile()))


class CloudflareChallengeLoginTests(LinuxdoAuthorizeHelpers, unittest.IsolatedAsyncioTestCase):
    """End-to-end wording for a challenged authorize leg."""

    async def test_does_not_blame_the_credential(self) -> None:
        result = await self._login(FakeResponse(403, CLOUDFLARE_PAGE))
        self.assertFalse(result.success)
        self.assertIn("Cloudflare", result.message)
        # Match the claim, not one phrasing of it — but still the *negated*
        # claim, so a message that blamed the credential could not pass.
        self.assertRegex(result.message, r"(不是|并非|而非)凭据失效")
        # None of the wrong remedies for an expired or incomplete cookie.
        self.assertNotIn("已失效或被拒绝", result.message)
        self.assertNotIn("尚未在浏览器中授权", result.message)

    async def test_names_the_clearance_cookie_and_its_bindings(self) -> None:
        result = await self._login(FakeResponse(403, CLOUDFLARE_PAGE))
        self.assertIn("cf_clearance", result.message)
        # The two things that silently invalidate a copied clearance cookie.
        self.assertIn("IP", result.message)
        self.assertIn("指纹", result.message)

    async def test_points_at_the_ml_dsa_option(self) -> None:
        """chrome131 sends no ML-DSA, the gap Cloudflare challenges; say where to close it."""
        result = await self._login(FakeResponse(403, CLOUDFLARE_PAGE))
        self.assertIn("chrome131", result.message)
        self.assertIn("未携带 ML-DSA", result.message)
        self.assertIn("全局设置", result.message)
        self.assertIn("TLS 携带 ML-DSA", result.message)
        self.assertIn("chrome150", result.message)

    async def test_no_ml_dsa_advice_once_the_handshake_had_it(self) -> None:
        for impersonate, mldsa in (("chrome131", True), ("chrome150", False)):
            session = FakeSession(self._routes(FakeResponse(403, CLOUDFLARE_PAGE)))
            client = OAuthLoginClient(session, BASE, impersonate, None, mldsa=mldsa)
            result = await client.login(LINUXDO_OAUTH, self.COOKIE)
            with self.subTest(impersonate=impersonate, mldsa=mldsa):
                self.assertIn("Cloudflare", result.message)
                self.assertNotIn("未携带 ML-DSA", result.message)

    async def test_reports_when_the_browser_is_unavailable(self) -> None:
        session = FakeSession(self._routes(FakeResponse(403, CLOUDFLARE_PAGE)))
        context = CloudflareContext(CloudflareOptions())
        client = OAuthLoginClient(session, BASE, "chrome131", None, cloudflare=context)
        result = await client.login(LINUXDO_OAUTH, self.COOKIE)
        self.assertFalse(result.success)
        self.assertIn("无头浏览器不可用", result.message)
        self.assertEqual(len(session.calls_to("/oauth2/authorize")), 1)
        self.assertRegex(result.message, r"(不是|并非|而非)凭据失效")

    async def test_offers_the_durable_alternative(self) -> None:
        """A clearance cookie expires long before the next scheduled run."""
        result = await self._login(FakeResponse(403, CLOUDFLARE_PAGE))
        self.assertIn("Github OAuth", result.message)

    async def test_records_the_page_in_the_trace(self) -> None:
        trace: list[dict] = []
        await self._login(FakeResponse(403, CLOUDFLARE_PAGE), trace=trace)
        authorize = [entry for entry in trace if "授权" in entry.get("step", "")][0]
        self.assertIn("Just a moment", authorize.get("response_text", ""))

    async def test_the_clearance_cookie_is_not_demanded_up_front(self) -> None:
        """It is only needed when challenged, so a credential without it is complete."""
        self.assertNotIn("cf_clearance", PROVIDERS[LINUXDO_OAUTH].all_cookies)
        self.assertEqual(_missing_cookies(PROVIDERS[LINUXDO_OAUTH], self.COOKIE), [])

    async def test_a_supplied_clearance_cookie_is_sent_through(self) -> None:
        """Nothing filters the credential, so the user can add it themselves."""
        cookie = f"{self.COOKIE}; cf_clearance=solved-token"
        session = FakeSession(self._routes(FakeResponse(403, CLOUDFLARE_PAGE)))
        client = OAuthLoginClient(session, BASE, "chrome131", None)
        await client.login(LINUXDO_OAUTH, cookie)
        authorize = session.calls_to("/oauth2/authorize")[0]
        self.assertIn("cf_clearance=solved-token", authorize["headers"]["Cookie"])


class MldsaLoginTests(LinuxdoAuthorizeHelpers, unittest.IsolatedAsyncioTestCase):
    """The credential's ML-DSA option covers every leg of its login."""

    REDIRECT = FakeResponse(302, "", headers={"location": f"{BASE}/oauth/linuxdo?code=C&state=st"})

    async def _calls(self, impersonate: str, mldsa: bool) -> list[dict]:
        session = FakeSession(self._routes(self.REDIRECT))
        result = await OAuthLoginClient(session, BASE, impersonate, None, mldsa=mldsa).login(
            LINUXDO_OAUTH, self.COOKIE
        )
        self.assertTrue(result.success, result.message)
        return session.calls

    async def test_every_leg_carries_it_when_asked(self) -> None:
        calls = await self._calls("chrome131", True)
        self.assertEqual(len(calls), 4)
        self.assertTrue(all(carries_mldsa(call) for call in calls))

    async def test_the_vs_pow_challenge_carries_it_too(self) -> None:
        session = FakeSession(self._routes(self.REDIRECT))
        client = OAuthLoginClient(session, BASE, "chrome131", None, mldsa=True, vs_pow=True)
        await client.login(LINUXDO_OAUTH, self.COOKIE)
        self.assertEqual(len(session.calls), 5)
        self.assertTrue(all(carries_mldsa(call) for call in session.calls))

    async def test_no_leg_is_altered_by_default(self) -> None:
        calls = await self._calls("chrome131", False)
        self.assertTrue(all(call["extra_fp"] is None for call in calls))

    async def test_a_fingerprint_that_carries_it_is_left_alone(self) -> None:
        calls = await self._calls("chrome150", True)
        self.assertTrue(all(call["extra_fp"] is None for call in calls))


class AuthorizeFingerprintTests(unittest.IsolatedAsyncioTestCase):
    """The authorize leg has to look like the navigation it claims to be.

    curl_cffi's impersonation already sends Chrome's real Accept, Sec-Ch-Ua and
    Sec-Fetch-* values. Overriding one by hand leaves a header set that
    disagrees with its own User-Agent, which is what bot scoring looks for.
    """

    async def test_does_not_override_the_impersonated_accept(self) -> None:
        session = FakeSession(github_routes())
        await make_client(session).login(GITHUB_OAUTH, "user_session=abc")
        authorize = session.calls_to("/login/oauth/authorize")[0]
        self.assertNotIn("Accept", authorize["headers"])

    async def test_sends_a_consistent_cross_site_navigation(self) -> None:
        """A Referer with Sec-Fetch-Site: none describes an impossible request."""
        session = FakeSession(github_routes())
        await make_client(session).login(GITHUB_OAUTH, "user_session=abc")
        headers = session.calls_to("/login/oauth/authorize")[0]["headers"]
        self.assertEqual(headers["Referer"], f"{BASE}/")
        self.assertEqual(headers["Sec-Fetch-Site"], "cross-site")


if __name__ == "__main__":
    unittest.main()
