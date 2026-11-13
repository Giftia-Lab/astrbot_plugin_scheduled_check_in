"""Tests for the headless-browser fallback past a Cloudflare managed challenge."""

from __future__ import annotations

import json
import sys
import types
import unittest
from typing import Any
from unittest import mock

import tests  # noqa: F401
from core import browser as browser_module
from core.adapters import create_adapter
from core.browser import (
    BrowserOptions,
    BrowserOutcome,
    BrowserRequest,
    BrowserResponse,
    BrowserSolver,
    BrowserUnavailable,
    _cookie_specs,
    _proxy_settings,
    _site_cookies,
    _zone,
    normalize_channel,
    normalize_timeout,
)
from core.cloudflare import (
    CloudflareContext,
    CloudflareOptions,
    normalize_cloudflare_settings,
)
from core.oauth import LINUXDO_OAUTH, OAuthLoginClient
from tests.fakes import POW_NONCE, FakeResponse, FakeSession, pow_challenge, pow_proof

BASE = "https://relay.example.com"
AUTHORIZE = "https://connect.linux.do/oauth2/authorize"
CHALLENGE_BODY = (
    "<html><head><title>Just a moment...</title></head><body>"
    "<script>window._cf_chl_opt = {cType: 'managed'};</script></body></html>"
)
CLEARANCE = [{"name": "cf_clearance", "value": "cl", "domain": ".linux.do", "path": "/"}]


def challenge() -> FakeResponse:
    return FakeResponse(403, CHALLENGE_BODY, headers={"cf-mitigated": "challenge"})


class FakeBrowser:
    """Stands in for BrowserSolver, answering from a queue."""

    def __init__(self, *answers: Any) -> None:
        self.answers = list(answers)
        self.calls: list[tuple[BrowserRequest, BrowserOptions, list]] = []
        # What the Turnstile widget hands out, and the widgets asked for one.
        self.token: Any = "tok"
        self.widgets: list[tuple[str, str, str | None]] = []

    async def request(self, request: BrowserRequest, options: BrowserOptions, clearance: Any = ()) -> BrowserOutcome:
        self.calls.append((request, options, list(clearance)))
        answer = self.answers.pop(0) if self.answers else BrowserResponse(200, "ok")
        if isinstance(answer, Exception):
            raise answer
        return BrowserOutcome(answer, CLEARANCE, "Chrome 153", 4.2, solved=True)

    async def turnstile_token(
        self, url: str, sitekey: str, options: BrowserOptions, proxy: str | None = None
    ) -> tuple[str, str]:
        self.widgets.append((url, sitekey, proxy))
        if isinstance(self.token, Exception):
            raise self.token
        return self.token, "Chrome 153"


def context(browser: Any, **options: Any) -> CloudflareContext:
    return CloudflareContext(CloudflareOptions(**options), browser=browser)


class Trace:
    def __init__(self) -> None:
        self.entries: list[dict[str, Any]] = []

    def __call__(self, step: str, method: str, url: str, **fields: Any) -> None:
        self.entries.append({"step": step, "method": method, "url": url, **fields})

    def browser_entries(self) -> list[dict[str, Any]]:
        return [e for e in self.entries if e["step"] == "Cloudflare 无头浏览器"]


async def resolve(ctx: CloudflareContext, trace: Trace | None = None, *, url: str = AUTHORIZE,
                  request: BrowserRequest | None = None, response: Any = None) -> Any:
    return await ctx.resolve(
        response=response if response is not None else challenge(),
        record=trace,
        browser_request=request or BrowserRequest("GET", url),
    )


# ----------------------------------------------------------------------
# Helpers and settings
# ----------------------------------------------------------------------
class HelperTests(unittest.TestCase):
    def test_zone_is_the_registrable_domain(self) -> None:
        self.assertEqual(_zone("connect.linux.do"), "linux.do")
        self.assertEqual(_zone("github.com"), "github.com")
        self.assertEqual(_zone("a.b.example.co.uk"), "example.co.uk")
        self.assertEqual(_zone("api.example.com.cn"), "example.com.cn")
        self.assertEqual(_zone("127.0.0.1"), "127.0.0.1")

    def test_provider_cookies_go_on_the_host_and_its_domain_host_only(self) -> None:
        specs = _cookie_specs(AUTHORIZE, [("_t", "a"), ("__Host-x", "b"), ("cf_clearance", "c")], zone_wide=True)
        self.assertEqual(specs, [
            # Host-only, so a value the site sets on either host replaces it.
            {"name": "_t", "value": "a", "url": "https://connect.linux.do/"},
            {"name": "_t", "value": "a", "url": "https://linux.do/"},
            {"name": "__Host-x", "value": "b", "url": "https://connect.linux.do/"},
            # Where Cloudflare itself puts its cookies.
            {"name": "cf_clearance", "value": "c", "domain": ".linux.do", "path": "/", "secure": True},
        ])
        station = _cookie_specs(f"{BASE}/api/x", [("session", "s"), ("cf_clearance", "c")], zone_wide=False)
        self.assertEqual(station, [
            {"name": "session", "value": "s", "url": f"{BASE}/"},
            {"name": "cf_clearance", "value": "c", "url": f"{BASE}/"},
        ])

    def test_a_cookie_the_site_set_wins_over_the_pasted_one(self) -> None:
        pasted = {"_t": "old", "sid": "old"}
        jar = [
            {"name": "_t", "value": "old"}, {"name": "_t", "value": "rotated"},
            {"name": "sid", "value": "fresh"}, {"name": "sid", "value": "old"},
            {"name": "_cfuvid", "value": "u"},
        ]
        self.assertEqual(_site_cookies(jar, pasted), {"_t": "rotated", "sid": "fresh", "_cfuvid": "u"})

    def test_saved_scopes_override_the_pasted_value_on_both_hosts(self) -> None:
        specs = _cookie_specs(
            AUTHORIZE,
            [("_t", "wrong"), ("other", "legacy")],
            zone_wide=True,
            provider_cookies=[
                {
                    "name": "_t",
                    "value": "connect",
                    "domain": "connect.linux.do",
                    "path": "/",
                },
                {
                    "name": "_t",
                    "value": "root",
                    "domain": "linux.do",
                    "path": "/session",
                },
            ],
        )
        saved = [cookie for cookie in specs if cookie["name"] == "_t"]
        self.assertEqual(
            [(c["value"], c["domain"], c["path"]) for c in saved],
            [("connect", "connect.linux.do", "/"), ("root", "linux.do", "/session")],
        )
        self.assertEqual(len([c for c in specs if c["name"] == "other"]), 2)

    def test_expired_scopes_do_not_resurrect_a_pasted_cookie(self) -> None:
        specs = _cookie_specs(
            AUTHORIZE,
            [("_t", "retired")],
            zone_wide=True,
            provider_cookies=[
                {"name": "_t", "value": "expired", "domain": "linux.do", "expires": 1}
            ],
        )
        self.assertEqual(specs, [])

    def test_proxy_credentials_are_split_out(self) -> None:
        self.assertEqual(
            _proxy_settings("http://u%40x:p@127.0.0.1:7890"),
            {"server": "http://127.0.0.1:7890", "username": "u@x", "password": "p"},
        )
        self.assertEqual(_proxy_settings("socks5h://h:1080"), {"server": "socks5://h:1080"})
        self.assertEqual(_proxy_settings("h:8080"), {"server": "http://h:8080"})

    def test_without_a_site_proxy_the_environment_is_honoured(self) -> None:
        with mock.patch.dict("os.environ", {"HTTPS_PROXY": "http://env:3128"}, clear=True):
            self.assertEqual(_proxy_settings(None), {"server": "http://env:3128"})
        with mock.patch.dict("os.environ", {}, clear=True):
            self.assertIsNone(_proxy_settings(""))

    def test_channel_and_timeout_are_validated(self) -> None:
        self.assertEqual(normalize_channel("Chrome"), "chrome")
        self.assertEqual(normalize_channel("firefox"), "auto")
        self.assertEqual(normalize_timeout("5"), 15.0)
        self.assertEqual(normalize_timeout(9999), 300.0)
        self.assertEqual(normalize_timeout("x"), 60.0)


class OptionTests(unittest.TestCase):
    def test_the_browser_is_on_and_headless_by_default(self) -> None:
        options = CloudflareOptions.from_settings({})
        self.assertTrue(options.browser_fallback)
        self.assertEqual(options.browser, BrowserOptions(headless=True, channel="auto", timeout=60.0))

    def test_normalization_rewrites_the_browser_keys(self) -> None:
        settings = {"cf_browser_fallback": "off", "cf_browser_headless": "0",
                    "cf_browser_channel": "EDGE", "cf_browser_timeout_seconds": "90"}
        normalize_cloudflare_settings(settings)
        self.assertEqual(settings, {
            "cf_browser_fallback": False, "cf_browser_headless": False,
            "cf_browser_channel": "auto", "cf_browser_timeout_seconds": 90,
        })

    def test_storage_defaults_carry_the_options(self) -> None:
        from core.storage import DEFAULT_SETTINGS

        self.assertIs(DEFAULT_SETTINGS["cf_browser_fallback"], True)
        self.assertEqual(DEFAULT_SETTINGS["cf_browser_channel"], "auto")


class UnavailableTests(unittest.IsolatedAsyncioTestCase):
    async def test_without_playwright_the_solver_says_how_to_install_it(self) -> None:
        with mock.patch.object(browser_module, "load_playwright", lambda: None):
            with self.assertRaises(BrowserUnavailable) as caught:
                await BrowserSolver().request(BrowserRequest("GET", AUTHORIZE), BrowserOptions())
        self.assertIn("pip install playwright", str(caught.exception))
        self.assertIn("一键安装", str(caught.exception))

    def test_a_package_installed_later_is_picked_up(self) -> None:
        # The module was imported without Playwright; an install since then
        # must be found without restarting the process.
        entry = object()
        fake = types.ModuleType("playwright.async_api")
        fake.async_playwright = entry
        with mock.patch.object(browser_module, "async_playwright", None), \
                mock.patch.dict(sys.modules, {"playwright.async_api": fake}):
            self.assertIs(browser_module.load_playwright(), entry)
            self.assertTrue(browser_module.playwright_installed())

    def test_a_broken_install_reports_why(self) -> None:
        with mock.patch.object(browser_module, "async_playwright", None), \
                mock.patch.dict(sys.modules, {"playwright.async_api": None}):
            self.assertIsNone(browser_module.load_playwright())
        self.assertIn("playwright.async_api", browser_module.playwright_import_error())


# ----------------------------------------------------------------------
# The context
# ----------------------------------------------------------------------
class ResolveTests(unittest.IsolatedAsyncioTestCase):
    async def test_the_browser_takes_over_as_soon_as_curl_is_challenged(self) -> None:
        browser, trace = FakeBrowser(BrowserResponse(200, "through")), Trace()
        resolution = await resolve(context(browser), trace)
        self.assertEqual(resolution.response.text, "through")
        self.assertEqual(len(browser.calls), 1)
        self.assertEqual([e["step"] for e in trace.entries], ["Cloudflare 无头浏览器"])
        entry = trace.browser_entries()[0]
        self.assertTrue(entry["success"])
        self.assertIn("Chrome 153 通过人机验证 (HTTP 200)", entry["message"])

    async def test_a_normal_curl_response_never_starts_the_browser(self) -> None:
        browser = FakeBrowser()
        original = FakeResponse(200, "ok")
        resolution = await resolve(context(browser), response=original)
        self.assertIs(resolution.response, original)
        self.assertEqual(browser.calls, [])

    async def test_a_retired_fingerprint_setting_cannot_restore_curl_retries(self) -> None:
        for value in (True, False):
            with self.subTest(value=value):
                browser, trace = FakeBrowser(BrowserResponse(200, "through")), Trace()
                ctx = CloudflareContext(
                    CloudflareOptions.from_settings({"cf_fingerprint_fallback": value}),
                    browser=browser,
                )
                resolution = await resolve(ctx, trace)
                self.assertEqual(resolution.response.text, "through")
                self.assertEqual(len(browser.calls), 1)
                self.assertEqual([e["step"] for e in trace.entries], ["Cloudflare 无头浏览器"])

    async def test_a_disabled_browser_says_so(self) -> None:
        browser = FakeBrowser()
        resolution = await resolve(context(browser, browser_fallback=False))
        self.assertEqual(browser.calls, [])
        self.assertIn("无头浏览器验证已在全局设置中关闭", resolution.detail)

    async def test_without_a_browser_request_the_challenge_is_reported(self) -> None:
        browser = FakeBrowser()
        ctx = context(browser)
        resolution = await ctx.resolve(response=challenge())
        self.assertEqual(resolution.response.status_code, 403)
        self.assertIn("缺少原始请求信息", resolution.detail)
        self.assertEqual(browser.calls, [])

    async def test_the_clearance_is_carried_to_the_next_request_through_the_same_proxy(self) -> None:
        browser = FakeBrowser(BrowserResponse(200, "a"), BrowserResponse(200, "b"), BrowserResponse(200, "c"))
        ctx = context(browser)
        await resolve(ctx, request=BrowserRequest("GET", AUTHORIZE, proxy="http://p:1"))
        await resolve(ctx, request=BrowserRequest("GET", AUTHORIZE, proxy="http://p:1"))
        await resolve(ctx, url=f"{BASE}/x", request=BrowserRequest("GET", f"{BASE}/x"))
        self.assertEqual([call[2] for call in browser.calls], [[], CLEARANCE, []])

    async def test_a_later_challenge_goes_straight_back_to_the_browser(self) -> None:
        browser, trace = FakeBrowser(BrowserResponse(200, "a"), BrowserResponse(200, "b")), Trace()
        ctx = context(browser)
        await resolve(ctx, trace)
        resolution = await resolve(ctx, trace)
        self.assertEqual(resolution.response.text, "b")
        self.assertEqual(len(browser.calls), 2)
        self.assertEqual([e["step"] for e in trace.entries], ["Cloudflare 无头浏览器"] * 2)

    async def test_a_failed_challenge_does_not_block_a_later_request(self) -> None:
        browser, trace = FakeBrowser(BrowserResponse(403, CHALLENGE_BODY, {"cf-mitigated": "challenge"})), Trace()
        ctx = context(browser, browser_timeout=30)
        first = await resolve(ctx, trace)
        self.assertEqual(first.response.status_code, 403)
        self.assertIn("30 秒内未能通过人机验证", first.detail)
        self.assertTrue(first.detail.startswith("已自动尝试："))
        second = await resolve(ctx)
        self.assertEqual(len(browser.calls), 2)
        self.assertEqual(second.response.status_code, 200)

    async def test_a_failed_proxy_does_not_block_another_proxy(self) -> None:
        browser = FakeBrowser(
            BrowserResponse(403, CHALLENGE_BODY), BrowserResponse(200, "through")
        )
        ctx = context(browser)
        await resolve(ctx, request=BrowserRequest("GET", AUTHORIZE, proxy="http://a:1"))
        second = await resolve(
            ctx, request=BrowserRequest("GET", AUTHORIZE, proxy="http://b:2")
        )
        self.assertEqual(second.response.text, "through")
        self.assertEqual(
            [call[0].proxy for call in browser.calls], ["http://a:1", "http://b:2"]
        )
        self.assertEqual(browser.calls[1][2], [])

    async def test_a_failed_endpoint_does_not_block_another_endpoint(self) -> None:
        for failure in (
            BrowserResponse(403, CHALLENGE_BODY),
            RuntimeError("connection reset"),
        ):
            with self.subTest(failure=type(failure).__name__):
                browser = FakeBrowser(failure, BrowserResponse(200, "through"))
                ctx = context(browser)
                await resolve(ctx, url=f"{BASE}/api/user/self")
                second = await resolve(
                    ctx,
                    url=f"{BASE}/api/user/checkin",
                    request=BrowserRequest("POST", f"{BASE}/api/user/checkin"),
                )
                self.assertEqual(second.response.text, "through")
                self.assertEqual(len(browser.calls), 2)

    async def test_an_unavailable_browser_is_reported_once_per_run(self) -> None:
        browser, trace = FakeBrowser(BrowserUnavailable("未安装 Playwright（pip install playwright）")), Trace()
        ctx = context(browser)
        first = await resolve(ctx, trace)
        second = await resolve(ctx, url=f"{BASE}/y", request=BrowserRequest("GET", f"{BASE}/y"))
        self.assertEqual(len(browser.calls), 1)
        for resolution in (first, second):
            self.assertIn("无头浏览器不可用", resolution.detail)
            self.assertIn("pip install playwright", resolution.detail)
        self.assertEqual(len(trace.browser_entries()), 1)

    async def test_a_browser_error_is_reported_not_raised(self) -> None:
        trace = Trace()
        resolution = await resolve(context(FakeBrowser(RuntimeError("net::ERR_TIMED_OUT"))), trace)
        self.assertEqual(resolution.response.status_code, 403)
        self.assertIn("无头浏览器请求异常：net::ERR_TIMED_OUT", resolution.detail)
        self.assertEqual(trace.browser_entries()[0]["error"], "net::ERR_TIMED_OUT")


# ----------------------------------------------------------------------
# OAuth and adapters
# ----------------------------------------------------------------------
class OAuthTests(unittest.IsolatedAsyncioTestCase):
    def _session(self) -> FakeSession:
        return FakeSession({
            ("GET", f"{BASE}/api/status"): FakeResponse(
                200, '{"data":{"linuxdo_oauth":true,"linuxdo_client_id":"cid"}}'
            ),
            ("GET", f"{BASE}/api/oauth/state"): FakeResponse(200, '{"data":"st"}'),
            ("GET", AUTHORIZE): challenge(),
            ("GET", f"{BASE}/api/oauth/linuxdo"): FakeResponse(
                200, '{"success":true,"data":{"id":7}}', cookies={"session": "fresh"}
            ),
        })

    async def test_the_authorize_leg_completes_in_the_browser(self) -> None:
        browser = FakeBrowser(BrowserResponse(
            302, "", {"location": f"{BASE}/oauth/linuxdo?code=C&state=st"}, {"_t": "rotated", "cf_clearance": "x"}
        ))
        session = self._session()
        client = OAuthLoginClient(session, BASE, "chrome131", "http://proxy:1",
                                  cloudflare=context(browser))
        result = await client.login(LINUXDO_OAUTH, "_t=a; _forum_session=b")
        self.assertTrue(result.success, result.message)
        self.assertEqual(result.session_cookie, "session=fresh")
        self.assertEqual(result.rotated_provider_cookie, "_t=rotated; _forum_session=b")
        self.assertEqual(len(session.calls_to("/oauth2/authorize")), 1)
        self.assertEqual(len(browser.calls), 1)
        self.assertTrue(browser.calls[0][1].headless)
        # The code went to the station over curl_cffi, not through the browser.
        exchange = session.calls_to("/api/oauth/linuxdo")[-1]
        self.assertEqual(exchange["params"], {"code": "C", "state": "st"})

        request = browser.calls[0][0]
        self.assertTrue(request.navigate)
        self.assertEqual(request.proxy, "http://proxy:1")
        self.assertEqual(request.headers["Cookie"], "_t=a; _forum_session=b")
        self.assertTrue(request.url.startswith(f"{AUTHORIZE}?client_id=cid&state=st"))
        self.assertIn("response_type=code", request.url)

    async def test_a_bounce_to_the_login_page_blames_the_session(self) -> None:
        browser = FakeBrowser(BrowserResponse(302, "", {"location": "https://linux.do/login"}))
        client = OAuthLoginClient(self._session(), BASE, "chrome131", None,
                                  cloudflare=context(browser))
        result = await client.login(LINUXDO_OAUTH, "_t=a; _forum_session=b")
        self.assertFalse(result.success)
        self.assertIn("会话 Cookie", result.message)

    async def test_a_posted_leg_carries_its_json_body(self) -> None:
        session = FakeSession({
            ("GET", f"{BASE}/api/oauth/state"): FakeResponse(404, "not found"),
            ("POST", f"{BASE}/api/oauth/state"): challenge(),
        })
        browser = FakeBrowser(BrowserResponse(200, '{"data":{"flow_token":"ft"}}', cookies={"sid": "1"}))
        client = OAuthLoginClient(session, BASE, "chrome131", None,
                                  cloudflare=context(browser))
        from core.oauth import PROVIDERS

        state, cookie = await client._fetch_flow_token(PROVIDERS[LINUXDO_OAUTH])
        self.assertEqual((state, cookie), ("ft", "sid=1"))
        request = browser.calls[0][0]
        self.assertFalse(request.navigate)
        self.assertEqual(json.loads(request.body), {"provider": "linuxdo", "intent": "login"})


class AdapterTests(unittest.IsolatedAsyncioTestCase):
    async def test_a_check_in_goes_through_the_browser(self) -> None:
        site = {
            "id": "s1", "name": "Relay", "type": "new-api", "base_url": BASE, "proxy": "",
            "credentials": [{"id": "c1", "type": "cookie", "value": "session=abc"}],
            "checkin": {}, "balance": {}, "enabled": True,
        }
        browser = FakeBrowser()
        browser.answers = [
            BrowserResponse(200, json.dumps({"success": True, "data": {"id": 7, "quota": 500000}})),
            BrowserResponse(200, '{"success":true,"message":"签到成功"}'),
            BrowserResponse(200, json.dumps({"success": True, "data": {"id": 7, "quota": 1000000}})),
        ]
        session = FakeSession({}, default=challenge())
        adapter = create_adapter(site, session, None, context(browser))
        result = await adapter.check_in()
        self.assertTrue(result.success, result.message)
        self.assertEqual(len(session.calls), len(browser.calls))
        self.assertEqual(len(session.calls_to("/api/user/checkin")), 1)
        self.assertTrue(all(call["impersonate"] == "chrome131" for call in session.calls))
        methods = [(call[0].method, call[0].url.removeprefix(BASE)) for call in browser.calls]
        self.assertIn(("POST", "/api/user/checkin"), methods)
        self.assertTrue(all("session=abc" in call[0].headers.get("Cookie", "") for call in browser.calls))
        self.assertIn("Cloudflare 无头浏览器", [a["step"] for a in adapter.attempts])
        self.assertNotIn("Cloudflare 指纹轮换", [a["step"] for a in adapter.attempts])


class TurnstileCheckInTests(unittest.IsolatedAsyncioTestCase):
    """New-API's Turnstile check on the check-in, as api.futureppo.top has it on."""

    CHECKIN = f"{BASE}/api/user/checkin"
    REFUSED = '{"message":"Turnstile token 为空","success":false}'

    def _session(self, status: Any = None, with_token: Any = None) -> FakeSession:
        return FakeSession({
            ("GET", f"{BASE}/api/user/self"): FakeResponse(
                200, json.dumps({"success": True, "data": {"id": 7, "quota": 500000}})
            ),
            ("POST", self.CHECKIN): FakeResponse(200, self.REFUSED),
            ("GET", f"{BASE}/api/status"): status or FakeResponse(
                200, '{"success":true,"data":{"turnstile_check":true,"turnstile_site_key":"0xKEY"}}'
            ),
            ("POST", f"{self.CHECKIN}?turnstile=tok"): with_token or FakeResponse(
                200, '{"success":true,"message":"签到成功"}'
            ),
        })

    @staticmethod
    def _site(**overrides: Any) -> dict[str, Any]:
        return {
            "id": "s1", "name": "Relay", "type": "new-api", "base_url": BASE, "proxy": "http://p:1",
            "credentials": [{"id": "c1", "type": "token", "value": "sk-a"}],
            "checkin": {}, "balance": {}, "enabled": True, **overrides,
        }

    async def test_a_refused_check_in_is_sent_again_with_a_token(self) -> None:
        browser, session = FakeBrowser(), self._session()
        result = await create_adapter(self._site(), session, None, context(browser)).check_in()
        self.assertTrue(result.success, result.message)
        self.assertEqual(result.message, "签到成功")
        self.assertEqual(browser.widgets, [(f"{BASE}/console/personal", "0xKEY", "http://p:1")])
        self.assertEqual(
            [call["url"] for call in session.calls if "/checkin" in call["url"]],
            [self.CHECKIN, f"{self.CHECKIN}?turnstile=tok"],
        )
        steps = [attempt["step"] for attempt in result.attempts]
        self.assertEqual(steps[1:5], [
            "签到", "获取 Turnstile 站点密钥", "Turnstile 无头浏览器", "签到（携带 Turnstile token）",
        ])
        # The token stays out of the trace.
        self.assertNotIn("turnstile=tok", json.dumps(result.attempts))

    async def test_a_check_in_that_is_not_refused_never_starts_the_browser(self) -> None:
        browser, session = FakeBrowser(), self._session()
        session.routes[("POST", self.CHECKIN)] = FakeResponse(200, '{"success":true}')
        result = await create_adapter(self._site(), session, None, context(browser)).check_in()
        self.assertTrue(result.success)
        self.assertEqual(browser.widgets, [])
        self.assertEqual(session.count_to("/api/status"), 0)

    async def test_a_token_the_station_refuses_is_not_asked_for_twice(self) -> None:
        refused = FakeResponse(200, '{"message":"Turnstile 校验失败，请刷新重试！","success":false}')
        browser, session = FakeBrowser(), self._session(with_token=refused)
        result = await create_adapter(self._site(), session, None, context(browser)).check_in()
        self.assertFalse(result.success)
        self.assertFalse(result.expired)
        self.assertIn("Turnstile 校验失败", result.message)
        self.assertEqual(len(browser.widgets), 1)

    async def test_why_there_is_no_token_is_reported_without_blaming_the_credential(self) -> None:
        no_key = FakeResponse(200, '{"success":true,"data":{"turnstile_check":true,"turnstile_site_key":""}}')
        timed_out, crashed, missing = FakeBrowser(), FakeBrowser(), FakeBrowser()
        timed_out.token = ""
        crashed.token = RuntimeError("net::ERR_TIMED_OUT")
        missing.token = BrowserUnavailable("未安装 Playwright")
        cases = [
            (context(FakeBrowser()), no_key, "未提供 turnstile_site_key"),
            (context(FakeBrowser(), browser_fallback=False), None, "无头浏览器验证已在全局设置中关闭"),
            (None, None, "未配置浏览器"),
            (context(timed_out, browser_timeout=30), None, "Chrome 153 在 30 秒内未取得 Turnstile token"),
            (context(crashed), None, "无头浏览器请求异常：net::ERR_TIMED_OUT"),
            (context(missing), None, "无头浏览器不可用：未安装 Playwright"),
        ]
        for cloudflare, status, expected in cases:
            with self.subTest(expected=expected):
                session = self._session(status=status)
                result = await create_adapter(self._site(), session, None, cloudflare).check_in()
                self.assertFalse(result.success)
                self.assertFalse(result.expired)
                self.assertIn("站点签到要求 Turnstile 验证，并非凭据失效", result.message)
                self.assertIn(expected, result.message)
                self.assertEqual(session.count_to("/api/user/checkin"), 1)

    async def test_the_token_request_still_carries_a_proof_of_work(self) -> None:
        browser, session = FakeBrowser(), self._session()
        session.routes[("GET", f"{BASE}/api/pow/challenge?purpose=checkin")] = [
            FakeResponse(200, pow_challenge("tok-1")), FakeResponse(200, pow_challenge("tok-2")),
        ]
        site = self._site(vs_pow=True, credentials=[{"id": "c1", "type": "cookie", "value": "session=abc"}])
        result = await create_adapter(site, session, None, context(browser)).check_in()
        self.assertTrue(result.success, result.message)
        self.assertEqual(
            [pow_proof(call) for call in session.calls if "/checkin" in call["url"]],
            [("tok-1", POW_NONCE), ("tok-2", POW_NONCE)],
        )


if __name__ == "__main__":
    unittest.main()
