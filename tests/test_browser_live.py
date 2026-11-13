"""The browser solver against a local stand-in for a managed challenge, in a real browser.

Skipped when Playwright or a browser it can drive is missing. The stand-in
answers 403 ``cf-mitigated: challenge`` with a page whose script sets
``cf_clearance`` and reloads, which is the shape the solver has to handle;
it says nothing about whether Cloudflare's own challenge passes.
"""

from __future__ import annotations

import asyncio
import tempfile
import time
import unittest
from dataclasses import replace
from pathlib import Path
from unittest import mock

import tests  # noqa: F401
from core import browser as browser_module
from core.browser import (
    BrowserOptions,
    BrowserRequest,
    BrowserSolver,
    BrowserUnavailable,
    playwright_installed,
)
from core.cloudflare import CloudflareContext
from core.oauth import LINUXDO_OAUTH, PROVIDERS, OAuthLoginClient
from core.storage import DatabaseManager
from tests.fakes import FakeResponse, FakeSession, pow_proof


try:
    from aiohttp import web
except ImportError:  # pragma: no cover
    web = None

CHALLENGE = """<html><head><title>Just a moment...</title></head><body>
<script>window._cf_chl_opt = {cType: 'managed'};
setTimeout(() => { document.cookie = 'cf_clearance=ok; path=/'; location.reload(); }, 800);</script>
</body></html>"""
STATION = "127.0.0.2"
# A provider zone of two hosts, as linux.do and connect.linux.do are; Chrome
# resolves every *.localhost name to this machine.
ZONE = "zone.localhost"
# An interactive challenge: nothing happens until the checkbox in the widget,
# a cross-site frame, is clicked by a trusted hand.
INTERACTIVE = """<html><head><title>Just a moment...</title></head><body>
<script>window._cf_chl_opt = {cType: 'managed'};
addEventListener('message', e => { document.cookie = 'cf_clearance=ok; path=/';
  document.cookie = 'moves=' + e.data + '; path=/'; location.reload(); });</script>
<div style="height:180px"></div><iframe src="http://%s:%d/widget" style="width:300px;height:65px;border:0"></iframe>
</body></html>"""
WIDGET = """<html><body style="margin:0">
<label style="display:flex;align-items:center;margin:20px 9px"><input type="checkbox" id="cb">Verify you are human</label>
<script>let moves = 0; addEventListener('mousemove', () => moves++);
document.getElementById('cb').addEventListener('click', e => { if (e.isTrusted) parent.postMessage(moves, '*'); });</script>
</body></html>"""
# A page with a site's own Turnstile widget on it: ticking the box has the
# widget hand the page a token, as Cloudflare's script does.
TURNSTILE = """<html><body><input type="hidden" name="cf-turnstile-response">
<script>addEventListener('message', e => {
  document.querySelector('[name="cf-turnstile-response"]').value = '{sitekey}.' + location.pathname + '.' + (e.data > 3);
});</script>
<div style="height:180px"></div><iframe src="http://widget.test/widget" style="width:300px;height:65px;border:0"></iframe>
</body></html>"""
# Measured by a challenge page once laid out (a window's outer size reads 0
# while its first document parses, headed too) and written into a cookie, so
# it comes back with the response.
GEOMETRY = """<html><head><title>Just a moment...</title></head><body><div style="height:3000px"></div><script>
setTimeout(() => {
  document.cookie = 'geometry=' + [innerWidth, outerWidth, innerHeight, outerHeight,
    innerWidth - document.documentElement.clientWidth, screen.width, screen.availHeight, screen.height].join('_') + '; path=/';
  document.cookie = 'cf_clearance=ok; path=/'; location.reload();
}, 300);
</script></body></html>"""


@unittest.skipUnless(playwright_installed() and web is not None, "Playwright or aiohttp is not installed")
class LiveBrowserTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        # These requests stay on loopback, regardless of the user's proxy.
        proxy_patch = mock.patch.object(
            browser_module, "_proxy_settings", return_value=None
        )
        proxy_patch.start()
        self.addCleanup(proxy_patch.stop)
        self.hits: list[tuple] = []
        self.proofs: list[tuple] = []
        app = web.Application()
        app.add_routes(
            [
                web.get("/oauth2/authorize", self.authorize),
                web.get("/hop", self.hop),
                web.get("/login", self.login),
                web.get("/oauth/linuxdo", self.callback),
                web.get("/", self.root),
                web.route("*", "/api/user/checkin", self.checkin),
                web.get("/ticked", self.ticked),
                web.get("/widget", self.widget),
                web.get("/geometry", self.geometry),
                web.get("/console/personal", self.console),
                web.get("/relay/authorize", self.relay_authorize),
                web.get("/relay/sso", self.relay_sso),
                web.get("/relay/callback", self.relay_callback),
                web.get("/scoped/authorize", self.scoped_authorize),
                web.get("/scoped/sso", self.scoped_sso),
                web.get("/scoped/callback", self.scoped_callback),
            ]
        )
        self.runner = web.AppRunner(app)
        await self.runner.setup()
        site = web.TCPSite(self.runner, "127.0.0.1", 0)
        await site.start()
        self.port = site._server.sockets[0].getsockname()[1]
        await web.TCPSite(self.runner, STATION, self.port).start()
        self.base = f"http://127.0.0.1:{self.port}"
        self.solver = BrowserSolver(idle_close=0)
        self.options = BrowserOptions(timeout=20)
        try:
            await self.solver.check(self.options)
        except BrowserUnavailable as exc:
            await self.runner.cleanup()
            self.skipTest(str(exc))

    async def asyncTearDown(self) -> None:
        await self.solver.aclose()
        await self.runner.cleanup()

    @staticmethod
    def gate(request: web.Request) -> web.Response | None:
        if request.cookies.get("cf_clearance") == "ok":
            return None
        return web.Response(status=403, text=CHALLENGE, content_type="text/html",
                            headers={"cf-mitigated": "challenge"})

    async def authorize(self, request: web.Request) -> web.Response:
        self.hits.append(("authorize", dict(request.cookies)))
        blocked = self.gate(request)
        if blocked is not None:
            return blocked
        if request.cookies.get("_t") != "tok":
            raise web.HTTPFound("/login")
        response = web.HTTPFound(f"/hop?state={request.query['state']}")
        response.set_cookie("_t", "tok2")
        raise response

    async def hop(self, request: web.Request) -> web.Response:
        raise web.HTTPFound(f"http://{STATION}:{self.port}/oauth/linuxdo?code=CODE&state={request.query['state']}")

    async def login(self, request: web.Request) -> web.Response:
        return web.Response(text="<html>login</html>", content_type="text/html")

    async def callback(self, request: web.Request) -> web.Response:
        self.hits.append(("callback",))
        return web.Response(text="spent the code")

    async def root(self, request: web.Request) -> web.Response:
        # Never challenged: vsllm.cc's rule covers /api/user/checkin alone.
        return web.Response(text="<html>home</html>", content_type="text/html")

    async def checkin(self, request: web.Request) -> web.Response:
        # The gate is Cloudflare's edge, in front of the origin, so it
        # challenges every method; only then does the origin refuse a GET.
        blocked = self.gate(request)
        if blocked is not None:
            return blocked
        self.proofs.append(pow_proof({"headers": request.headers}))
        if request.method != "POST":
            self.hits.append(("solve", dict(request.cookies)))
            return web.json_response({"success": False}, status=405)
        self.hits.append(("checkin", dict(request.cookies), request.headers.get("New-Api-User"), await request.text()))
        response = web.json_response({"success": True})
        response.set_cookie("session", "rotated")
        return response

    async def ticked(self, request: web.Request) -> web.Response:
        if request.cookies.get("cf_clearance") != "ok":
            return web.Response(status=403, text=INTERACTIVE % (STATION, self.port), content_type="text/html",
                                headers={"cf-mitigated": "challenge"})
        self.hits.append(("ticked", int(request.cookies.get("moves", 0))))
        return web.json_response({"success": True})

    async def widget(self, request: web.Request) -> web.Response:
        return web.Response(text=WIDGET, content_type="text/html")

    async def geometry(self, request: web.Request) -> web.Response:
        if request.cookies.get("cf_clearance") != "ok":
            return web.Response(status=403, text=GEOMETRY, content_type="text/html", headers={"cf-mitigated": "challenge"})
        return web.Response(text="<html>measured</html>", content_type="text/html")

    async def console(self, request: web.Request) -> web.Response:
        self.hits.append(("console",))
        return web.Response(text="<html>the station's own page</html>", content_type="text/html")

    @staticmethod
    def first_cookie(request: web.Request, name: str) -> str | None:
        # Of a name sent twice, the first, which is the one connect.linux.do reads.
        for part in request.headers.get("Cookie", "").split(";"):
            key, _, value = part.strip().partition("=")
            if key == name:
                return value
        return None

    async def relay_authorize(self, request: web.Request) -> web.Response:
        """connect.linux.do's authorize: a session it does not honour is
        replaced, and the browser sent round linux.do's SSO to sign it in."""
        self.hits.append(("relay-authorize",))
        state = request.query["state"]
        if self.first_cookie(request, "sess") == "valid":
            raise web.HTTPFound(f"http://{STATION}:{self.port}/oauth/linuxdo?code=CODE&state={state}")
        response = web.HTTPFound(f"http://{ZONE}:{self.port}/relay/sso?state={state}")
        response.set_cookie("sess", "nonce")
        raise response

    async def relay_sso(self, request: web.Request) -> web.Response:
        self.hits.append(("relay-sso",))
        if self.first_cookie(request, "_t") != "tok":
            raise web.HTTPFound("/login")
        response = web.HTTPFound(f"http://connect.{ZONE}:{self.port}/relay/callback?state={request.query['state']}")
        response.set_cookie("_t", "tok2")
        raise response

    async def relay_callback(self, request: web.Request) -> web.Response:
        self.hits.append(("relay-callback",))
        if self.first_cookie(request, "sess") != "nonce":
            return web.Response(status=400, text="<html>Invalid state</html>", content_type="text/html")
        response = web.HTTPFound(f"/relay/authorize?state={request.query['state']}")
        response.set_cookie("sess", "valid")
        raise response

    async def scoped_authorize(self, request: web.Request) -> web.Response:
        self.hits.append(("scoped-connect", self.first_cookie(request, "_t")))
        if self.first_cookie(request, "_t") not in ("seed", "connect-session"):
            return web.Response(
                status=403, text="connect rejected another host's cookie"
            )
        response = web.HTTPFound(f"http://{ZONE}:{self.port}/scoped/sso")
        response.set_cookie("_t", "connect-session", path="/scoped")
        raise response

    async def scoped_sso(self, request: web.Request) -> web.Response:
        self.hits.append(("scoped-root", self.first_cookie(request, "_t")))
        if self.first_cookie(request, "_t") not in ("seed", "root-session"):
            return web.Response(status=403, text="root rejected another host's cookie")
        response = web.HTTPFound(f"http://connect.{ZONE}:{self.port}/scoped/callback")
        response.set_cookie("_t", "root-session", path="/scoped")
        raise response

    async def scoped_callback(self, request: web.Request) -> web.Response:
        if self.first_cookie(request, "_t") != "connect-session":
            return web.Response(status=403, text="callback received the wrong cookie")
        raise web.HTTPFound(
            f"http://{STATION}:{self.port}/oauth/linuxdo?code=CODE&state=ST"
        )

    async def test_scoped_provider_cookies_survive_storage_and_a_second_login(
        self,
    ) -> None:
        authorize = f"http://connect.{ZONE}:{self.port}/scoped/authorize"
        provider = replace(PROVIDERS[LINUXDO_OAUTH], authorize_url=authorize)
        with tempfile.TemporaryDirectory() as folder:
            db = DatabaseManager(Path(folder) / "cookies.db")
            db.save_sites(
                [
                    {
                        "id": "s1",
                        "name": "Relay",
                        "type": "new-api",
                        "base_url": self.base,
                        "credentials": [
                            {"id": "c1", "type": "linuxdo_oauth", "value": "_t=seed"}
                        ],
                    }
                ]
            )
            with mock.patch.dict(PROVIDERS, {LINUXDO_OAUTH: provider}):
                for _ in range(2):
                    credential = db.get_sites()[0]["credentials"][0]
                    session = FakeSession(
                        {
                            ("GET", f"{self.base}/api/status"): FakeResponse(
                                200,
                                '{"data":{"linuxdo_oauth":true,"linuxdo_client_id":"cid"}}',
                            ),
                            ("GET", f"{self.base}/api/oauth/state"): FakeResponse(
                                200, '{"data":"ST"}'
                            ),
                            ("GET", authorize): FakeResponse(
                                403, CHALLENGE, headers={"cf-mitigated": "challenge"}
                            ),
                            ("GET", f"{self.base}/api/oauth/linuxdo"): FakeResponse(
                                200, "{}", cookies={"session": "fresh"}
                            ),
                        }
                    )
                    client = OAuthLoginClient(
                        session,
                        self.base,
                        "chrome131",
                        cloudflare=CloudflareContext(browser=self.solver),
                    )
                    result = await client.login(
                        LINUXDO_OAUTH,
                        credential["value"],
                        credential["provider_cookies"],
                    )
                    self.assertTrue(result.success, result.message)
                    db.update_credential_value(
                        "s1",
                        "c1",
                        result.rotated_provider_cookie or credential["value"],
                        provider_cookies=result.provider_cookies,
                    )
            scoped = {
                (c["domain"], c["path"]): c["value"]
                for c in db.get_sites()[0]["credentials"][0]["provider_cookies"]
            }
            self.assertEqual(scoped[(f"connect.{ZONE}", "/scoped")], "connect-session")
            self.assertEqual(scoped[(ZONE, "/scoped")], "root-session")
            self.assertEqual(
                self.hits,
                [
                    ("scoped-connect", "seed"),
                    ("scoped-root", "seed"),
                    ("scoped-connect", "connect-session"),
                    ("scoped-root", "root-session"),
                ],
            )

    async def test_navigation_solves_the_challenge_and_stops_before_the_station(self) -> None:
        outcome = await self.solver.request(BrowserRequest(
            "GET", f"{self.base}/oauth2/authorize?client_id=c&state=ST",
            {"Cookie": "_t=tok; _forum_session=fs"}, navigate=True,
        ), self.options)
        response = outcome.response
        self.assertTrue(outcome.solved)
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.headers["location"], f"http://{STATION}:{self.port}/oauth/linuxdo?code=CODE&state=ST")
        self.assertEqual(response.cookies["_t"], "tok2")
        self.assertNotIn(("callback",), self.hits)
        self.assertEqual([c["name"] for c in outcome.clearance], ["cf_clearance"])

        # The clearance spares the next request the challenge.
        again = await self.solver.request(BrowserRequest(
            "GET", f"{self.base}/oauth2/authorize?client_id=c&state=S2", {"Cookie": "_t=bad"}, navigate=True,
        ), self.options, outcome.clearance)
        self.assertFalse(again.solved)
        self.assertEqual(again.response.status_code, 302)
        self.assertEqual(again.response.headers["location"], f"{self.base}/login")

    async def test_a_session_set_on_the_relay_replaces_the_pasted_one(self) -> None:
        """A stale pasted session must not shadow the one the relay sets: the
        callback would read the stale one first and refuse the state."""
        outcome = await self.solver.request(BrowserRequest(
            "GET", f"http://connect.{ZONE}:{self.port}/relay/authorize?state=ST",
            {"Cookie": "_t=tok; sess=stale"}, navigate=True,
        ), self.options)
        response = outcome.response
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.headers["location"], f"http://{STATION}:{self.port}/oauth/linuxdo?code=CODE&state=ST")
        self.assertEqual(self.hits, [("relay-authorize",), ("relay-sso",), ("relay-callback",), ("relay-authorize",)])
        # What the run writes back: the values the provider set, not the pasted ones.
        self.assertEqual(response.cookies["sess"], "valid")
        self.assertEqual(response.cookies["_t"], "tok2")

    async def test_an_api_call_is_made_with_fetch_after_the_challenge(self) -> None:
        """A POST to a path the rule covers alone: the challenge is met on that
        path, not on the root, and without the user's credentials."""
        outcome = await self.solver.request(BrowserRequest(
            "POST", f"{self.base}/api/user/checkin",
            {"Cookie": "session=abc", "New-Api-User": "7", "Content-Type": "application/json",
             "Referer": f"{self.base}/console", "Sec-Fetch-Site": "same-origin"},
            body='{"a":1}',
        ), self.options)
        self.assertTrue(outcome.solved)
        self.assertEqual(outcome.response.status_code, 200)
        self.assertEqual(outcome.response.cookies.get("session"), "rotated")
        self.assertEqual(self.hits, [
            ("solve", {"cf_clearance": "ok"}),
            ("checkin", {"cf_clearance": "ok", "session": "abc"}, "7", '{"a":1}'),
        ])

    async def test_a_proof_of_work_reaches_only_the_real_call(self) -> None:
        """A proof works once, so the solving navigation must not spend it."""
        outcome = await self.solver.request(BrowserRequest(
            "POST", f"{self.base}/api/user/checkin", {"X-Pow-Token": "tok", "X-Pow-Nonce": "4600"},
        ), self.options)
        self.assertEqual(outcome.response.status_code, 200)
        self.assertEqual(self.proofs, [(None, None), ("tok", "4600")])

    async def test_an_interactive_challenge_has_its_checkbox_ticked(self) -> None:
        # The stand-in widget is served from the station's address rather than Cloudflare's.
        with mock.patch.object(browser_module, "_CHALLENGE_HOST_SUFFIXES", (STATION,)):
            outcome = await self.solver.request(BrowserRequest("GET", f"{self.base}/ticked"), self.options)
        self.assertTrue(outcome.solved)
        self.assertEqual(outcome.response.status_code, 200)
        # Reached by the solving navigation and again by the fetch() after it.
        self.assertEqual({name for name, _ in self.hits}, {"ticked"})
        # The pointer travelled across the widget, not teleported onto the box.
        self.assertGreater(self.hits[-1][1], 3)

    async def test_a_turnstile_widget_issues_a_token_without_contacting_the_site(self) -> None:
        # A page the browser answers itself counts as public, and Chrome keeps
        # public pages from framing this machine, so the stand-in widget is
        # answered in the browser too, under a host of its own.
        new_context = self.solver._browser.new_context

        async def with_widget(**options: object) -> object:
            context = await new_context(**options)
            await context.route(
                "http://widget.test/widget",
                lambda route: route.fulfill(status=200, content_type="text/html", body=WIDGET),
            )
            return context

        with mock.patch.object(browser_module, "_CHALLENGE_HOST_SUFFIXES", ("widget.test",)), \
                mock.patch.object(browser_module, "_TURNSTILE_PAGE", TURNSTILE), \
                mock.patch.object(self.solver._browser, "new_context", with_widget):
            token, label = await self.solver.turnstile_token(
                f"{self.base}/console/personal", '0x"KEY', self.options
            )
        # Issued on the site's own address, to a pointer that travelled there.
        self.assertEqual(token, "0x&quot;KEY./console/personal.true")
        self.assertTrue(label)
        self.assertEqual(self.hits, [])

    async def test_a_widget_that_issues_nothing_times_out_empty(self) -> None:
        with mock.patch.object(browser_module, "_TURNSTILE_PAGE", "<html><body>no widget</body></html>"):
            token, _ = await self.solver.turnstile_token(
                f"{self.base}/console/personal", "0xKEY", BrowserOptions(timeout=2)
            )
        self.assertEqual(token, "")

    async def test_a_browser_command_that_stalls_ends_with_the_timeout(self) -> None:
        async def never(page: object) -> bool:
            await asyncio.Event().wait()
            return False

        started = time.monotonic()
        with mock.patch.object(browser_module, "_TURNSTILE_PAGE", "<html><body>no widget</body></html>"), \
                mock.patch.object(browser_module, "_press_checkbox", never):
            token, _ = await self.solver.turnstile_token(
                f"{self.base}/console/personal", "0xKEY", BrowserOptions(timeout=2)
            )
        self.assertEqual(token, "")
        self.assertLess(time.monotonic() - started, 10)

    async def test_the_window_looks_like_a_desktop_window(self) -> None:
        outcome = await self.solver.request(BrowserRequest("GET", f"{self.base}/geometry"), self.options)
        inner_w, outer_w, inner_h, outer_h, scrollbar, screen_w, avail_h, screen_h = map(
            int, outcome.response.cookies["geometry"].split("_"))
        self.assertLess(inner_h, outer_h)
        self.assertLessEqual(inner_w, outer_w)
        self.assertGreater(scrollbar, 0)
        self.assertLess(outer_w, screen_w)
        self.assertLess(avail_h, screen_h)


if __name__ == "__main__":
    unittest.main()
