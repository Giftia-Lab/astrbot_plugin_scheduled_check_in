"""Tests for the dashboard's site test and probe endpoints in main.py.

The dashboard posts back its own copy of a site, and that copy never carries a
login's station secrets. These tests drive the real handlers to pin that the
stored secrets are used instead: without them a connection test logs in, which
on login-as-check-in stations spends the day's sign-in.

main.py imports the AstrBot runtime at module scope, which the test process
does not have, so the few AstrBot names it uses are stubbed while it loads.
Everything beneath the web layer — storage, adapters, the OAuth client — is real.
"""

from __future__ import annotations

import contextlib
import importlib
import json
import sys
import tempfile
import types
import unittest
from pathlib import Path
from typing import Any
from unittest import mock

import tests  # noqa: F401
from tests.fakes import FakeResponse, FakeSession

PLUGIN_DIR = Path(__file__).resolve().parent.parent
BASE = "https://relay.example.com"

# Every leg of a GitHub login. A test that sees any of them requested logged in.
LOGIN_ROUTES = {
    ("GET", f"{BASE}/api/status"): FakeResponse(
        200, '{"data":{"github_oauth":true,"github_client_id":"cid"}}'
    ),
    ("POST", f"{BASE}/api/oauth/state"): FakeResponse(200, '{"data":{"flow_token":"f"}}'),
    ("GET", "https://github.com/login/oauth/authorize"): FakeResponse(
        302, "", headers={"location": f"{BASE}/cb?code=C&state=f"}
    ),
    ("GET", f"{BASE}/api/oauth/github"): FakeResponse(200, "{}", cookies={"session": "fresh"}),
}


class _Request:
    """Stands in for AstrBot's request proxy; ``body`` is what was posted."""

    body: Any = None

    async def json(self) -> Any:
        return self.body


class _Context:
    """Accepts the plugin's route registrations and nothing else."""

    def register_web_api(self, **_route: Any) -> None:
        pass


def _astrbot_stubs() -> dict[str, types.ModuleType]:
    """Build the AstrBot modules main.py imports, reduced to the names it uses."""

    def passthrough(*_args: Any, **_kwargs: Any) -> Any:
        return lambda target: target

    class Star:
        def __init__(self, context: Any, config: Any = None) -> None:
            self.context = context

    modules = {
        name: types.ModuleType(name)
        for name in (
            "astrbot",
            "astrbot.api",
            "astrbot.api.event",
            "astrbot.api.star",
            "astrbot.api.web",
            "astrbot.core",
            "astrbot.core.utils",
            "astrbot.core.utils.astrbot_path",
        )
    }
    event = modules["astrbot.api.event"]
    event.AstrMessageEvent = event.MessageChain = event.MessageEventResult = object
    event.filter = types.SimpleNamespace(
        command=passthrough,
        permission_type=passthrough,
        PermissionType=types.SimpleNamespace(ADMIN="admin"),
    )
    star = modules["astrbot.api.star"]
    star.Context, star.Star, star.register = object, Star, passthrough
    web = modules["astrbot.api.web"]
    web.request = _Request()
    web.json_response = lambda data=None: {"status": "ok", "data": data}
    web.error_response = lambda message="", data=None: {"status": "error", "message": message}
    web.file_response = lambda *_args, **_kwargs: None
    modules["astrbot.core.utils.astrbot_path"].get_astrbot_plugin_data_path = tempfile.gettempdir
    return modules


def _load_main() -> types.ModuleType:
    """Import main.py as a package module, with AstrBot stubbed while it loads.

    Only the stubs are withdrawn afterwards. The plugin's own modules stay
    registered, so an import one of them makes later still resolves.
    """
    package = types.ModuleType("_checkin_plugin")
    package.__path__ = [str(PLUGIN_DIR)]
    sys.modules["_checkin_plugin"] = package
    stubs = {name: module for name, module in _astrbot_stubs().items() if name not in sys.modules}
    sys.modules.update(stubs)
    try:
        return importlib.import_module("_checkin_plugin.main")
    finally:
        for name in stubs:
            del sys.modules[name]


main = _load_main()


@contextlib.asynccontextmanager
async def _serving(session: FakeSession):
    """Stand-in for create_client_session that hands out ``session``."""
    yield session


class SiteEndpointTests(unittest.IsolatedAsyncioTestCase):
    """The site test and probe endpoints, fed what the dashboard really sends."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        with mock.patch.object(main, "get_astrbot_plugin_data_path", return_value=self.temp_dir.name):
            self.plugin = main.ScheduledCheckInPlugin(_Context())
        self.db = self.plugin.db

    def tearDown(self) -> None:
        try:
            self.temp_dir.cleanup()
        except OSError:
            # Windows keeps WAL sidecar files briefly locked; the test is done.
            pass

    def _save_oauth_site(self, **credential: Any) -> None:
        """Store a login-as-check-in station whose GitHub login already ran."""
        self.db.save_sites([
            {
                "id": "site_1",
                "name": "Relay",
                "type": "new-api",
                "base_url": BASE,
                "credentials": [
                    {"id": "gh", "type": "github_oauth", "value": "user_session=gh", **credential}
                ],
                "checkin": {"protocol": "oauth"},
                "balance": {},
                "enabled": True,
            }
        ])

    def _editor_form(self, **balance: Any) -> dict:
        """The saved site as buildSitePayloadFromForm posts it from the editor.

        An untouched OAuth cookie is left out, and no station secret is known.
        """
        site = self.plugin.get_sites_for_display()[0]
        return {
            "id": site["id"],
            "name": site["name"],
            "type": site["type"],
            "base_url": site["base_url"],
            "proxy": site["proxy"],
            "credentials": [{"id": "gh", "type": "github_oauth", "label": "", "tls_mldsa": False}],
            "checkin": site["checkin"],
            "balance": {**site["balance"], **balance},
            "enabled": site["enabled"],
        }

    async def _post(self, handler: Any, body: dict, session: FakeSession) -> dict:
        """Call one endpoint with ``body`` as the posted JSON, against ``session``."""
        main.request.body = body
        with mock.patch.object(main, "create_client_session", lambda _settings=None: _serving(session)):
            return await handler()

    async def test_a_connection_test_reuses_the_stored_session(self) -> None:
        """testSingleSite posts the display view; testing must not sign in."""
        self._save_oauth_site(session_cookie="session=live")
        session = FakeSession({
            **LOGIN_ROUTES,
            ("GET", f"{BASE}/api/user/self"): FakeResponse(
                200, json.dumps({"success": True, "data": {"quota": 1500000}})
            ),
        })

        response = await self._post(
            self.plugin.api_test_site, self.plugin.get_sites_for_display()[0], session
        )

        self.assertTrue(response["data"]["success"], response)
        self.assertEqual(response["data"]["total_quota"], 3.0)
        self.assertEqual(session.urls(), [f"{BASE}/api/user/self"])
        self.assertEqual(session.calls[0]["headers"]["Cookie"], "session=live")

    async def test_a_probe_sees_the_stored_session(self) -> None:
        """Without it the probe would claim a login is needed first."""
        self._save_oauth_site(session_cookie="session=live")
        session = FakeSession(LOGIN_ROUTES)

        response = await self._post(self.plugin.api_probe_new_api_user, self._editor_form(), session)

        self.assertIn("无需手动获取", response["message"])
        self.assertEqual(session.calls, [])

    async def test_a_token_refreshed_during_a_probe_is_kept(self) -> None:
        """The refresh retires the refresh cookie it presents, so losing its
        replacement would get the session revoked on the next run."""
        self._save_oauth_site(
            session_cookie="new_api_refresh=r1",
            access_token="at-old",
            access_expires_at=1_000_000_000,  # long expired
        )
        refreshed = {"access_token": "at-new", "access_expires_at": 4102444800, "user": {"id": 2259}}
        session = FakeSession({
            **LOGIN_ROUTES,
            ("POST", f"{BASE}/api/user/auth/refresh"): FakeResponse(
                200, json.dumps({"success": True, "data": refreshed}), cookies={"new_api_refresh": "r2"}
            ),
        })
        form = self._editor_form(headers=[{"key": "X-Draft", "value": "1"}])

        await self._post(self.plugin.api_probe_new_api_user, form, session)

        self.assertEqual(session.urls(), [f"{BASE}/api/user/auth/refresh"])
        self.assertEqual(session.calls[0]["headers"]["Cookie"], "new_api_refresh=r1")
        stored = self.db.get_sites()[0]
        credential = stored["credentials"][0]
        self.assertEqual(credential["session_cookie"], "new_api_refresh=r2")
        self.assertEqual((credential["access_token"], credential["access_expires_at"]), ("at-new", 4102444800))
        # The form was never saved, so none of its headers may reach storage.
        self.assertEqual(stored["balance"]["headers"], [])


class TaskEndpointTests(SiteEndpointTests):
    """Saving, previewing and running scheduled tasks through the web API."""

    TASK = {"id": "t1", "name": "保活", "schedule": "cron", "cron": "*/30 * * * *", "method": "GET", "url": "/api/ping"}

    def _site(self, **task: Any) -> dict:
        return {
            "id": "site_1",
            "name": "Relay",
            "type": "new-api",
            "base_url": BASE,
            "credentials": [{"id": "c1", "type": "token", "value": "sk-a"}],
            "checkin": {},
            "balance": {},
            "tasks": [{**self.TASK, **task}],
            "enabled": True,
        }

    async def test_an_invalid_task_is_refused_and_nothing_saved(self) -> None:
        main.request.body = [self._site(cron="61 * * * *")]
        response = await self.plugin.api_save_sites()
        self.assertEqual(response["status"], "error")
        self.assertIn("保活", response["message"])
        self.assertEqual(self.db.get_sites(), [])

    async def test_a_saved_task_is_scheduled_at_once(self) -> None:
        main.request.body = [self._site()]
        response = await self.plugin.api_save_sites()
        self.assertEqual(response["status"], "ok")
        state = self.db.get_task_states()[("site_1", "t1")]
        self.assertTrue(state["next_run_at"])

    async def test_an_invalid_pow_purpose_does_not_replace_saved_sites(self) -> None:
        self.db.save_sites([self._site(pow_purpose="checkin")])
        saved = self.db.get_sites()
        for purpose in ("!!!", "中文", "  !!!  "):
            with self.subTest(purpose=purpose):
                main.request.body = [self._site(pow_purpose=purpose)]
                response = await self.plugin.api_save_sites()
                self.assertEqual(response["status"], "error")
                self.assertIn("PoW", response["message"])
                self.assertEqual(self.db.get_sites(), saved)

    async def test_a_valid_pow_purpose_is_normalized_when_saved(self) -> None:
        main.request.body = [self._site(pow_purpose=" CheckIn ")]
        response = await self.plugin.api_save_sites()
        self.assertEqual(response["status"], "ok")
        self.assertEqual(self.db.get_sites()[0]["tasks"][0]["pow_purpose"], "checkin")

    async def test_preview(self) -> None:
        main.request.body = {"schedule": "cron", "cron": "0 8 * * 1-5"}
        data = (await self.plugin.api_preview_task_schedule())["data"]
        self.assertEqual((len(data["runs"]), data["error"]), (3, ""))
        main.request.body = {"schedule": "cron", "cron": "0 8 *"}
        self.assertIn("5 个字段", (await self.plugin.api_preview_task_schedule())["data"]["error"])

    async def test_run_now_uses_the_unsaved_form(self) -> None:
        main.request.body = [self._site()]
        await self.plugin.api_save_sites()
        session = FakeSession({("POST", f"{BASE}/api/other"): FakeResponse(200, '{"message":"pong"}')})
        body = {"site": self._site(method="POST", url="/api/other", body='{"a":1}'), "task_id": "t1"}
        # The plugin's own copy of the module: main.py is loaded as a package.
        scheduler_module = sys.modules[type(self.plugin.task_scheduler).__module__]
        with mock.patch.object(scheduler_module, "create_client_session", lambda _settings=None: _serving(session)), \
                mock.patch.object(self.plugin, "record_history") as record:
            main.request.body = body
            response = await self.plugin.api_run_site_task()
        data = response["data"]
        self.assertTrue(data["result"]["success"], data)
        self.assertEqual(session.calls[0]["data"], b'{"a":1}')
        self.assertIs(data["state"]["last_success"], True)
        record.assert_called_once()
        self.assertEqual(record.call_args.kwargs, {"log_type": "task", "manual": True})

    async def test_run_now_refuses_an_unknown_task(self) -> None:
        main.request.body = {"site": self._site(), "task_id": "nope"}
        self.assertEqual((await self.plugin.api_run_site_task())["status"], "error")


if __name__ == "__main__":
    unittest.main()
