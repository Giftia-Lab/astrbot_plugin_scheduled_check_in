"""An OAuth login's station cookie is also kept as a Cookie credential of the site."""

from __future__ import annotations

import tempfile
import unittest
from datetime import datetime
from pathlib import Path
from unittest import mock

import tests  # noqa: F401
from core.adapters import SiteWriteback, create_adapter, persist_writeback
from core.site_schema import resolve_action_credential
from core.storage import DatabaseManager
from tests.fakes import FakeResponse, FakeSession

BASE = "https://relay.example.com"
GITHUB = {"id": "gh", "type": "github_oauth", "label": "Github", "value": "user_session=gh"}


def site(*credentials: dict, **extra) -> dict:
    return {
        "id": "s1", "name": "S", "type": "new-api", "base_url": BASE, "enabled": True,
        "credentials": [GITHUB, *credentials], "checkin": {"protocol": "oauth"}, "balance": {},
        **extra,
    }


class UpsertTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db = DatabaseManager(Path(self.temp_dir.name) / "data.db")

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def credentials(self) -> list[dict]:
        return self.db.get_sites()[0]["credentials"]

    def test_a_cookie_credential_is_added_on_the_first_login(self) -> None:
        self.db.save_sites([site()])
        self.assertTrue(self.db.upsert_station_cookie("s1", "gh", "session=one"))
        added = self.credentials()[1]
        self.assertEqual(added["type"], "cookie")
        self.assertEqual(added["value"], "session=one")
        self.assertEqual(added["source_credential_id"], "gh")
        self.assertEqual(added["label"], "Github 登录 Cookie")
        self.assertTrue(added["value_updated_at"])

    def test_later_logins_overwrite_it(self) -> None:
        self.db.save_sites([site()])
        self.db.upsert_station_cookie("s1", "gh", "session=one")
        self.db.upsert_station_cookie("s1", "gh", "session=two")
        cookies = [item for item in self.credentials() if item["type"] == "cookie"]
        self.assertEqual([item["value"] for item in cookies], ["session=two"])

    def test_a_hand_added_cookie_is_overwritten_rather_than_duplicated(self) -> None:
        self.db.save_sites([site({"id": "ck", "type": "cookie", "label": "手填", "value": "session=old"})])
        self.db.upsert_station_cookie("s1", "gh", "session=new")
        cookies = [item for item in self.credentials() if item["type"] == "cookie"]
        self.assertEqual(len(cookies), 1)
        self.assertEqual((cookies[0]["id"], cookies[0]["label"]), ("ck", "手填"))
        self.assertEqual(cookies[0]["value"], "session=new")
        self.assertEqual(cookies[0]["source_credential_id"], "gh")

    def test_each_login_keeps_its_own_cookie(self) -> None:
        linuxdo = {"id": "ld", "type": "linuxdo_oauth", "value": "_t=x"}
        self.db.save_sites([site(linuxdo)])
        self.db.upsert_station_cookie("s1", "gh", "session=g")
        self.db.upsert_station_cookie("s1", "ld", "session=l")
        cookies = {item["source_credential_id"]: item["value"]
                   for item in self.credentials() if item["type"] == "cookie"}
        self.assertEqual(cookies, {"gh": "session=g", "ld": "session=l"})

    def test_nothing_is_written_without_a_usable_cookie(self) -> None:
        self.db.save_sites([site()])
        self.assertFalse(self.db.upsert_station_cookie("s1", "gh", ""))
        # A refresh cookie authenticates nothing by itself.
        self.assertFalse(self.db.upsert_station_cookie("s1", "gh", "new_api_refresh=r; new_api_has_session=1"))
        self.assertFalse(self.db.upsert_station_cookie("s1", "nope", "session=x"))
        self.assertEqual(len(self.credentials()), 1)

    def test_a_dashboard_save_without_the_value_keeps_it(self) -> None:
        """An untouched written-back cookie is omitted on save, like an OAuth provider cookie."""
        self.db.save_sites([site()])
        self.db.upsert_station_cookie("s1", "gh", "session=one")
        posted = self.db.get_sites_for_display()
        cookie = posted[0]["credentials"][1]
        del cookie["value"]
        cookie.pop("source_credential_id")
        self.db.save_sites(posted)
        stored = self.credentials()[1]
        self.assertEqual((stored["value"], stored["source_credential_id"]), ("session=one", "gh"))

    def test_the_dashboard_sees_the_written_back_cookie(self) -> None:
        self.db.save_sites([site()])
        self.db.upsert_station_cookie("s1", "gh", "session=one")
        shown = self.db.get_sites_for_display()[0]["credentials"][1]
        self.assertEqual(shown["value"], "session=one")

    def test_a_cookie_added_while_the_editor_was_open_survives_its_save(self) -> None:
        self.db.save_sites([site()])
        opened = self.db.get_sites_for_display()
        with mock.patch("core.storage.datetime") as clock:
            clock.now.return_value = datetime(2099, 1, 1, 0, 0, 0)
            self.db.upsert_station_cookie("s1", "gh", "session=fresh")
        opened[0]["name"] = "Renamed"
        self.db.save_sites(opened)
        cookies = [item for item in self.credentials() if item["type"] == "cookie"]
        self.assertEqual([item["value"] for item in cookies], ["session=fresh"])
        self.assertEqual(self.db.get_sites()[0]["name"], "Renamed")

    def test_a_written_back_cookie_the_user_deleted_stays_deleted(self) -> None:
        self.db.save_sites([site()])
        self.db.upsert_station_cookie("s1", "gh", "session=one")
        opened = self.db.get_sites_for_display()
        opened[0]["credentials"] = opened[0]["credentials"][:1]
        self.db.save_sites(opened)
        self.assertEqual([item["type"] for item in self.credentials()], ["github_oauth"])

    def test_a_save_without_loaded_at_adds_nothing(self) -> None:
        """An API caller that sends no updated_at gets its list exactly as sent."""
        self.db.save_sites([site()])
        self.db.upsert_station_cookie("s1", "gh", "session=one")
        self.db.save_sites([site()])
        self.assertEqual(len(self.credentials()), 1)

    def test_an_untouched_hand_added_cookie_keeps_a_fresh_overwrite(self) -> None:
        self.db.save_sites([site({"id": "ck", "type": "cookie", "value": "session=old"})])
        opened = self.db.get_sites_for_display()
        self.db.upsert_station_cookie("s1", "gh", "session=new")
        del opened[0]["credentials"][1]["value"]  # untouched: the dashboard leaves it out
        self.db.save_sites(opened)
        self.assertEqual(self.credentials()[1]["value"], "session=new")


class SelectionTests(unittest.TestCase):
    def test_an_action_naming_none_does_not_pick_a_written_back_cookie(self) -> None:
        cookie = {"id": "c", "type": "cookie", "value": "session=x", "source_credential_id": "gh"}
        plan = resolve_action_credential([GITHUB, cookie], {"protocol": "auto"})
        self.assertEqual(plan.credential["id"], "gh")

    def test_it_is_used_when_named(self) -> None:
        cookie = {"id": "c", "type": "cookie", "value": "session=x", "source_credential_id": "gh"}
        plan = resolve_action_credential([GITHUB, cookie], {"protocol": "auto", "credential_id": "c"})
        self.assertEqual((plan.mode, plan.credential["id"]), ("request", "c"))


class LoginWritebackTests(unittest.IsolatedAsyncioTestCase):
    async def test_a_login_check_in_writes_the_cookie_credential(self) -> None:
        routes = {
            ("GET", f"{BASE}/api/status"): FakeResponse(200, '{"data":{"github_oauth":true,"github_client_id":"cid"}}'),
            ("POST", f"{BASE}/api/oauth/state"): FakeResponse(200, '{"data":{"flow_token":"flow-1"}}'),
            ("GET", "https://github.com/login/oauth/authorize"): FakeResponse(
                302, "", headers={"location": f"{BASE}/oauth/github?code=C&state=flow-1"}
            ),
            ("GET", f"{BASE}/api/oauth/github"): FakeResponse(200, '{"success":true,"data":{"id":7}}', cookies={"session": "fresh"}),
            ("GET", f"{BASE}/api/user/self"): FakeResponse(200, '{"success":true,"data":{"id":7,"quota":0}}'),
        }
        with tempfile.TemporaryDirectory() as folder:
            db = DatabaseManager(Path(folder) / "data.db")
            db.save_sites([site()])
            adapter = create_adapter(db.get_sites()[0], FakeSession(routes))
            self.assertTrue((await adapter.check_in()).success)
            self.assertEqual(adapter.writeback.station_cookies, {"gh": "session=fresh"})
            persist_writeback(db, "s1", adapter.writeback)
            cookie = db.get_sites()[0]["credentials"][1]
            self.assertEqual((cookie["type"], cookie["value"]), ("cookie", "session=fresh"))

    def test_writeback_with_only_a_station_cookie_is_persisted(self) -> None:
        calls = []

        class Db:
            def upsert_station_cookie(self, *args):
                calls.append(args)
                return True

        persist_writeback(Db(), "s1", SiteWriteback(station_cookies={"gh": "session=x"}))
        self.assertEqual(calls, [("s1", "gh", "session=x")])


if __name__ == "__main__":
    unittest.main()
