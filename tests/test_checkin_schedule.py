"""Tests for a site's own check-in time: fixed, or random within a range."""

from __future__ import annotations

import copy
import json
import sqlite3
import tempfile
import unittest
from datetime import date, datetime
from pathlib import Path
from typing import Any
from unittest import mock

import tests  # noqa: F401
from core.adapters import CheckInResult
from core.scheduler import CheckInScheduler, draw_checkin_time
from core.site_schema import (
    normalize_action,
    normalize_checkin_schedule,
    normalize_time_of_day,
    site_checkin_schedule,
)
from core.storage import DatabaseManager

FIXED = {"mode": "fixed", "time": "09:15", "start": "08:00", "end": "10:30"}
RANGE = {"mode": "range", "time": "08:30", "start": "13:00", "end": "14:00"}


def site(site_id: str, schedule: dict | None = None, **extra: Any) -> dict:
    checkin: dict[str, Any] = {}
    if schedule is not None:
        checkin["schedule"] = schedule
    return {"id": site_id, "name": site_id, "enabled": True, "checkin": checkin, **extra}


class ScheduleSchemaTests(unittest.TestCase):
    def test_times_of_day_are_normalized(self) -> None:
        self.assertEqual(normalize_time_of_day("9:05", "x"), "09:05")
        for bad in ("", "24:00", "12:60", "noon", "12", None):
            self.assertEqual(normalize_time_of_day(bad, "08:00"), "08:00")

    def test_defaults_follow_the_global_time(self) -> None:
        schedule = normalize_checkin_schedule(None)
        self.assertEqual(schedule["mode"], "global")
        self.assertIsNone(site_checkin_schedule(site("s")))

    def test_a_backwards_range_is_turned_round(self) -> None:
        schedule = normalize_checkin_schedule({"mode": "range", "start": "11:00", "end": "09:00"})
        self.assertEqual((schedule["start"], schedule["end"]), ("09:00", "11:00"))

    def test_unknown_modes_fall_back_to_global(self) -> None:
        self.assertEqual(normalize_checkin_schedule({"mode": "weekly"})["mode"], "global")

    def test_only_the_check_in_action_carries_a_schedule(self) -> None:
        self.assertIn("schedule", normalize_action({"schedule": FIXED}, allow_oauth=True, scheduled=True))
        self.assertNotIn("schedule", normalize_action({"schedule": FIXED}, allow_oauth=False))


class DrawTests(unittest.TestCase):
    def test_a_fixed_time_is_that_time(self) -> None:
        self.assertEqual(draw_checkin_time(FIXED, date(2026, 11, 6)), datetime(2026, 11, 6, 9, 15))

    def test_a_range_draws_within_it(self) -> None:
        for _ in range(50):
            moment = draw_checkin_time(RANGE, date(2026, 11, 6))
            self.assertTrue(datetime(2026, 11, 6, 13) <= moment <= datetime(2026, 11, 6, 14))

    def test_earliest_trims_the_range(self) -> None:
        for _ in range(50):
            moment = draw_checkin_time(RANGE, date(2026, 11, 6), earliest=datetime(2026, 11, 6, 13, 50, 30))
            self.assertTrue(datetime(2026, 11, 6, 13, 50) <= moment <= datetime(2026, 11, 6, 14))

    def test_a_passed_slot_yields_nothing(self) -> None:
        self.assertIsNone(draw_checkin_time(FIXED, date(2026, 11, 6), earliest=datetime(2026, 11, 6, 9, 16)))
        # The current minute is still usable.
        self.assertIsNotNone(draw_checkin_time(FIXED, date(2026, 11, 6), earliest=datetime(2026, 11, 6, 9, 15, 40)))


class StorageTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "data.db"
        self.db = DatabaseManager(self.db_path)
        self.base = {
            "id": "s1", "name": "S", "type": "new-api", "base_url": "https://s.example.com",
            "credentials": [{"id": "c1", "type": "token", "value": "sk"}], "enabled": True,
        }

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_the_schedule_round_trips_in_the_clear(self) -> None:
        self.db.save_sites([{**self.base, "checkin": {"schedule": RANGE}}])
        self.assertEqual(self.db.get_sites()[0]["checkin"]["schedule"], RANGE)
        conn = sqlite3.connect(str(self.db_path))
        try:
            stored = json.loads(conn.execute("SELECT checkin_config FROM sites").fetchone()[0])
        finally:
            conn.close()
        self.assertEqual(stored["schedule"], RANGE)

    def test_a_save_without_a_schedule_keeps_the_stored_one(self) -> None:
        """An older dashboard omits the field; that must not reset the site to the global time."""
        self.db.save_sites([{**self.base, "checkin": {"schedule": FIXED}}])
        self.db.save_sites([{**self.base, "checkin": {"path": "/sign"}}])
        checkin = self.db.get_sites()[0]["checkin"]
        self.assertEqual(checkin["schedule"], FIXED)
        self.assertEqual(checkin["path"], "/sign")

    def test_rows_from_before_have_the_global_time(self) -> None:
        self.db.save_sites([{**self.base, "checkin": {}}])
        self.assertEqual(self.db.get_sites()[0]["checkin"]["schedule"]["mode"], "global")


class _Plugin:
    def __init__(self, sites: list[dict], settings: dict | None = None) -> None:
        self.sites = sites
        self.settings = settings or {"enabled": True, "random_enabled": False, "checkin_time": "08:30"}

    def get_sites(self) -> list[dict]:
        return copy.deepcopy(self.sites)

    def get_settings(self) -> dict:
        return copy.deepcopy(self.settings)


class SchedulingTests(unittest.IsolatedAsyncioTestCase):
    NOW = datetime(2026, 11, 6, 9, 0)

    def test_a_site_fires_once_at_its_own_time(self) -> None:
        scheduler = CheckInScheduler(_Plugin([site("own", FIXED), site("global")]))
        self.assertEqual(scheduler._due_sites(self.NOW), [])
        self.assertEqual(scheduler._due_sites(datetime(2026, 11, 6, 9, 15)), ["own"])
        self.assertEqual(scheduler._due_sites(datetime(2026, 11, 6, 9, 15, 30)), [])
        self.assertEqual(scheduler._due_sites(datetime(2026, 11, 6, 23, 0)), [])
        self.assertEqual(scheduler._due_sites(datetime(2026, 11, 7, 9, 15)), ["own"])

    def test_a_slot_already_passed_waits_for_tomorrow(self) -> None:
        scheduler = CheckInScheduler(_Plugin([site("own", FIXED)]))
        info_time = scheduler._site_target(site("own", FIXED), datetime(2026, 11, 6, 10, 0))
        self.assertEqual(info_time, datetime(2026, 11, 7, 9, 15))

    def test_a_site_already_checked_in_today_is_passed_over(self) -> None:
        done = site("own", FIXED, last_checkin_date="2026-11-06", last_checkin_success=True)
        scheduler = CheckInScheduler(_Plugin([done]))
        self.assertEqual(scheduler._due_sites(datetime(2026, 11, 6, 9, 15)), [])

    def test_disabled_sites_never_fire(self) -> None:
        scheduler = CheckInScheduler(_Plugin([site("own", FIXED, enabled=False)]))
        self.assertEqual(scheduler._due_sites(datetime(2026, 11, 6, 9, 15)), [])

    def test_a_changed_schedule_is_redrawn(self) -> None:
        plugin = _Plugin([site("own", FIXED)])
        scheduler = CheckInScheduler(plugin)
        self.assertEqual(scheduler._site_target(plugin.sites[0], self.NOW), datetime(2026, 11, 6, 9, 15))
        plugin.sites[0]["checkin"]["schedule"] = {**FIXED, "time": "09:40"}
        self.assertEqual(scheduler._site_target(plugin.sites[0], self.NOW), datetime(2026, 11, 6, 9, 40))

    def test_the_dashboard_sees_the_next_time(self) -> None:
        scheduler = CheckInScheduler(_Plugin([site("own", FIXED)]))
        with mock.patch("core.scheduler.datetime") as clock:
            clock.now.return_value = self.NOW
            clock.combine = datetime.combine
            info = scheduler.site_target_info(site("own", FIXED))
        self.assertEqual(info["display_text"], "今日 09:15")
        self.assertIsNone(scheduler.site_target_info(site("global")))

    async def test_the_global_run_leaves_own_time_sites_alone(self) -> None:
        scheduler = CheckInScheduler(_Plugin([site("own", FIXED), site("global")]))
        ran: list[str] = []

        with mock.patch("core.scheduler.create_client_session") as session, \
             mock.patch("core.scheduler.create_adapter") as adapter, \
             mock.patch.object(CheckInScheduler, "_persist_checkin_results", new=mock.AsyncMock()):
            session.return_value.__aenter__.return_value = object()

            def build(site_config, *args, **kwargs):
                ran.append(site_config["id"])
                fake = mock.Mock()
                fake.check_in = mock.AsyncMock(return_value=CheckInResult(site_config["id"], "", True, "ok"))
                fake.writeback = None
                return fake

            adapter.side_effect = build
            with mock.patch("core.scheduler.asyncio.sleep", new=mock.AsyncMock()):
                await scheduler.run_check_in_all(own_schedule=False)
                self.assertEqual(ran, ["global"])
                ran.clear()
                await scheduler.run_check_in_all(only=["own"])
                self.assertEqual(ran, ["own"])
                ran.clear()
                # A manual run still covers every site.
                await scheduler.run_check_in_all(manual=True)
                self.assertEqual(ran, ["own", "global"])


if __name__ == "__main__":
    unittest.main()
