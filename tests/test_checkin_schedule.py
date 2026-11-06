"""Tests for a site's own check-in time: fixed, or random within a range."""

from __future__ import annotations

import asyncio
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
    validate_checkin_schedule,
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

    def test_a_range_draws_between_its_ends(self) -> None:
        """The draw itself is checked, so always returning the start would fail."""
        with mock.patch("core.scheduler.random.randint", return_value=13 * 60 + 37) as draw:
            moment = draw_checkin_time(RANGE, date(2026, 11, 6))
        draw.assert_called_once_with(13 * 60, 14 * 60)
        self.assertEqual(moment, datetime(2026, 11, 6, 13, 37))

    def test_earliest_trims_the_range(self) -> None:
        with mock.patch("core.scheduler.random.randint", side_effect=lambda low, high: high) as draw:
            moment = draw_checkin_time(RANGE, date(2026, 11, 6), earliest=datetime(2026, 11, 6, 13, 50, 30))
        draw.assert_called_once_with(13 * 60 + 50, 14 * 60)
        self.assertEqual(moment, datetime(2026, 11, 6, 14, 0))

    def test_earliest_on_another_day_leaves_the_range_whole(self) -> None:
        with mock.patch("core.scheduler.random.randint", return_value=13 * 60) as draw:
            draw_checkin_time(RANGE, date(2026, 11, 7), earliest=datetime(2026, 11, 6, 13, 50))
        draw.assert_called_once_with(13 * 60, 14 * 60)

    def test_a_passed_slot_yields_nothing(self) -> None:
        self.assertIsNone(draw_checkin_time(FIXED, date(2026, 11, 6), earliest=datetime(2026, 11, 6, 9, 16)))
        # The current minute is still usable.
        self.assertIsNotNone(draw_checkin_time(FIXED, date(2026, 11, 6), earliest=datetime(2026, 11, 6, 9, 15, 40)))


class ValidationTests(unittest.TestCase):
    def test_a_reversed_range_is_refused_not_swapped(self) -> None:
        self.assertIn("结束不能早于开始", validate_checkin_schedule({**RANGE, "start": "14:00", "end": "13:00"}))

    def test_malformed_times_are_refused(self) -> None:
        self.assertTrue(validate_checkin_schedule({**FIXED, "time": "25:00"}))
        self.assertTrue(validate_checkin_schedule({**RANGE, "end": "noon"}))

    def test_fields_of_other_modes_are_not_checked(self) -> None:
        self.assertEqual(validate_checkin_schedule({"mode": "global", "time": "garbage"}), "")
        self.assertEqual(validate_checkin_schedule({**FIXED, "start": "14:00", "end": "13:00"}), "")
        self.assertEqual(validate_checkin_schedule(RANGE), "")
        self.assertEqual(validate_checkin_schedule(None), "")


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


class _Db:
    """The scheduler's view of storage: metadata only."""

    def __init__(self) -> None:
        self.metadata: dict[str, str] = {}

    def get_metadata(self, key: str) -> str | None:
        return self.metadata.get(key)

    def set_metadata(self, key: str, value: str) -> None:
        self.metadata[key] = value


class _Plugin:
    def __init__(self, sites: list[dict], settings: dict | None = None, db: _Db | None = None) -> None:
        self.sites = sites
        self.settings = settings or {"enabled": True, "random_enabled": False, "checkin_time": "08:30"}
        self.db = db or _Db()
        self.locked = False
        self.saved_settings: list[dict] = []
        self.history: list = []

    def get_sites(self) -> list[dict]:
        return copy.deepcopy(self.sites)

    def get_settings(self) -> dict:
        return copy.deepcopy(self.settings)

    def save_settings(self, settings: dict) -> None:
        self.saved_settings.append(copy.deepcopy(settings))
        self.settings = copy.deepcopy(settings)

    def is_config_locked(self) -> bool:
        return self.locked

    def record_history(self, results, log_type: str) -> None:
        self.history.append((results, log_type))

    def update_site_checkin_state(self, site_id, last_checkin_date, last_checkin_time,
                                  last_checkin_success, last_quota=None) -> None:
        for item in self.sites:
            if item["id"] == site_id:
                item.update(last_checkin_date=last_checkin_date, last_checkin_time=last_checkin_time,
                            last_checkin_success=last_checkin_success, last_quota=last_quota)


class SchedulingTests(unittest.IsolatedAsyncioTestCase):
    NOW = datetime(2026, 11, 6, 9, 0)
    AT = datetime(2026, 11, 6, 9, 15)

    def test_a_site_fires_once_at_its_own_time(self) -> None:
        scheduler = CheckInScheduler(_Plugin([site("own", FIXED), site("global")]))
        self.assertEqual(scheduler._due_sites(self.NOW), [])
        self.assertEqual(scheduler._due_sites(self.AT), ["own"])
        self.assertEqual(scheduler._due_sites(datetime(2026, 11, 6, 9, 15, 30)), [])
        self.assertEqual(scheduler._due_sites(datetime(2026, 11, 6, 23, 0)), [])
        self.assertEqual(scheduler._due_sites(datetime(2026, 11, 7, 9, 15)), ["own"])

    def test_a_failed_run_is_not_repeated_after_a_restart(self) -> None:
        """The daily marker is stored, so a new scheduler does not draw another time today."""
        db = _Db()
        first = CheckInScheduler(_Plugin([site("own", RANGE)], db=db))
        first._site_targets["own"] = (tuple(normalize_checkin_schedule(RANGE).values()), datetime(2026, 11, 6, 13, 10))
        self.assertEqual(first._due_sites(datetime(2026, 11, 6, 13, 10)), ["own"])
        restarted = CheckInScheduler(_Plugin([site("own", RANGE)], db=db))
        self.assertEqual(restarted._site_target(site("own", RANGE), datetime(2026, 11, 6, 13, 20)).date(), date(2026, 11, 7))
        self.assertEqual(restarted._due_sites(datetime(2026, 11, 6, 13, 59)), [])

    def test_a_locked_vault_does_not_use_up_the_day(self) -> None:
        """A target drawn on an earlier tick still runs once the vault is unlocked."""
        plugin = _Plugin([site("own", FIXED)])
        scheduler = CheckInScheduler(plugin)
        self.assertEqual(scheduler._due_sites(self.NOW), [])
        plugin.locked = True
        self.assertEqual(scheduler._due_sites(self.AT), [])
        plugin.locked = False
        self.assertEqual(scheduler._due_sites(datetime(2026, 11, 6, 9, 20)), ["own"])

    def test_a_slot_already_passed_waits_for_tomorrow(self) -> None:
        scheduler = CheckInScheduler(_Plugin([site("own", FIXED)]))
        info_time = scheduler._site_target(site("own", FIXED), datetime(2026, 11, 6, 10, 0))
        self.assertEqual(info_time, datetime(2026, 11, 7, 9, 15))

    def test_a_site_already_checked_in_today_waits_for_tomorrow(self) -> None:
        done = site("own", FIXED, last_checkin_date="2026-11-06", last_checkin_success=True)
        scheduler = CheckInScheduler(_Plugin([done]))
        self.assertEqual(scheduler._due_sites(self.AT), [])
        self.assertEqual(scheduler._site_target(done, self.NOW), datetime(2026, 11, 7, 9, 15))

    def test_a_manual_success_moves_a_drawn_target_to_tomorrow(self) -> None:
        plugin = _Plugin([site("own", FIXED)])
        scheduler = CheckInScheduler(plugin)
        self.assertEqual(scheduler._site_target(plugin.sites[0], self.NOW), self.AT)
        plugin.sites[0].update(last_checkin_date="2026-11-06", last_checkin_success=True)
        self.assertEqual(scheduler._site_target(plugin.sites[0], self.NOW), datetime(2026, 11, 7, 9, 15))

    def test_disabled_sites_have_no_target(self) -> None:
        disabled = site("own", FIXED, enabled=False)
        scheduler = CheckInScheduler(_Plugin([disabled]))
        self.assertEqual(scheduler._due_sites(self.AT), [])
        self.assertIsNone(scheduler._site_target(disabled, self.NOW))
        self.assertNotIn("own", scheduler._site_targets)

    def test_a_changed_schedule_is_redrawn(self) -> None:
        plugin = _Plugin([site("own", FIXED)])
        scheduler = CheckInScheduler(plugin)
        self.assertEqual(scheduler._site_target(plugin.sites[0], self.NOW), self.AT)
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
            self.assertIsNone(scheduler.site_target_info(site("own", FIXED, enabled=False)))

    async def test_turning_automatic_check_in_back_on_does_not_catch_up(self) -> None:
        plugin = _Plugin([site("own", FIXED)])
        scheduler = CheckInScheduler(plugin)
        scheduler._site_target(plugin.sites[0], self.NOW)
        plugin.settings["enabled"] = False
        scheduler._running = True

        async def stop_after_one_tick(*_):
            scheduler._running = False

        with mock.patch("core.scheduler.asyncio.sleep", new=stop_after_one_tick):
            await scheduler._scheduler_loop()
        self.assertEqual(scheduler._site_targets, {})
        plugin.settings["enabled"] = True
        self.assertEqual(scheduler._due_sites(datetime(2026, 11, 6, 10, 0)), [])
        self.assertEqual(scheduler._site_target(plugin.sites[0], datetime(2026, 11, 6, 10, 0)), datetime(2026, 11, 7, 9, 15))


def _fake_adapters(ran: list[str], gate: asyncio.Event | None = None):
    """Adapters whose check-in records the site and, with a gate, waits on it."""

    def build(site_config, *args, **kwargs):
        async def check_in():
            ran.append(site_config["id"])
            if gate is not None:
                await gate.wait()
            return CheckInResult(site_config["id"], site_config["id"], True, "ok")

        fake = mock.Mock()
        fake.check_in = check_in
        fake.writeback = None
        return fake

    return build


class RunTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        patches = [
            mock.patch("core.scheduler.create_client_session"),
            mock.patch("core.scheduler.asyncio.sleep", new=mock.AsyncMock()),
        ]
        session = patches[0].start()
        session.return_value.__aenter__.return_value = object()
        patches[1].start()
        for patch in patches:
            self.addCleanup(patch.stop)

    async def test_the_global_run_leaves_own_time_sites_alone(self) -> None:
        scheduler = CheckInScheduler(_Plugin([site("own", FIXED), site("global")]))
        ran: list[str] = []
        with mock.patch("core.scheduler.create_adapter", side_effect=_fake_adapters(ran)):
            await scheduler.run_check_in_all(own_schedule=False)
            self.assertEqual(ran, ["global"])
            ran.clear()
            await scheduler.run_check_in_all(only=["own"])
            self.assertEqual(ran, ["own"])

    async def test_a_manual_run_still_covers_every_site(self) -> None:
        scheduler = CheckInScheduler(_Plugin([site("own", FIXED), site("global")]))
        ran: list[str] = []
        with mock.patch("core.scheduler.create_adapter", side_effect=_fake_adapters(ran)):
            await scheduler.run_check_in_all(manual=True)
        self.assertEqual(ran, ["own", "global"])

    async def test_overlapping_runs_check_a_site_in_once(self) -> None:
        """A run that waited for the other reads its success and does not repeat it."""
        plugin = _Plugin([site("own", FIXED)])
        scheduler = CheckInScheduler(plugin)
        ran: list[str] = []
        gate = asyncio.Event()
        with mock.patch("core.scheduler.create_adapter", side_effect=_fake_adapters(ran, gate)):
            scheduled = asyncio.create_task(scheduler.run_check_in_all(only=["own"]))
            await asyncio.sleep(0)
            manual = asyncio.create_task(scheduler.run_check_in_all(manual=True))
            await asyncio.sleep(0)
            gate.set()
            await asyncio.gather(scheduled, manual)
        self.assertEqual(ran, ["own"])
        self.assertTrue(plugin.sites[0]["last_checkin_success"])

    async def test_an_empty_global_run_still_clears_the_one_off_time(self) -> None:
        plugin = _Plugin([site("own", FIXED)], settings={"enabled": True, "manual_target_time": "10:00"})
        scheduler = CheckInScheduler(plugin)
        self.assertEqual(await scheduler.run_check_in_all(own_schedule=False), [])
        self.assertEqual(plugin.settings["manual_target_time"], "")

    async def test_an_own_time_run_leaves_the_one_off_time(self) -> None:
        plugin = _Plugin([site("own", FIXED)], settings={"enabled": True, "manual_target_time": "10:00"})
        scheduler = CheckInScheduler(plugin)
        with mock.patch("core.scheduler.create_adapter", side_effect=_fake_adapters([])):
            await scheduler.run_check_in_all(only=["own"])
        self.assertEqual(plugin.settings["manual_target_time"], "10:00")


if __name__ == "__main__":
    unittest.main()
