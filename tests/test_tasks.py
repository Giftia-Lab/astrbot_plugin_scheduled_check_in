"""Tests for scheduled tasks: their schema and schedules, storage, running, and the scheduler loop."""

from __future__ import annotations

import json
import random
import sqlite3
import tempfile
import unittest
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

import tests  # noqa: F401
from core.adapters import create_adapter
from core.crypto import CIPHER_PREFIX
from core.storage import DatabaseManager
from core.task_scheduler import LOG_TYPE_TASK, MISFIRE_GRACE_SECONDS, TaskScheduler
from core.task_schema import (
    SCHEDULE_INTERVAL,
    next_cron_run,
    next_run,
    normalize_task,
    normalize_tasks,
    preview_schedule,
    schedule_key,
    validate_task,
)
from tests.fakes import (
    POW_NONCE,
    POW_REFUSED,
    FakeResponse,
    FakeSession,
    pow_challenge,
    pow_proof,
)

BASE = "https://relay.example.com"
# A Sunday.
SUNDAY = datetime(2026, 9, 27, 4, 53, 56)


def make_task(**overrides: Any) -> dict[str, Any]:
    task = {
        "id": "t1",
        "name": "保活",
        "schedule": "cron",
        "cron": "*/30 * * * *",
        "method": "GET",
        "url": "/api/ping",
    }
    task.update(overrides)
    return normalize_task(task)


def make_site(tasks: list[dict[str, Any]] | None = None, **overrides: Any) -> dict[str, Any]:
    site = {
        "id": "site_1",
        "name": "Relay",
        "type": "new-api",
        "base_url": BASE,
        "proxy": "",
        "credentials": [{"id": "c1", "type": "token", "value": "sk-a"}],
        "checkin": {},
        "balance": {},
        "tasks": tasks if tasks is not None else [make_task()],
        "enabled": True,
    }
    site.update(overrides)
    return site


class _TempDb(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "data.db"
        self.db = DatabaseManager(self.db_path)

    def tearDown(self) -> None:
        try:
            self.temp_dir.cleanup()
        except OSError:
            pass  # Windows keeps WAL sidecar files briefly locked

    def raw(self, column: str) -> str:
        conn = sqlite3.connect(str(self.db_path))
        try:
            row = conn.execute(f"SELECT {column} FROM sites WHERE id = 'site_1'").fetchone()
        finally:
            conn.close()
        return "" if row is None else str(row[0] or "")


# ----------------------------------------------------------------------
# Schema and schedules
# ----------------------------------------------------------------------
class TaskSchemaTests(unittest.TestCase):
    def test_defaults_fill_every_field(self) -> None:
        task = normalize_task({})
        self.assertEqual(task["schedule"], "cron")
        self.assertEqual(task["method"], "GET")
        self.assertTrue(task["enabled"])
        self.assertTrue(task["log_history"])
        self.assertEqual((task["interval_min"], task["interval_max"]), (60, 120))
        self.assertEqual(task["headers"], [])
        self.assertEqual(task["pow_purpose"], "")

    def test_interval_bounds_are_ordered_and_clamped(self) -> None:
        task = normalize_task({"schedule": "interval", "interval_min": 90, "interval_max": 0})
        self.assertEqual((task["interval_min"], task["interval_max"]), (1, 90))

    def test_editor_state_and_duplicates_are_dropped(self) -> None:
        tasks = normalize_tasks([make_task(state={"x": 1}), make_task(name="dup"), "junk"])
        self.assertEqual(len(tasks), 1)
        self.assertNotIn("state", tasks[0])

    def test_validation(self) -> None:
        self.assertEqual(validate_task(make_task()), "")
        self.assertIn("URL", validate_task(make_task(url="")))
        self.assertIn("http", validate_task(make_task(url="ftp://x")))
        self.assertIn("5 个字段", validate_task(make_task(cron="* * *")))
        self.assertIn("cron", validate_task(make_task(cron="61 * * * *")))
        self.assertIn("JSON", validate_task(make_task(method="POST", body="{bad")))
        # A GET never sends its body, so a leftover one does not block it.
        self.assertEqual(validate_task(make_task(method="GET", body="{bad")), "")
        # An interval schedule needs no cron expression.
        self.assertEqual(validate_task(make_task(schedule="interval", cron="")), "")

    def test_an_invalid_pow_purpose_is_rejected_after_normalization(self) -> None:
        for purpose in ("!!!", "中文", "  !!!  "):
            with self.subTest(purpose=purpose):
                self.assertIn("PoW", validate_task(make_task(pow_purpose=purpose)))

    def test_valid_and_empty_pow_purposes_remain_usable(self) -> None:
        for purpose, expected in (
            (None, ""),
            ("", ""),
            ("   ", ""),
            (" CheckIn ", "checkin"),
            ("a b&c", "abc"),
        ):
            with self.subTest(purpose=purpose):
                task = make_task(pow_purpose=purpose)
                self.assertEqual(task["pow_purpose"], expected)
                self.assertEqual(validate_task(task), "")

    def test_day_of_week_follows_crontab(self) -> None:
        """APScheduler counts from Monday; crontab's 0 and 7 are Sunday."""
        for expression in ("0 0 * * 0", "0 0 * * 7", "0 0 * * sun"):
            self.assertEqual(next_cron_run(expression, SUNDAY), datetime(2026, 10, 4), expression)
        self.assertEqual(next_cron_run("0 8 * * 1-5", SUNDAY), datetime(2026, 9, 28, 8))
        self.assertEqual(next_cron_run("0 9 * * 5-7", SUNDAY), datetime(2026, 9, 27, 9))
        runs, error = preview_schedule({"cron": "0 0 * * */2"}, SUNDAY)
        self.assertEqual(error, "")
        # Sunday, Tuesday, Thursday, Saturday: the next three after Sunday 04:53.
        self.assertEqual(runs, ["2026-09-29 00:00", "2026-10-01 00:00", "2026-10-03 00:00"])

    def test_a_run_never_repeats_the_instant_just_run(self) -> None:
        self.assertEqual(next_cron_run("0 5 * * *", datetime(2026, 9, 27, 5)), datetime(2026, 9, 28, 5))

    def test_invalid_expressions_say_why(self) -> None:
        self.assertIn("星期", preview_schedule({"cron": "0 0 * * 8"}, SUNDAY)[1])
        self.assertIn("5 个字段", preview_schedule({"cron": "0 0 *"}, SUNDAY)[1])

    def test_an_interval_run_falls_between_its_bounds(self) -> None:
        task = make_task(schedule=SCHEDULE_INTERVAL, interval_min=10, interval_max=30)
        rng = random.Random(7)
        for _ in range(50):
            gap = next_run(task, SUNDAY, rng) - SUNDAY
            self.assertTrue(timedelta(minutes=10) <= gap <= timedelta(minutes=30), gap)

    def test_the_schedule_key_follows_only_the_schedule(self) -> None:
        self.assertEqual(schedule_key(make_task()), schedule_key(make_task(url="/other", name="x")))
        self.assertNotEqual(schedule_key(make_task()), schedule_key(make_task(cron="0 * * * *")))


# ----------------------------------------------------------------------
# Storage
# ----------------------------------------------------------------------
class TaskStorageTests(_TempDb):
    def test_round_trip_with_secrets_apart(self) -> None:
        task = make_task(method="POST", headers=[{"key": "X-Key", "value": "secret"}], body='{"a": 1}')
        self.db.save_sites([make_site([task])])
        loaded = self.db.get_sites()[0]["tasks"][0]
        self.assertEqual(loaded, task)
        plain = json.loads(self.raw("tasks_config"))
        self.assertNotIn("headers", plain[0])
        self.assertNotIn("body", plain[0])
        self.assertIn("secret", self.raw("tasks_secrets"))

    def test_the_vault_seals_headers_and_body(self) -> None:
        task = make_task(method="POST", headers=[{"key": "X-Key", "value": "secret"}], body='{"a": 1}')
        self.db.save_sites([make_site([task])])
        self.db.enable_encryption()
        self.assertTrue(self.raw("tasks_secrets").startswith(CIPHER_PREFIX))
        self.assertEqual(self.db.get_sites()[0]["tasks"][0]["body"], '{"a": 1}')
        # The schedule stays readable, as an action's path does.
        self.assertEqual(json.loads(self.raw("tasks_config"))[0]["cron"], "*/30 * * * *")

    def test_a_task_without_secrets_leaves_the_column_empty(self) -> None:
        self.db.save_sites([make_site()])
        self.assertEqual(self.raw("tasks_secrets"), "")

    def test_the_pow_purpose_is_kept_in_the_plain_config(self) -> None:
        self.db.save_sites([make_site([make_task(pow_purpose="checkin")])])
        self.assertEqual(self.db.get_sites()[0]["tasks"][0]["pow_purpose"], "checkin")
        self.assertEqual(json.loads(self.raw("tasks_config"))[0]["pow_purpose"], "checkin")

    def test_an_older_client_preserves_pow_settings_by_task_id(self) -> None:
        self.db.save_sites(
            [
                make_site(
                    [
                        make_task(pow_purpose="checkin"),
                        make_task(id="t2", pow_purpose="oauth"),
                    ],
                    vs_pow=True,
                )
            ]
        )
        submitted = make_site([make_task(id="t2"), make_task(), make_task(id="t3")])
        for task in submitted["tasks"]:
            del task["pow_purpose"]
        self.db.save_sites([submitted])
        stored = self.db.get_sites()[0]
        self.assertIs(stored["vs_pow"], True)
        self.assertEqual(
            {task["id"]: task["pow_purpose"] for task in stored["tasks"]},
            {"t2": "oauth", "t1": "checkin", "t3": ""},
        )
        self.assertNotIn("vs_pow", submitted)
        self.assertTrue(all("pow_purpose" not in task for task in submitted["tasks"]))

    def test_omitted_pow_settings_are_kept_while_locked(self) -> None:
        self.db.save_sites(
            [
                make_site(
                    [
                        make_task(pow_purpose="checkin", body='{"secret":1}'),
                    ],
                    vs_pow=True,
                )
            ]
        )
        key = self.db.enable_encryption()
        self.db.lock_encryption()
        submitted = self.db.get_sites_for_display()
        self.assertTrue(submitted[0]["locked"])
        del submitted[0]["vs_pow"]
        del submitted[0]["tasks"][0]["pow_purpose"]
        self.db.save_sites(submitted)
        self.db.unlock_encryption(key)
        stored = self.db.get_sites()[0]
        self.assertIs(stored["vs_pow"], True)
        self.assertEqual(stored["tasks"][0]["pow_purpose"], "checkin")
        self.assertEqual(stored["tasks"][0]["body"], '{"secret":1}')

    def test_explicit_values_can_still_disable_pow(self) -> None:
        self.db.save_sites([make_site([make_task(pow_purpose="checkin")], vs_pow=True)])
        self.db.save_sites([make_site([make_task(pow_purpose="")], vs_pow=False)])
        stored = self.db.get_sites()[0]
        self.assertIs(stored["vs_pow"], False)
        self.assertEqual(stored["tasks"][0]["pow_purpose"], "")

    def test_the_vs_pow_switch_round_trips_and_defaults_off(self) -> None:
        self.db.save_sites([make_site()])
        self.assertIs(self.db.get_sites()[0]["vs_pow"], False)
        self.db.save_sites([make_site(vs_pow=True)])
        self.assertIs(self.db.get_sites()[0]["vs_pow"], True)
        self.assertEqual(self.raw("vs_pow"), "1")
        # Only a real True turns it on; an explicit false-like value turns it off.
        for value in (None, "true", 1):
            self.db.save_sites([make_site(vs_pow=value)])
            self.assertIs(self.db.get_sites()[0]["vs_pow"], False, value)
        self.db.save_sites([make_site()])
        self.assertIs(self.db.get_sites()[0]["vs_pow"], False)

    def test_a_table_from_before_tasks_is_upgraded_in_place(self) -> None:
        conn = sqlite3.connect(str(self.db_path))
        conn.execute("DROP TABLE sites")
        conn.execute(
            "CREATE TABLE sites (id TEXT PRIMARY KEY, name TEXT NOT NULL, type TEXT NOT NULL,"
            " base_url TEXT NOT NULL, proxy TEXT NOT NULL DEFAULT '', credentials TEXT NOT NULL DEFAULT '',"
            " checkin_config TEXT NOT NULL DEFAULT '', checkin_headers TEXT NOT NULL DEFAULT '',"
            " balance_config TEXT NOT NULL DEFAULT '', balance_headers TEXT NOT NULL DEFAULT '',"
            " enabled INTEGER NOT NULL DEFAULT 1, last_checkin_date TEXT, last_checkin_time TEXT,"
            " last_checkin_success INTEGER, last_quota REAL, display_order INTEGER NOT NULL DEFAULT 0,"
            " created_at TEXT NOT NULL, updated_at TEXT NOT NULL)"
        )
        conn.execute(
            "INSERT INTO sites (id, name, type, base_url, created_at, updated_at)"
            " VALUES ('site_1', 'Old', 'new-api', 'https://old.example.com', 'x', 'x')"
        )
        conn.commit()
        conn.close()
        db = DatabaseManager(self.db_path)
        self.assertEqual(db.get_sites()[0]["tasks"], [])
        # Added in place too, and off for every site that existed before it.
        self.assertIs(db.get_sites()[0]["vs_pow"], False)
        db.save_sites([make_site()])
        self.assertEqual(db.get_sites()[0]["tasks"][0]["id"], "t1")

    def test_state_survives_saves_and_goes_with_its_task(self) -> None:
        self.db.save_sites([make_site([make_task(), make_task(id="t2")])])
        self.db.set_task_schedule("site_1", "t1", "cron|x", "2026-09-27 05:00:00")
        self.db.record_task_run("site_1", "t1", "2026-09-27 04:30:00", False, "请求失败（HTTP 500）")
        self.db.set_task_schedule("site_1", "t2", "cron|x", "2026-09-27 05:00:00")
        # The dashboard posts back what it displayed, run state included.
        displayed = self.db.get_sites_for_display()
        self.assertEqual(displayed[0]["tasks"][0]["state"]["last_message"], "请求失败（HTTP 500）")
        displayed[0]["tasks"] = displayed[0]["tasks"][:1]
        self.db.save_sites(displayed)
        states = self.db.get_task_states()
        self.assertEqual(set(states), {("site_1", "t1")})
        self.assertEqual(states[("site_1", "t1")]["next_run_at"], "2026-09-27 05:00:00")
        self.assertIs(states[("site_1", "t1")]["last_success"], False)
        self.assertNotIn("state", self.db.get_sites()[0]["tasks"][0])

    def test_history_can_leave_out_task_runs(self) -> None:
        detail = [{"site_id": "site_1", "success": True, "message": "ok"}]
        for log_type in ("scheduled", LOG_TYPE_TASK):
            self.db.record_history_entries([{
                "timestamp": "2026-09-27 05:00:00", "type": log_type, "manual": False,
                "success": True, "report": "r", "details": detail,
            }])
        for site_id in (None, "site_1"):
            logs = self.db.read_history_logs(site_id=site_id, exclude_type=LOG_TYPE_TASK)
            self.assertEqual([log["type"] for log in logs], ["scheduled"], site_id)
        self.assertEqual(len(self.db.read_history_logs()), 2)


# ----------------------------------------------------------------------
# Running one task
# ----------------------------------------------------------------------
class RunTaskTests(unittest.IsolatedAsyncioTestCase):
    async def _run(self, task: dict[str, Any], routes: dict, **site: Any):
        session = FakeSession(routes)
        adapter = create_adapter(make_site([task], **site), session)
        return await adapter.run_task(task), session

    async def test_a_post_sends_its_json_body_credential_and_headers(self) -> None:
        task = make_task(
            method="POST",
            credential_id="c1",
            headers=[{"key": "X-Key", "value": "v"}, {"key": "Content-Type", "value": "application/json; charset=utf-8"}],
            body='{"名": 1}',
        )
        result, session = await self._run(task, {("POST", f"{BASE}/api/ping"): FakeResponse(200, '{"message":"pong"}')})
        self.assertTrue(result.success, result.message)
        self.assertEqual(result.message, "请求成功（HTTP 200）：pong")
        self.assertEqual(result.site_name, "Relay · 保活")
        call = session.calls[0]
        self.assertEqual(call["data"], '{"名": 1}'.encode())
        self.assertEqual(call["headers"]["Authorization"], "Bearer sk-a")
        self.assertEqual(call["headers"]["X-Key"], "v")
        # The task's own headers are applied last.
        self.assertEqual(call["headers"]["Content-Type"], "application/json; charset=utf-8")
        # Recorded even on success, so the log shows what came back.
        self.assertEqual(result.attempts[0]["response"], '{"message":"pong"}')

    async def test_without_a_credential_nothing_authenticates(self) -> None:
        task = make_task(url="https://other.example.com/health")
        result, session = await self._run(task, {("GET", "https://other.example.com/health"): FakeResponse(204, "")})
        self.assertTrue(result.success)
        self.assertNotIn("Authorization", session.calls[0]["headers"])
        self.assertNotIn("data", session.calls[0])

    async def test_a_get_never_sends_a_body(self) -> None:
        task = make_task(body='{"a": 1}')
        _result, session = await self._run(task, {("GET", f"{BASE}/api/ping"): FakeResponse(200, "ok")})
        self.assertNotIn("data", session.calls[0])

    async def test_a_missing_new_api_user_is_not_an_expired_credential(self) -> None:
        task = make_task(method="POST", credential_id="c1")
        result, _session = await self._run(task, {("POST", f"{BASE}/api/ping"): FakeResponse(
            401, '{"message":"无权进行此操作，未提供 New-Api-User","success":false}')})
        self.assertFalse(result.success)
        self.assertFalse(result.expired)
        self.assertIn("New-Api-User", result.message)
        self.assertIn("并非凭据失效", result.message)

    async def test_an_error_status_fails_with_the_stations_message(self) -> None:
        task = make_task()
        result, _session = await self._run(
            task, {("GET", f"{BASE}/api/ping"): FakeResponse(500, '{"message":"internal"}')}
        )
        self.assertFalse(result.success)
        self.assertEqual(result.message, "请求失败（HTTP 500）：internal")

    async def test_a_deleted_credential_is_reported_not_replaced(self) -> None:
        task = make_task(credential_id="gone")
        result, session = await self._run(task, {})
        self.assertFalse(result.success)
        self.assertIn("凭据已被删除", result.message)
        self.assertEqual(session.calls, [])

    async def test_a_task_solves_the_vs_pow_it_names(self) -> None:
        challenge = f"{BASE}/api/pow/challenge?purpose=checkin"
        task = make_task(method="POST", credential_id="c1", pow_purpose="checkin")
        result, session = await self._run(task, {
            ("GET", challenge): FakeResponse(200, pow_challenge("tok")),
            ("POST", f"{BASE}/api/ping"): FakeResponse(200, '{"success":true}'),
        }, vs_pow=True)
        self.assertTrue(result.success, result.message)
        # The challenge goes out with the task's credential: the token names the account.
        self.assertEqual(session.calls[0]["headers"]["Authorization"], "Bearer sk-a")
        self.assertEqual(pow_proof(session.calls_to("/api/ping")[0]), ("tok", POW_NONCE))

    async def test_a_purpose_does_nothing_until_the_site_switch_is_on(self) -> None:
        task = make_task(pow_purpose="checkin")
        _result, session = await self._run(task, {("GET", f"{BASE}/api/ping"): FakeResponse(200, "ok")})
        self.assertEqual(session.urls(), [f"{BASE}/api/ping"])

    async def test_a_refused_proof_is_a_failure_despite_the_200(self) -> None:
        for site, hint in (({}, "「求解 Vs PoW」"), ({"vs_pow": True}, "请求前求解 Vs PoW")):
            with self.subTest(site=site):
                result, _session = await self._run(
                    make_task(), {("GET", f"{BASE}/api/ping"): FakeResponse(200, POW_REFUSED)}, **site
                )
                self.assertFalse(result.success)
                self.assertFalse(result.expired)
                self.assertIn(hint, result.message)
                self.assertFalse(result.attempts[-1]["success"])

    async def test_without_a_purpose_no_challenge_is_asked_for(self) -> None:
        _result, session = await self._run(
            make_task(), {("GET", f"{BASE}/api/ping"): FakeResponse(200, "ok")}, vs_pow=True
        )
        self.assertEqual(session.urls(), [f"{BASE}/api/ping"])


# ----------------------------------------------------------------------
# The scheduler
# ----------------------------------------------------------------------
class FakePlugin:
    """The parts of the plugin the task scheduler uses, over a real database."""

    acw_cache_file = None

    def __init__(self, db: DatabaseManager, session: FakeSession) -> None:
        self.db = db
        self.session = session
        self.locked = False
        self.history: list[tuple[str, bool | None, list]] = []

    def is_config_locked(self) -> bool:
        return self.locked

    def get_sites(self) -> list[dict[str, Any]]:
        return self.db.get_sites()

    def get_settings(self) -> dict[str, Any]:
        return self.db.get_settings()

    def cloudflare_context(self, _settings: Any) -> None:
        return None

    def record_history(self, results: list, log_type: str, manual: bool | None = None) -> None:
        self.history.append((log_type, manual, results))


class TaskSchedulerTests(_TempDb):
    def setUp(self) -> None:
        super().setUp()
        self.session = FakeSession({}, default=FakeResponse(200, '{"message":"pong"}'))
        self.plugin = FakePlugin(self.db, self.session)
        self.scheduler = TaskScheduler(self.plugin)
        import core.task_scheduler as module

        # Every run goes out on the fake session.
        self._original = module.create_client_session

        class _Session:
            def __init__(inner, _settings: Any) -> None:
                pass

            async def __aenter__(inner) -> FakeSession:
                return self.session

            async def __aexit__(inner, *_exc: Any) -> None:
                return None

        module.create_client_session = _Session
        self.module = module

    def tearDown(self) -> None:
        self.module.create_client_session = self._original
        super().tearDown()

    def state(self, task_id: str = "t1") -> dict[str, Any]:
        return self.db.get_task_states().get(("site_1", task_id), {})

    def run_tick(self, now: datetime) -> list:
        import asyncio

        return asyncio.run(self.scheduler.tick(now))

    def test_a_new_task_is_scheduled_not_run(self) -> None:
        self.db.save_sites([make_site()])
        self.assertEqual(self.run_tick(SUNDAY), [])
        self.assertEqual(self.state()["next_run_at"], "2026-09-27 05:00:00")
        self.assertEqual(self.session.calls, [])

    def test_a_due_task_runs_and_is_rescheduled(self) -> None:
        self.db.save_sites([make_site()])
        self.run_tick(SUNDAY)
        results = self.run_tick(datetime(2026, 9, 27, 5, 0, 10))
        self.assertEqual(len(results), 1)
        self.assertTrue(results[0].success)
        self.assertEqual(self.session.urls(), [f"{BASE}/api/ping"])
        state = self.state()
        self.assertTrue(state["last_success"])
        # Counted from the real clock at run time, so strictly later than the slot.
        self.assertGreater(state["next_run_at"], "2026-09-27 05:00:00")
        self.assertEqual(self.plugin.history[0][:2], (LOG_TYPE_TASK, False))

    def test_a_run_missed_while_stopped_is_skipped(self) -> None:
        self.db.save_sites([make_site()])
        self.run_tick(SUNDAY)
        late = datetime(2026, 9, 27, 5, 0) + timedelta(seconds=MISFIRE_GRACE_SECONDS + 60)
        self.assertEqual(self.run_tick(late), [])
        self.assertEqual(self.session.calls, [])
        self.assertEqual(self.state()["next_run_at"], "2026-09-27 05:30:00")

    def test_a_changed_schedule_is_worked_out_again(self) -> None:
        self.db.save_sites([make_site()])
        self.run_tick(SUNDAY)
        self.db.save_sites([make_site([make_task(cron="0 8 * * *")])])
        self.run_tick(SUNDAY)
        self.assertEqual(self.state()["next_run_at"], "2026-09-27 08:00:00")

    def test_nothing_runs_for_a_disabled_task_or_site_or_while_locked(self) -> None:
        for site in (
            make_site([make_task(enabled=False)]),
            make_site(enabled=False),
        ):
            self.db.save_sites([site])
            self.assertEqual(self.scheduler.plan(SUNDAY), [])
            self.assertEqual(self.state(), {})
        self.db.save_sites([make_site()])
        self.plugin.locked = True
        self.assertEqual(self.scheduler.plan(SUNDAY), [])
        self.assertEqual(self.state(), {})

    def test_history_is_optional_for_scheduled_runs_only(self) -> None:
        import asyncio

        task = make_task(log_history=False)
        self.db.save_sites([make_site([task])])
        self.run_tick(SUNDAY)
        self.run_tick(datetime(2026, 9, 27, 5, 0, 10))
        self.assertEqual(self.plugin.history, [])
        asyncio.run(self.scheduler.run(make_site([task]), task, manual=True))
        self.assertEqual([(kind, manual) for kind, manual, _ in self.plugin.history], [(LOG_TYPE_TASK, True)])

    def test_a_manual_run_leaves_the_schedule_alone(self) -> None:
        import asyncio

        self.db.save_sites([make_site()])
        self.run_tick(SUNDAY)
        asyncio.run(self.scheduler.run(make_site(), make_task(), manual=True))
        state = self.state()
        self.assertEqual(state["next_run_at"], "2026-09-27 05:00:00")
        self.assertTrue(state["last_success"])


if __name__ == "__main__":
    unittest.main()
