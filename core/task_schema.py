"""Scheduled tasks: per-site HTTP requests on a cron expression or a random interval.

A task belongs to a site and is sent through that site's adapter (see
``BaseCheckInAdapter.run_task``), so it shares the site's proxy, fingerprint,
credentials, Cloudflare handling and acw_sc__v2 solving. A task may also solve
a station's proof of work first (``pow_purpose``, see core/pow.py). This module
holds what has no network in it: the shape of a task, its validation, and when
it runs.

Two schedules are offered:

* **cron** — a standard five-field crontab expression (minute, hour, day of
  month, month, day of week), evaluated in the local time zone. Day of week
  follows crontab: 0 and 7 are Sunday. APScheduler, which evaluates the other
  fields, counts from Monday, so that field is translated here.
* **interval** — after every run the next one is drawn at random between a
  minimum and a maximum number of minutes.
"""

from __future__ import annotations

import json
import random
from datetime import datetime, timedelta
from typing import Any

from .pow import normalize_pow_purpose
from .site_schema import normalize_headers

SCHEDULE_CRON = "cron"
SCHEDULE_INTERVAL = "interval"
SCHEDULES = (SCHEDULE_CRON, SCHEDULE_INTERVAL)
TASK_METHODS = ("GET", "POST")

MIN_INTERVAL_MINUTES = 1
MAX_INTERVAL_MINUTES = 7 * 24 * 60
DEFAULT_INTERVAL_MINUTES = (60, 120)
MAX_TASKS_PER_SITE = 20
MAX_BODY_CHARS = 64 * 1024

# The task fields kept in the plain config column; the rest (headers, body)
# may carry secrets and are sealed by the vault. See core/storage.py.
PLAIN_TASK_FIELDS = (
    "id",
    "name",
    "enabled",
    "schedule",
    "cron",
    "interval_min",
    "interval_max",
    "method",
    "url",
    "credential_id",
    "log_history",
    # The challenge to solve first, empty for none; see core/pow.py.
    "pow_purpose",
)
SECRET_TASK_FIELDS = ("headers", "body")

_DOW_NAMES = ("sun", "mon", "tue", "wed", "thu", "fri", "sat")


class ScheduleError(ValueError):
    """A schedule that cannot be evaluated; the message says why, in Chinese."""


# ----------------------------------------------------------------------
# Normalization and validation
# ----------------------------------------------------------------------
def _to_minutes(raw: Any, default: int) -> int:
    try:
        value = int(float(raw))
    except (TypeError, ValueError):
        return default
    return max(MIN_INTERVAL_MINUTES, min(value, MAX_INTERVAL_MINUTES))


def normalize_task(raw: Any, index: int = 0) -> dict[str, Any]:
    """Normalize one task, filling every field with a usable value.

    Normalization never rejects: a half-filled task from the editor keeps what
    it has. :func:`validate_task` says whether it can run.
    """
    source = raw if isinstance(raw, dict) else {}
    schedule = str(source.get("schedule") or "").strip().lower()
    method = str(source.get("method") or "").strip().upper()
    interval_min = _to_minutes(source.get("interval_min"), DEFAULT_INTERVAL_MINUTES[0])
    interval_max = _to_minutes(source.get("interval_max"), DEFAULT_INTERVAL_MINUTES[1])
    body = source.get("body")
    purpose = str(source.get("pow_purpose") or "").strip()
    return {
        "id": str(source.get("id") or f"task_{index + 1}").strip(),
        "name": str(source.get("name") or "").strip(),
        "enabled": source.get("enabled", True) is not False,
        "schedule": schedule if schedule in SCHEDULES else SCHEDULE_CRON,
        # Runs of whitespace collapsed, so the same expression always compares equal.
        "cron": " ".join(str(source.get("cron") or "").split()),
        "interval_min": min(interval_min, interval_max),
        "interval_max": max(interval_min, interval_max),
        "method": method if method in TASK_METHODS else "GET",
        "url": str(source.get("url") or "").strip(),
        "credential_id": str(source.get("credential_id") or "").strip(),
        "headers": normalize_headers(source.get("headers")),
        "body": "" if body is None else str(body)[:MAX_BODY_CHARS],
        "log_history": source.get("log_history", True) is not False,
        # Preserve invalid nonempty input for validation instead of disabling PoW.
        "pow_purpose": normalize_pow_purpose(purpose) or purpose,
    }


def normalize_tasks(raw: Any) -> list[dict[str, Any]]:
    """Normalize a site's task list, dropping duplicate ids and any beyond the cap."""
    if not isinstance(raw, list):
        return []
    tasks: list[dict[str, Any]] = []
    seen: set[str] = set()
    for index, item in enumerate(raw):
        if not isinstance(item, dict):
            continue
        task = normalize_task(item, index)
        if task["id"] in seen:
            continue
        seen.add(task["id"])
        tasks.append(task)
        if len(tasks) >= MAX_TASKS_PER_SITE:
            break
    return tasks


def task_label(task: dict[str, Any]) -> str:
    """How a task is named to the user."""
    return str(task.get("name") or "").strip() or "未命名任务"


def validate_task(task: dict[str, Any]) -> str:
    """Why ``task`` cannot run, or ``""`` when it can."""
    url = str(task.get("url") or "")
    if not url:
        return "请填写请求 URL"
    if not (url.startswith(("http://", "https://", "/"))):
        return "URL 须以 http:// 或 https:// 开头，或以 / 开头表示站点 Base URL 下的路径"
    purpose = str(task.get("pow_purpose") or "").strip()
    if purpose and not normalize_pow_purpose(purpose):
        return "PoW 题目用途无效：请至少填写一个英文字母、数字、_ 或 -"
    if task.get("schedule") == SCHEDULE_CRON:
        try:
            cron_trigger(str(task.get("cron") or ""))
        except ScheduleError as exc:
            return str(exc)
    if task.get("method") == "POST" and str(task.get("body") or "").strip():
        try:
            json.loads(task["body"])
        except ValueError as exc:
            return f"JSON Body 不是合法的 JSON：{exc}"
    return ""


# ----------------------------------------------------------------------
# Schedules
# ----------------------------------------------------------------------
def _dow_value(token: str) -> int:
    token = token.strip().lower()
    if token in _DOW_NAMES:
        return _DOW_NAMES.index(token)
    if token.isdigit() and 0 <= int(token) <= 7:
        return int(token) % 7
    raise ScheduleError(f"星期字段中的「{token}」无效，应为 0-7（0 与 7 都是周日）或 sun-sat")


def _crontab_days_of_week(field: str) -> str:
    """Translate a crontab day-of-week field into APScheduler's numbering.

    Crontab counts Sunday as 0 (or 7); APScheduler counts Monday as 0, so an
    expression handed over unchanged would run a day late. The field is
    expanded into its days and rewritten as an explicit list.
    """
    if field in ("*", "?"):
        return "*"
    days: set[int] = set()
    for part in field.split(","):
        base, _, step_text = part.partition("/")
        step = 1
        if step_text:
            if not step_text.isdigit() or int(step_text) < 1:
                raise ScheduleError(f"星期字段中的步长「{step_text}」无效")
            step = int(step_text)
        if base in ("*", "?"):
            start, end = 0, 6
        elif "-" in base:
            first, _, last = base.partition("-")
            start, end = _dow_value(first), _dow_value(last)
            if last.strip() == "7":
                end = 7  # "5-7" is Friday to Sunday
            if end < start:
                raise ScheduleError(f"星期范围「{base}」的起点不能晚于终点")
        else:
            start = end = _dow_value(base)
            if step_text:
                end = 6  # "1/2" is every other day from Monday
        days.update(day % 7 for day in range(start, end + 1, step))
    # APScheduler: mon=0 ... sun=6.
    return ",".join(str(value) for value in sorted((day + 6) % 7 for day in days))


def cron_trigger(expression: str) -> Any:
    """An APScheduler trigger for a five-field crontab expression.

    Raises:
        ScheduleError: The expression is empty or invalid, or APScheduler,
            which AstrBot ships, cannot be imported.
    """
    fields = expression.split()
    if not fields:
        raise ScheduleError("请填写 cron 表达式")
    if len(fields) != 5:
        raise ScheduleError(f"cron 表达式应有 5 个字段（分 时 日 月 星期），当前为 {len(fields)} 个")
    try:
        from apscheduler.triggers.cron import CronTrigger
    except ImportError as exc:  # pragma: no cover - AstrBot depends on it
        raise ScheduleError("当前环境缺少 apscheduler，无法解析 cron 表达式") from exc
    minute, hour, day, month, day_of_week = fields
    try:
        return CronTrigger(
            minute=minute,
            hour=hour,
            day=day,
            month=month,
            day_of_week=_crontab_days_of_week(day_of_week),
        )
    except ScheduleError:
        raise
    except (ValueError, TypeError) as exc:
        raise ScheduleError(f"cron 表达式无效：{exc}") from exc


def _local(moment: datetime) -> datetime:
    """A naive local time, the form every timestamp of this plugin takes."""
    return moment.astimezone().replace(tzinfo=None) if moment.tzinfo else moment


def next_cron_run(expression: str, after: datetime) -> datetime | None:
    """The first time ``expression`` fires strictly after ``after`` (naive local)."""
    trigger = cron_trigger(expression)
    aware = (after if after.tzinfo else after.astimezone()).astimezone(trigger.timezone)
    # get_next_fire_time includes its start; a microsecond on keeps the
    # instant just run from being returned again.
    moment = trigger.get_next_fire_time(None, aware + timedelta(microseconds=1))
    return _local(moment) if moment is not None else None


def next_run(task: dict[str, Any], after: datetime, rng: random.Random | None = None) -> datetime | None:
    """When ``task`` next runs, counting from ``after`` (naive local)."""
    if task.get("schedule") == SCHEDULE_INTERVAL:
        low = int(task.get("interval_min") or DEFAULT_INTERVAL_MINUTES[0])
        high = max(low, int(task.get("interval_max") or low))
        seconds = (rng or random).uniform(low * 60, high * 60)
        return (after + timedelta(seconds=seconds)).replace(microsecond=0)
    return next_cron_run(str(task.get("cron") or ""), after)


def schedule_key(task: dict[str, Any]) -> str:
    """Identifies a task's schedule; a change means its next run is recomputed."""
    if task.get("schedule") == SCHEDULE_INTERVAL:
        return f"interval|{task.get('interval_min')}|{task.get('interval_max')}"
    return f"cron|{task.get('cron')}"


def preview_schedule(task: dict[str, Any], now: datetime, count: int = 3) -> tuple[list[str], str]:
    """The next ``count`` run times of a cron schedule, or why there are none.

    An interval schedule has no fixed times; its description is returned as
    the only entry.
    """
    task = normalize_task(task)
    if task["schedule"] == SCHEDULE_INTERVAL:
        low, high = task["interval_min"], task["interval_max"]
        span = f"{low} 分钟" if low == high else f"{low} ~ {high} 分钟"
        return [f"每次运行后随机等待 {span}"], ""
    runs: list[str] = []
    moment = now
    try:
        for _ in range(count):
            upcoming = next_cron_run(task["cron"], moment)
            if upcoming is None:
                break
            runs.append(upcoming.strftime("%Y-%m-%d %H:%M"))
            moment = upcoming
    except ScheduleError as exc:
        return [], str(exc)
    if not runs:
        return [], "该 cron 表达式今后不会再触发"
    return runs, ""


def split_task(task: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    """Split a normalized task into its plain and its secret half."""
    plain = {key: task[key] for key in PLAIN_TASK_FIELDS}
    secret = {key: task[key] for key in SECRET_TASK_FIELDS}
    return plain, secret


def join_tasks(plain: Any, secrets: Any) -> list[dict[str, Any]]:
    """Rebuild a task list from the stored halves; missing secrets stay empty."""
    if not isinstance(plain, list):
        return []
    secrets = secrets if isinstance(secrets, dict) else {}
    joined = []
    for item in plain:
        if not isinstance(item, dict):
            continue
        secret = secrets.get(str(item.get("id") or ""))
        joined.append({**item, **(secret if isinstance(secret, dict) else {})})
    return normalize_tasks(joined)
