"""Scheduler module managing daily sign-in execution and report formatting."""

import asyncio
import json
import logging
import random
from collections.abc import Collection
from datetime import date, datetime, time, timedelta
from typing import Any

from .adapters import CheckInResult, create_adapter, persist_writeback
from .http_client import RequestOptions, create_client_session
from .site_schema import (
    CHECKIN_SCHEDULE_FIXED,
    site_checkin_schedule,
    time_of_day_minutes,
)

logger = logging.getLogger("astrbot")

# Shown when a run is skipped because the configuration is still encrypted.
LOCKED_MESSAGE = "配置已加密未解锁，请在 Web 端输入密钥后重试"

# storage_metadata key prefix of the day each site last ran at its own time,
# so a restart never runs a site twice in one day.
_OWN_RUN_KEY = "own_checkin_day:"


def draw_checkin_time(
    schedule: dict[str, str],
    day: date,
    earliest: datetime | None = None,
) -> datetime | None:
    """Pick a site's check-in moment on ``day`` from its own schedule.

    Args:
        schedule: A normalized fixed or range schedule.
        day: The day to pick on.
        earliest: Nothing before this minute; the current minute itself is
            still usable, as it is for the global window.

    Returns:
        The moment, or None when ``earliest`` leaves nothing of the day's slot.
    """
    if schedule["mode"] == CHECKIN_SCHEDULE_FIXED:
        low = high = time_of_day_minutes(schedule["time"])
    else:
        low, high = time_of_day_minutes(schedule["start"]), time_of_day_minutes(schedule["end"])
    if earliest is not None and earliest.date() == day:
        low = max(low, earliest.hour * 60 + earliest.minute)
    if low > high:
        return None
    minutes = random.randint(low, high)
    return datetime.combine(day, time(minutes // 60, minutes % 60))


class CheckInScheduler:
    """Manager for scheduled daily check-ins and notification dispatch."""

    def __init__(self, plugin_inst: Any) -> None:
        """Initialize scheduler instance.

        Args:
            plugin_inst: Reference to parent Star plugin instance.
        """
        self.plugin = plugin_inst
        self._task: asyncio.Task | None = None
        self._running: bool = False
        self._last_run_date: str = ""
        self._today_target_time: str = ""
        self._tomorrow_target_time: str = ""
        self._today_date_str: str = ""
        self._persistence_lock = asyncio.Lock()
        self._history_lock = asyncio.Lock()
        # Sites with their own check-in time: the schedule each next moment
        # was drawn from, and that moment; and the day each last fired, read
        # from and written to the database.
        self._site_targets: dict[str, tuple[tuple[str, ...], datetime]] = {}
        self._site_last_run: dict[str, str] = {}
        # One check-in of a site at a time, across scheduled and manual runs.
        self._site_locks: dict[str, asyncio.Lock] = {}

    def reset_today_target_time(self) -> None:
        """Reset cached target time when settings are updated."""
        self._today_target_time = ""
        self._tomorrow_target_time = ""
        self._today_date_str = ""

    def get_next_target_info(self) -> dict[str, Any]:
        """Get next scheduled check-in time details.

        Returns:
            Dict containing enabled, is_manual, target_time, is_tomorrow, and display_text.
        """
        now = datetime.now()
        current_date = now.strftime("%Y-%m-%d")
        now_minutes = now.hour * 60 + now.minute

        settings = self.plugin.get_settings()
        enabled = settings.get("enabled", True)
        manual_time = settings.get("manual_target_time", "").strip()

        if not enabled:
            return {
                "enabled": False,
                "is_manual": False,
                "target_time": "--:--",
                "is_tomorrow": False,
                "display_text": "自动定时签到已禁用",
            }

        # Priority 1: Manual target time override (unrestricted by window config)
        if manual_time:
            try:
                mh, mm = map(int, manual_time.split(":"))
                target_mins = mh * 60 + mm
                is_tomorrow = (now_minutes > target_mins) or (self._last_run_date == current_date and now_minutes >= target_mins)
                day_prefix = "明日" if is_tomorrow else "今日"
                return {
                    "enabled": True,
                    "is_manual": True,
                    "target_time": f"{mh:02d}:{mm:02d}",
                    "is_tomorrow": is_tomorrow,
                    "display_text": f"下次预计签到: {day_prefix} {mh:02d}:{mm:02d} (手动)",
                }
            except Exception:
                pass

        # Priority 2: Automatic Random / Fixed calculation
        random_enabled = settings.get("random_enabled", True)
        start_time = settings.get("start_time", "08:00")
        end_time = settings.get("end_time", "10:30")
        fixed_time = settings.get("checkin_time", "08:30")

        if random_enabled:
            try:
                sh, sm = map(int, start_time.split(":"))
                eh, em = map(int, end_time.split(":"))
                start_mins = sh * 60 + sm
                end_mins = eh * 60 + em
                if end_mins <= start_mins:
                    end_mins = start_mins + 30
            except Exception:
                start_mins, end_mins = 8 * 60, 10 * 60 + 30

            # If today's window has already passed OR today has already run
            if now_minutes > end_mins or self._last_run_date == current_date:
                if not self._tomorrow_target_time or self._today_date_str != current_date:
                    target_mins = random.randint(start_mins, end_mins)
                    th = (target_mins // 60) % 24
                    tm = target_mins % 60
                    self._tomorrow_target_time = f"{th:02d}:{tm:02d}"
                    self._today_date_str = current_date
                return {
                    "enabled": True,
                    "is_manual": False,
                    "target_time": self._tomorrow_target_time,
                    "is_tomorrow": True,
                    "display_text": f"下次预计签到: 明日 {self._tomorrow_target_time}",
                }
            else:
                if self._today_date_str != current_date or not self._today_target_time:
                    pick_start = max(start_mins, now_minutes)
                    target_mins = random.randint(pick_start, end_mins)
                    th = (target_mins // 60) % 24
                    tm = target_mins % 60
                    self._today_target_time = f"{th:02d}:{tm:02d}"
                    self._today_date_str = current_date
                return {
                    "enabled": True,
                    "is_manual": False,
                    "target_time": self._today_target_time,
                    "is_tomorrow": False,
                    "display_text": f"下次预计签到: 今日 {self._today_target_time}",
                }
        else:
            try:
                fh, fm = map(int, fixed_time.split(":"))
                fixed_mins = fh * 60 + fm
            except Exception:
                fixed_mins = 8 * 60 + 30

            if now_minutes > fixed_mins or self._last_run_date == current_date:
                return {
                    "enabled": True,
                    "is_manual": False,
                    "target_time": fixed_time,
                    "is_tomorrow": True,
                    "display_text": f"下次预计签到: 明日 {fixed_time}",
                }
            else:
                return {
                    "enabled": True,
                    "is_manual": False,
                    "target_time": fixed_time,
                    "is_tomorrow": False,
                    "display_text": f"下次预计签到: 今日 {fixed_time}",
                }

    def start(self) -> None:
        """Start the background scheduler task."""
        if self._running:
            return
        self._running = True
        self._task = asyncio.create_task(self._scheduler_loop())
        logger.info("CheckInScheduler started background loop.")

    def _own_run_day(self, site_id: str) -> str:
        """The day a site last ran at its own time, surviving restarts."""
        if site_id not in self._site_last_run:
            db = getattr(self.plugin, "db", None)
            day = ""
            if db is not None:
                try:
                    day = db.get_metadata(f"{_OWN_RUN_KEY}{site_id}") or ""
                except Exception as exc:
                    logger.warning(f"Could not read a site's last own-time run: {exc}")
            self._site_last_run[site_id] = day
        return self._site_last_run[site_id]

    def _mark_own_run(self, site_id: str, day: str) -> None:
        """Record that a site ran at its own time today: once a day, success or not."""
        self._site_last_run[site_id] = day
        db = getattr(self.plugin, "db", None)
        if db is None:
            return
        try:
            db.set_metadata(f"{_OWN_RUN_KEY}{site_id}", day)
        except Exception as exc:
            logger.warning(f"Could not record a site's own-time run: {exc}")

    @staticmethod
    def _succeeded_today(site: dict[str, Any], today: str) -> bool:
        """Whether a site's stored state says it checked in successfully today."""
        return site.get("last_checkin_date") == today and bool(site.get("last_checkin_success"))

    def _site_target(self, site: dict[str, Any], now: datetime) -> datetime | None:
        """When a site with its own check-in time checks in next.

        Drawn once and kept, like the global target, until the site fires or
        its schedule changes. A site that already ran at its own time today,
        or checked in successfully some other way, is drawn for tomorrow. A
        target of an earlier day was never reached and is drawn again rather
        than run a day late; one earlier today is still run, so a busy loop or
        a locked vault delays a check-in instead of losing it. Targets are
        dropped while automatic check-in is off (see _scheduler_loop), so
        turning it back on does not catch up what it skipped.

        Returns:
            The moment, or None for a site that follows the global time or
            is disabled.
        """
        site_id = self._normalize_site_id(site.get("id"))
        schedule = site_checkin_schedule(site)
        if not site_id or schedule is None or site.get("enabled") is not True:
            if site_id:
                self._site_targets.pop(site_id, None)
            return None
        today = now.date()
        done_today = (
            self._own_run_day(site_id) == today.isoformat()
            or self._succeeded_today(site, today.isoformat())
        )
        key = tuple(schedule.values())
        cached = self._site_targets.get(site_id)
        if (
            cached is not None
            and cached[0] == key
            and cached[1].date() >= today
            and not (done_today and cached[1].date() == today)
        ):
            return cached[1]
        target = None if done_today else draw_checkin_time(schedule, today, earliest=now)
        if target is None:
            target = draw_checkin_time(schedule, today + timedelta(days=1))
        self._site_targets[site_id] = (key, target)
        return target

    def site_target_info(self, site: dict[str, Any]) -> dict[str, Any] | None:
        """A site's own next check-in time for the dashboard.

        Returns:
            Dict with target_time, is_tomorrow and display_text, or None when
            the site follows the global time, is disabled, or automatic
            check-in is off.
        """
        if not self.plugin.get_settings().get("enabled", True):
            return None
        now = datetime.now()
        target = self._site_target(site, now)
        if target is None:
            return None
        is_tomorrow = target.date() > now.date()
        hhmm = target.strftime("%H:%M")
        return {
            "target_time": hhmm,
            "is_tomorrow": is_tomorrow,
            "display_text": f"{'明日' if is_tomorrow else '今日'} {hhmm}",
        }

    def _due_sites(self, now: datetime) -> list[str]:
        """Sites with their own check-in time that are due now.

        Each runs at most once a day, recorded before the run so neither a
        failure nor a restart sends a second request that day. Nothing is
        consumed while the vault is locked, since nothing could run.
        """
        if self._is_locked():
            return []
        today = now.strftime("%Y-%m-%d")
        due: list[str] = []
        for site in self.plugin.get_sites():
            target = self._site_target(site, now)
            if target is None or target > now:
                continue
            site_id = self._normalize_site_id(site.get("id"))
            self._mark_own_run(site_id, today)
            self._site_targets.pop(site_id, None)
            due.append(site_id)
        return due

    def _site_lock(self, site_id: str) -> asyncio.Lock:
        """The lock serialising every check-in of one site."""
        return self._site_locks.setdefault(site_id, asyncio.Lock())

    def stop(self) -> None:
        """Stop the background scheduler task."""
        self._running = False
        if self._task and not self._task.done():
            self._task.cancel()
            logger.info("CheckInScheduler task cancelled.")

    @staticmethod
    def _update_site_checkin_state(
        site_config: dict[str, Any],
        result: CheckInResult,
        checked_at: datetime | None = None,
    ) -> None:
        """Apply a check-in result to a site configuration in memory."""
        checked_at = checked_at or datetime.now()
        site_config["last_checkin_date"] = checked_at.strftime("%Y-%m-%d")
        site_config["last_checkin_time"] = checked_at.strftime("%H:%M:%S")
        site_config["last_checkin_success"] = result.success
        site_config["last_quota"] = result.total_quota

    @staticmethod
    def _normalize_site_id(value: Any) -> str:
        """Normalize the shared site-ID contract used by the web API.

        Site IDs are transported and compared as trimmed strings.  The
        dashboard's ``getSiteId`` helper follows the same contract.
        """
        return str(value or "").strip()

    @classmethod
    def _find_site_config(
        cls, sites: list[dict[str, Any]], site_id: str
    ) -> dict[str, Any] | None:
        """Find a site using the same normalized ID rules as persistence."""
        normalized_site_id = cls._normalize_site_id(site_id)
        if not normalized_site_id:
            logger.warning("Skipping site lookup with an empty site ID")
            return None

        for site in sites:
            current_site_id = cls._normalize_site_id(site.get("id"))
            if not current_site_id:
                logger.warning(
                    "Skipping site without an ID while looking up site %s: %s",
                    normalized_site_id,
                    site.get("name", "<unnamed>"),
                )
                continue
            if current_site_id == normalized_site_id:
                return site
        return None

    def _record_checkin_history(self, results: list[CheckInResult], manual: bool) -> None:
        """Record check-in results using the same log type for all flows."""
        self.plugin.record_history(results, log_type="manual" if manual else "scheduled")

    async def _persist_checkin_results(
        self,
        results: list[CheckInResult],
        manual: bool,
        site_results_to_persist: list[CheckInResult] | None = None,
        checked_at: datetime | None = None,
    ) -> None:
        """Merge results into the latest configuration and record history.

        Check-in requests may run while the web UI edits sites or while another
        check-in is completing. Direct site state updates or reloading under a
        scheduler-wide lock keeps those operations consistent.
        """
        checked_at = checked_at or datetime.now()
        if site_results_to_persist:
            await self._persist_site_states(site_results_to_persist, checked_at)
        async with self._history_lock:
            self._record_checkin_history(results, manual)

    async def _persist_site_states(
        self,
        site_results_to_persist: list[CheckInResult],
        checked_at: datetime,
    ) -> None:
        """Store each result as its site's latest check-in state."""
        date_str = checked_at.strftime("%Y-%m-%d")
        time_str = checked_at.strftime("%H:%M:%S")

        async with self._persistence_lock:
            if site_results_to_persist:
                if hasattr(self.plugin, "update_site_checkin_state"):
                    for result in site_results_to_persist:
                        result_site_id = self._normalize_site_id(result.site_id)
                        if not result_site_id:
                            logger.warning(
                                "Skipping check-in result without a site ID: %s",
                                result.site_name,
                            )
                            continue
                        self.plugin.update_site_checkin_state(
                            site_id=result_site_id,
                            last_checkin_date=date_str,
                            last_checkin_time=time_str,
                            last_checkin_success=result.success,
                            last_quota=result.total_quota,
                        )
                else:
                    latest_sites = self.plugin.get_sites()
                    result_by_site_id: dict[str, CheckInResult] = {}
                    for result in site_results_to_persist:
                        result_site_id = self._normalize_site_id(result.site_id)
                        if not result_site_id:
                            logger.warning(
                                "Skipping check-in result without a site ID: %s",
                                result.site_name,
                            )
                            continue
                        result_by_site_id[result_site_id] = result
                    sites_changed = False
                    for site_config in latest_sites:
                        site_id = self._normalize_site_id(site_config.get("id"))
                        if not site_id:
                            logger.warning(
                                "Skipping persistence for site without an ID: %s",
                                site_config.get("name", "<unnamed>"),
                            )
                            continue
                        result = result_by_site_id.get(
                            site_id
                        )
                        if result is not None:
                            self._update_site_checkin_state(site_config, result, checked_at)
                            sites_changed = True

                    if sites_changed:
                        self.plugin.save_sites(latest_sites)

    async def _scheduler_loop(self) -> None:
        """Internal background loop running check-ins at configured daily time window."""
        while self._running:
            try:
                # Piggy-backs on the loop that already runs every 30 seconds, so
                # a vault locked outside of a check-in window is still reported.
                await self._poll_lock_alert()

                info = self.get_next_target_info()
                if info.get("enabled") and not info.get("is_tomorrow"):
                    now = datetime.now()
                    current_date = now.strftime("%Y-%m-%d")
                    current_hhmm = now.strftime("%H:%M")
                    target_time = info.get("target_time")

                    if current_hhmm == target_time and self._last_run_date != current_date:
                        self._last_run_date = current_date
                        logger.info(f"Triggering scheduled daily check-in at target time ({target_time})...")
                        results = await self.run_check_in_all(own_schedule=False)
                        # Every site may check in at its own time, leaving
                        # nothing for this run to report.
                        if results or not self._has_own_schedule_sites():
                            await self._send_report(results)

                if info.get("enabled"):
                    due = self._due_sites(datetime.now())
                    if due:
                        logger.info(f"Triggering check-in of {len(due)} site(s) at their own time...")
                        results = await self.run_check_in_all(only=due)
                        if results:
                            await self._send_report(results)
                else:
                    # Nothing skipped while off is caught up once back on.
                    self._site_targets.clear()

                await asyncio.sleep(30)
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in CheckInScheduler loop: {e}", exc_info=True)
                await asyncio.sleep(60)

    def _has_own_schedule_sites(self) -> bool:
        """Whether any enabled site checks in at its own time."""
        return any(
            site.get("enabled") is True and site_checkin_schedule(site) is not None
            for site in self.plugin.get_sites()
        )

    async def _send_report(self, results: list[CheckInResult]) -> None:
        """Push a scheduled run's briefing at the configured reporting level."""
        settings = self.plugin.get_settings()
        report_level = settings.get("report_level", "all")
        report_session = str(settings.get("lock_notify_session") or "").strip()
        report_text = self.format_report(results, report_level=report_level)
        if report_text:
            await self.plugin.send_notification(report_text, session=report_session)
        else:
            logger.info("Scheduled check-in completed; report skipped based on reporting level.")

    async def _poll_lock_alert(self) -> None:
        """Ask the plugin to push its locked-vault alert if one is due.

        Optional and self-contained: a plugin without the hook, or a push that
        fails, must never stop the check-in loop it shares.
        """
        poller = getattr(self.plugin, "poll_lock_alert", None)
        if not callable(poller):
            return
        try:
            await poller()
        except Exception as exc:
            logger.warning(f"Locked-vault alert check failed: {exc}", exc_info=True)

    def _is_locked(self) -> bool:
        """Return whether the plugin's configuration is encrypted but unlocked."""
        checker = getattr(self.plugin, "is_config_locked", None)
        if not callable(checker):
            return False
        try:
            return bool(checker())
        except Exception as exc:
            logger.warning(f"Could not determine vault state, assuming unlocked: {exc}")
            return False

    async def _skip_locked_run(self, manual: bool) -> list[CheckInResult]:
        """Record a skipped run so a locked vault is visible in the history.

        The scheduled task keeps firing on purpose: silently doing nothing would
        look identical to a healthy day with nothing to sign in for.
        """
        logger.warning("Skipping check-in run: %s", LOCKED_MESSAGE)
        results = [
            CheckInResult(
                site_id="",
                site_name="全部站点",
                success=False,
                message=LOCKED_MESSAGE,
            )
        ]
        async with self._history_lock:
            self._record_checkin_history(results, manual)
        return results

    async def run_check_in_all(
        self,
        manual: bool = False,
        force: bool = False,
        own_schedule: bool = True,
        only: Collection[str] | None = None,
    ) -> list[CheckInResult]:
        """Execute check-in for all enabled sites.

        Args:
            manual: Flag indicating if this was triggered manually.
            force: If True, execute check-in even if already signed in today.
            own_schedule: Include sites with their own check-in time. The
                global scheduled run leaves them to their own.
            only: Restrict the run to these site ids.

        Returns:
            List of CheckInResult objects.
        """
        if self._is_locked():
            return await self._skip_locked_run(manual)

        all_sites = self.plugin.get_sites()
        enabled_sites: list[dict[str, Any]] = []
        wanted = None if only is None else {self._normalize_site_id(site_id) for site_id in only}
        for site_config in all_sites:
            site_id = self._normalize_site_id(site_config.get("id"))
            if not site_id:
                logger.warning(
                    "Skipping site without an ID: %s",
                    site_config.get("name", "<unnamed>"),
                )
                continue
            if site_config.get("enabled") is not True:
                logger.info(
                    "Skipping site %s because enabled is not true",
                    site_id,
                )
                continue
            if wanted is not None and site_id not in wanted:
                continue
            if not own_schedule and site_checkin_schedule(site_config) is not None:
                continue
            enabled_sites.append(site_config)
        results: list[CheckInResult] = []
        settings = self.plugin.get_settings()

        if not enabled_sites:
            logger.info("No enabled check-in sites configured.")
            if only is None:
                self._clear_manual_target(settings)
            return results

        async with create_client_session(settings) as session:
            # Share browser clearance across the run while allowing each
            # challenged request its own browser attempt.
            cloudflare = self._cloudflare_context(settings)
            options = RequestOptions.from_settings(settings)
            for idx, site_config in enumerate(enabled_sites):
                site_id = self._normalize_site_id(site_config.get("id"))
                # One check-in of a site at a time, scheduled or manual. A run
                # that waited reads the state the other one left, so it does
                # not repeat a check-in that just succeeded.
                async with self._site_lock(site_id):
                    fresh = self._find_site_config(self.plugin.get_sites(), site_id)
                    if fresh is not None:
                        site_config = fresh
                    checked_at = datetime.now()
                    today_str = checked_at.strftime("%Y-%m-%d")
                    site_name = site_config.get("name", "<unnamed>")
                    last_date = site_config.get("last_checkin_date", "")
                    last_success = site_config.get("last_checkin_success", False)

                    # Skip if already signed in today successfully
                    if not force and last_date == today_str and last_success:
                        checkin_time = site_config.get("last_checkin_time", "")
                        msg = f"今日已完成签到 ({checkin_time})" if checkin_time else "今日已完成签到"
                        results.append(
                            CheckInResult(
                                site_id=site_id,
                                site_name=site_name,
                                success=True,
                                message=msg,
                                total_quota=site_config.get("last_quota", 0.0),
                            )
                        )
                        continue

                    if idx > 0:
                        await asyncio.sleep(random.uniform(1.5, 3.5))

                    adapter = create_adapter(
                        site_config,
                        session,
                        getattr(self.plugin, "acw_cache_file", None),
                        cloudflare,
                        options,
                    )
                    result = await adapter.check_in()
                    self._persist_site_writeback(site_id, adapter)
                    results.append(result)
                    # Stored before the lock is released, so it is the state
                    # the next run of this site reads.
                    await self._persist_site_states([result], checked_at)

        # Clear temporary manual_target_time override after check-in execution;
        # a site checking in at its own time leaves the global run's alone.
        if only is None:
            self._clear_manual_target(settings)

        async with self._history_lock:
            self._record_checkin_history(results, manual)
        return results

    def _clear_manual_target(self, settings: dict[str, Any]) -> None:
        """Drop the one-off global target time once the global run has fired."""
        if settings.get("manual_target_time"):
            settings["manual_target_time"] = ""
            self.plugin.save_settings(settings)
            self.reset_today_target_time()

    async def run_check_in_site(self, site_id: str, manual: bool = True) -> CheckInResult | None:
        """Force a check-in for one configured site, ignoring today's skip state.

        Args:
            site_id: ID of the configured site to check in.
            manual: Flag indicating whether this was triggered manually.

        Returns:
            The check-in result, or None if the site does not exist.
        """
        all_sites = self.plugin.get_sites()
        normalized_site_id = self._normalize_site_id(site_id)
        site_config = self._find_site_config(all_sites, normalized_site_id)
        if site_config is None:
            return None

        if self._is_locked() or site_config.get("locked"):
            return CheckInResult(
                site_id=normalized_site_id,
                site_name=str(site_config.get("name") or ""),
                success=False,
                message=LOCKED_MESSAGE,
            )

        settings = self.plugin.get_settings()
        async with self._site_lock(normalized_site_id):
            checked_at = datetime.now()
            async with create_client_session(settings) as session:
                adapter = create_adapter(
                    site_config,
                    session,
                    getattr(self.plugin, "acw_cache_file", None),
                    self._cloudflare_context(settings),
                    RequestOptions.from_settings(settings),
                )
                result = await adapter.check_in()
                self._persist_site_writeback(normalized_site_id, adapter)
            await self._persist_site_states([result], checked_at)

        async with self._history_lock:
            self._record_checkin_history([result], manual)
        return result

    def _cloudflare_context(self, settings: dict[str, Any]) -> Any:
        """Build the run's Cloudflare context, or None when the plugin offers none.

        Optional on purpose, like the lock-alert hook: a context that cannot be
        built costs the run its challenge handling, never the run itself.
        """
        factory = getattr(self.plugin, "cloudflare_context", None)
        if not callable(factory):
            return None
        try:
            return factory(settings)
        except Exception as exc:
            logger.warning(f"Cloudflare handling unavailable for this run: {exc}", exc_info=True)
            return None

    def _persist_site_writeback(self, site_id: str, adapter: Any) -> None:
        """Store config values the adapter discovered while running."""
        if not site_id:
            return
        db = getattr(self.plugin, "db", None)
        if db is None:
            return
        persist_writeback(db, site_id, getattr(adapter, "writeback", None))

    @staticmethod
    def build_history_entries(
        results: list[CheckInResult],
        log_type: str,
        timestamp: str,
        manual: bool | None = None,
    ) -> list[dict[str, Any]]:
        """Build one history entry per site result.

        A batch run is stored as a separate row per site so that every history
        entry, and the detail view built from it, covers exactly one task.

        Args:
            results: Results of one run.
            log_type: ``scheduled``, ``manual``, ``test`` or ``task``.
            timestamp: Shared timestamp for every row of this run.
            manual: Whether a user started the run; by default, whether
                ``log_type`` is ``manual``.

        Returns:
            Entry dictionaries ready for ``record_history_entries``.
        """
        return [
            {
                "timestamp": timestamp,
                "type": log_type,
                "manual": log_type == "manual" if manual is None else manual,
                "success": bool(result.success),
                "report": CheckInScheduler.format_result_line(result),
                "details": [result.to_dict()],
            }
            # Reversed because every row of one run shares a timestamp and the
            # drawer lists newest first: this makes the sites read top-down in
            # the order they were checked.
            for result in reversed(results)
        ]

    @staticmethod
    def _clean_result_message(message: str, success: bool = True) -> str:
        """Strip raw JSON, HTML, or verbose HTTP dumps from result messages."""
        raw = (message or "").strip()
        if not raw:
            return "签到成功" if success else "未知失败原因"

        # Check if the message is or embeds a JSON object
        if raw.startswith(("HTTP ", "{", "[")) or '{"' in raw or '":' in raw:
            # Try extracting human-readable message if embedded in JSON
            try:
                json_str = raw
                if "{" in raw and "}" in raw:
                    json_str = raw[raw.find("{") : raw.rfind("}") + 1]
                parsed = json.loads(json_str)
                if isinstance(parsed, dict):
                    human = parsed.get("message") or parsed.get("msg") or parsed.get("detail")
                    if not human and isinstance(parsed.get("error"), dict):
                        human = parsed["error"].get("message") or parsed["error"].get("detail")
                    elif not human and parsed.get("error"):
                        human = str(parsed["error"])
                    if human:
                        msg_str = str(human).strip()
                        if len(msg_str) > 80:
                            return f"{msg_str[:77]}..."
                        return msg_str
            except Exception:
                pass

            # If it's a success and no human message was extracted, don't dump raw JSON/HTTP
            if success:
                return "签到成功"
            # For failures, show at most a concise status
            if raw.startswith("HTTP "):
                return raw.split(":", 1)[0].strip()
            return "请求异常或返回非预期的响应格式"

        if raw.startswith(("<", "http://", "https://")):
            return "签到成功" if success else "服务器返回异常网页内容"

        if len(raw) > 80:
            return "签到成功" if success else f"{raw[:77]}..."

        return raw

    @staticmethod
    def format_result_line(result: CheckInResult) -> str:
        """Format one result as a single report line.

        Also used as the stored report of a per-site history entry, so the
        history and the broadcast briefing read identically.

        Args:
            result: The result to describe.

        Returns:
            One formatted line:
            - Success: [成功] 站点名称 | 余额变化（如有） (余额: $X.XX)
            - Failure: [失败]/[Token失效] 站点名称 | 失败原因
        """
        if result.success:
            status_str = "[成功]"
            parts: list[str] = []
            if result.gained_quota > 0:
                parts.append(f"+${result.gained_quota:.2f}")
            else:
                clean_msg = CheckInScheduler._clean_result_message(result.message, success=True)
                if clean_msg and clean_msg != "签到成功" and not clean_msg.startswith("额度增加"):
                    parts.append(clean_msg)

            if result.total_quota > 0:
                parts.append(f"(余额: ${result.total_quota:.2f})")

            if parts:
                detail_str = " ".join(parts)
            else:
                detail_str = "签到成功"

            return f"{status_str} {result.site_name} | {detail_str}"

        if result.expired:
            status_str = "[Token失效]"
        else:
            status_str = "[失败]"

        error_msg = CheckInScheduler._clean_result_message(result.message, success=False)
        return f"{status_str} {result.site_name} | {error_msg}"

    @staticmethod
    def format_report(results: list[CheckInResult], report_level: str = "all") -> str:
        """Format check-in results into a clean markdown report card.

        Args:
            results: List of CheckInResult objects.
            report_level: Reporting verbosity level ("all" or "failure_only").

        Returns:
            Formatted markdown string, or empty string if report_level is
            "failure_only" and all sites succeeded.
        """
        if not results:
            return "未配置有效的中转站签到目标。"

        if report_level == "failure_only":
            failed_results = [r for r in results if not r.success]
            if not failed_results:
                return ""
            lines = [
                "⚠️ API 中转站自动签到异常提醒",
                "━━━━━━━━━━━━━━━━━━━━",
            ]
            for r in failed_results:
                lines.append(CheckInScheduler.format_result_line(r))
            lines.append("━━━━━━━━━━━━━━━━━━━━")
            lines.append(
                f"统计: 共检测 {len(results)} 个站点，其中 {len(failed_results)} 个签到失败，请及时处理！"
            )
            return "\n".join(lines)

        lines = ["每日 API 中转站自动签到简报", "━━━━━━━━━━━━━━━━━━━━"]
        success_count = 0
        total_quota_sum = 0.0

        for r in results:
            if r.success:
                success_count += 1
            if r.total_quota > 0:
                total_quota_sum += r.total_quota
            lines.append(CheckInScheduler.format_result_line(r))

        lines.append("━━━━━━━━━━━━━━━━━━━━")
        failed_count = len(results) - success_count
        if failed_count > 0:
            summary_line = f"完成统计: {success_count}/{len(results)} 成功 | 失败: {failed_count}"
        else:
            summary_line = f"完成统计: {success_count}/{len(results)}"
        if total_quota_sum > 0:
            summary_line += f" | 总余额估算: ${total_quota_sum:.2f}"
        lines.append(summary_line)

        return "\n".join(lines)
