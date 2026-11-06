"""Main plugin entry point for AstrBot scheduled check-in plugin."""

import logging
import os
from collections.abc import AsyncGenerator
from dataclasses import replace
from datetime import datetime, timedelta
from math import isfinite
from pathlib import Path
from typing import Any

from astrbot.api.event import AstrMessageEvent, MessageChain, MessageEventResult, filter
from astrbot.api.star import Context, Star, register
from astrbot.api.web import error_response, file_response, json_response, request
from astrbot.core.utils.astrbot_path import get_astrbot_plugin_data_path

from .core.adapters import create_adapter, persist_writeback
from .core.browser import (
    BROWSER_CHANNELS,
    BrowserSolver,
    BrowserUnavailable,
    playwright_installed,
)
from .core.cloudflare import (
    CloudflareContext,
    CloudflareOptions,
    normalize_cloudflare_settings,
)
from .core.crypto import VaultError, encode_bytes
from .core.dependencies import (
    ReinstallError,
    astrbot_pip_environment,
    cleanup_leftovers,
    curl_cffi_status,
    download_chromium,
    install_playwright,
    playwright_status,
    reinstall_curl_cffi,
    reinstall_running,
)
from .core.http_client import (
    RequestOptions,
    create_client_session,
    get_impersonate_options,
    mldsa_support,
    normalize_impersonate,
)
from .core.lock_notifier import LockNotifier
from .core.scheduler import LOCKED_MESSAGE, CheckInScheduler
from .core.site_schema import (
    NEW_API_USER_HEADER,
    SITE_TYPE_NEW_API,
    normalize_site_type,
)
from .core.storage import DEFAULT_SETTINGS, SLOT_WEBAUTHN, DatabaseManager
from .core.task_scheduler import LOG_TYPE_TASK, TaskScheduler
from .core.task_schema import (
    normalize_tasks,
    preview_schedule,
    task_label,
    validate_task,
)

logger = logging.getLogger("astrbot")

# Fixed WebAuthn user handle. The vault is a single local secret, not a
# multi-user account system, so one stable handle is all that is needed.
_PASSKEY_USER_HANDLE = b"astrbot-checkin-vault"

# Bounds on one activity query. Monthly aggregation happens in memory, so a
# busy site must not be able to make a single request load unbounded rows.
SITE_ACTIVITY_MAX_RECORDS = 20000
SITE_ACTIVITY_LOG_BATCH_SIZE = 500


async def _read_json_body() -> tuple[bool, Any]:
    """Parse the current request body without leaking JSON decode failures."""
    try:
        payload = await request.json()
    except Exception:
        return False, None
    if payload is None:
        return False, None
    return True, payload


@register(
    "astrbot_plugin_scheduled_check_in",
    "Soulter",
    "LLM API 中转站自动签到插件，支持 Pages 可视化配置与定时广播简报",
    "1.5.0",
)
class ScheduledCheckInPlugin(Star):
    """Star plugin managing auto sign-ins for API relay stations."""

    def __init__(self, context: Context, config: dict[str, Any] | None = None) -> None:
        """Initialize plugin and storage paths.

        Args:
            context: AstrBot plugin Context object.
            config: Optional configuration dictionary.
        """
        super().__init__(context, config)
        self.data_dir: Path = Path(get_astrbot_plugin_data_path()) / "astrbot_plugin_scheduled_check_in"
        self.data_dir.mkdir(parents=True, exist_ok=True)

        self.db = DatabaseManager(self.data_dir / "data.db", legacy_data_dir=self.data_dir)
        self.acw_cache_file: Path = self.data_dir / "acw_sc_v2_cache.json"
        # Served at the real AstrBot origin rather than from pages/, which
        # AstrBot would auto-discover and render inside the sandboxed iframe.
        self.passkey_page_file: Path = Path(__file__).parent / "webauthn" / "passkey.html"

        # One headless browser for the plugin's lifetime, launched on the first
        # challenge nothing else got past and closed again once idle.
        self.browser_solver = BrowserSolver()
        self.scheduler = CheckInScheduler(self)
        self.task_scheduler = TaskScheduler(self)
        self.lock_notifier = LockNotifier(
            is_locked=self.is_config_locked,
            get_target=self._get_lock_notify_session,
            was_sent=self._lock_alert_sent,
            mark_sent=self._set_lock_alert_sent,
            send=self._push_session_message,
        )
        self._register_routes()

    async def initialize(self) -> None:
        """Lifecycle method called after plugin initialization."""
        self.scheduler.start()
        self.task_scheduler.start()
        try:
            # Files a curl_cffi reinstall could not delete while they were loaded.
            cleanup_leftovers(astrbot_pip_environment()[1])
        except Exception as exc:
            logger.warning(f"Cleaning up after a curl_cffi reinstall failed: {exc}")
        logger.info("ScheduledCheckInPlugin initialized successfully.")

    async def terminate(self) -> None:
        """Lifecycle method called when plugin is stopping or unloading."""
        self.scheduler.stop()
        self.task_scheduler.stop()
        await self.browser_solver.aclose()
        logger.info("ScheduledCheckInPlugin terminated successfully.")

    # ------------------------------------------------------------------
    # Data Storage Utilities
    # ------------------------------------------------------------------
    def get_sites(self) -> list[dict[str, Any]]:
        """Read configured sites from SQLite database.

        Returns:
            List of site configuration dictionaries.
        """
        try:
            return self.db.get_sites()
        except Exception as e:
            logger.error(f"Error reading sites from database: {e}", exc_info=True)
            return []

    def get_sites_for_display(self) -> list[dict[str, Any]]:
        """Read sites for the dashboard, withholding OAuth session cookies.

        Returns:
            List of site configuration dictionaries safe to send to the browser.
        """
        try:
            return self.db.get_sites_for_display()
        except Exception as e:
            logger.error(f"Error reading sites for display: {e}", exc_info=True)
            return []

    def is_config_locked(self) -> bool:
        """Return whether encryption is on but no key has been supplied."""
        try:
            return bool(self.db.vault.locked)
        except Exception as e:
            logger.error(f"Error reading vault state: {e}", exc_info=True)
            return False

    def save_sites(self, sites_data: list[dict[str, Any]]) -> None:
        """Write site configurations to SQLite database.

        Args:
            sites_data: List of site dictionaries.
        """
        try:
            self.db.save_sites(sites_data)
        except Exception as e:
            logger.error(f"Error saving sites to database: {e}", exc_info=True)

    def update_site_checkin_state(
        self,
        site_id: str,
        last_checkin_date: str,
        last_checkin_time: str,
        last_checkin_success: bool,
        last_quota: float | None = None,
    ) -> None:
        """Update check-in status and quota for a single site in SQLite database.

        Args:
            site_id: ID of the site to update.
            last_checkin_date: YYYY-MM-DD string.
            last_checkin_time: HH:MM:SS string.
            last_checkin_success: Success boolean flag.
            last_quota: Balance quota float.
        """
        try:
            self.db.update_site_checkin_state(
                site_id=site_id,
                last_checkin_date=last_checkin_date,
                last_checkin_time=last_checkin_time,
                last_checkin_success=last_checkin_success,
                last_quota=last_quota,
            )
        except Exception as e:
            logger.error(f"Error updating site check-in state in database: {e}", exc_info=True)

    def get_settings(self) -> dict[str, Any]:
        """Read plugin settings from SQLite database.

        Returns:
            Settings dictionary.
        """
        try:
            return self.db.get_settings()
        except Exception as e:
            logger.error(f"Error reading settings from database: {e}", exc_info=True)
            return dict(DEFAULT_SETTINGS)

    def save_settings(
        self,
        settings_data: dict[str, Any],
        *,
        rearm_lock_alert: bool = False,
    ) -> bool:
        """Write settings to SQLite database and optionally rearm lock alerts.

        Args:
            settings_data: Settings dictionary.
            rearm_lock_alert: Atomically clear the persisted one-shot alert
                flag and process-local delivery state when the alert target changes.

        Returns:
            ``True`` when the write succeeds, otherwise ``False``.
        """
        try:
            self.db.save_settings(settings_data, rearm_lock_alert=rearm_lock_alert)
            if rearm_lock_alert and hasattr(self, "lock_notifier"):
                self.lock_notifier.rearm_after_target_change()
            return True
        except Exception as e:
            logger.error(f"Error saving settings to database: {e}", exc_info=True)
            return False

    def cloudflare_context(self, settings: dict[str, Any] | None = None) -> CloudflareContext:
        """Create the Cloudflare context for one client session's worth of requests."""
        settings = self.get_settings() if settings is None else settings
        return CloudflareContext(CloudflareOptions.from_settings(settings), browser=self.browser_solver)

    def record_history(
        self,
        results: list[Any],
        log_type: str = "scheduled",
        manual: bool | None = None,
    ) -> None:
        """Record check-in results into the history table, one entry per site.

        A batch run writes a separate row for every site instead of one
        aggregated row, so each history entry — and its detail view — describes
        exactly one site's task and request chain. The broadcast briefing still
        combines them; only storage is split.

        Args:
            results: List of CheckInResult objects.
            log_type: Type of log entry ("scheduled", "manual", "test", "task").
            manual: Whether a user started the run; see build_history_entries.
        """
        try:
            entries = CheckInScheduler.build_history_entries(
                results,
                log_type,
                datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                manual=manual,
            )
            if not entries:
                return
            self.db.record_history_entries(entries)
        except Exception as e:
            logger.error(f"Error recording history to database: {e}", exc_info=True)

    def read_history_logs(
        self,
        limit: int | None = 100,
        before_id: int | None = None,
        start_date: str | None = None,
        end_date: str | None = None,
        site_id: str | None = None,
        exclude_type: str | None = None,
    ) -> list[dict[str, Any]]:
        """Read history log entries from SQLite database.

        Args:
            limit: Maximum number of logs to return. ``None`` returns all matches.
            before_id: Optional log ID cursor.
            start_date: Optional inclusive start date (YYYY-MM-DD).
            end_date: Optional inclusive end date (YYYY-MM-DD).
            site_id: Optional site filter, resolved through the index table.
            exclude_type: Optional log type to leave out.

        Returns:
            List of history log entries.
        """
        try:
            return self.db.read_history_logs(
                limit=limit,
                before_id=before_id,
                start_date=start_date,
                end_date=end_date,
                site_id=site_id,
                exclude_type=exclude_type,
            )
        except Exception as e:
            logger.error(f"Error reading history logs from database: {e}", exc_info=True)
            return []

    def count_history_logs(
        self,
        start_date: str | None = None,
        end_date: str | None = None,
    ) -> int:
        """Count total history log entries in SQLite database."""
        try:
            return self.db.count_history_logs(start_date=start_date, end_date=end_date)
        except Exception as e:
            logger.error(f"Error counting history logs from database: {e}", exc_info=True)
            return 0

    def clear_history_logs(self) -> None:
        """Clear all history log entries from SQLite database."""
        try:
            self.db.clear_history_logs()
        except Exception as e:
            logger.error(f"Error clearing history logs from database: {e}", exc_info=True)

    # ------------------------------------------------------------------
    # Web API Routes for Pages Dashboard
    # ------------------------------------------------------------------
    def _register_routes(self) -> None:
        """Register custom plugin REST API routes with AstrBot."""
        prefix = "/astrbot_plugin_scheduled_check_in"
        routes = [
            ("/api/sites", self.api_get_sites, ["GET"], "获取站点列表"),
            ("/api/sites", self.api_save_sites, ["POST"], "保存站点配置"),
            ("/api/sites/test", self.api_test_site, ["POST"], "测试站点连接"),
            ("/api/sites/probe-new-api-user", self.api_probe_new_api_user, ["POST"], "探测 new-api-user"),
            ("/api/sites/recheckin", self.api_recheckin_site, ["POST"], "重新签到单个站点"),
            ("/api/sites/activity", self.api_get_site_activity, ["GET"], "获取站点签到日历与余额变化"),
            ("/api/sites/tasks/run", self.api_run_site_task, ["POST"], "立即运行定时任务"),
            ("/api/tasks/preview", self.api_preview_task_schedule, ["POST"], "预览定时任务触发时间"),
            ("/api/checkin/run", self.api_run_checkin, ["POST"], "触发一键打卡"),
            ("/api/settings", self.api_get_settings, ["GET"], "获取设置"),
            ("/api/settings", self.api_save_settings, ["POST"], "保存设置"),
            ("/api/settings/target_time", self.api_save_custom_target_time, ["POST"], "设置自定义下次签到时间"),
            ("/api/cloudflare/browser/check", self.api_check_browser, ["POST"], "检测无头浏览器"),
            ("/api/dependencies/curl_cffi/reinstall", self.api_reinstall_curl_cffi, ["POST"], "重新安装 curl_cffi"),
            ("/api/dependencies/playwright", self.api_get_playwright_status, ["GET"], "获取 Playwright 状态"),
            ("/api/dependencies/playwright/install", self.api_install_playwright, ["POST"], "安装 Playwright"),
            ("/api/dependencies/playwright/chromium", self.api_download_chromium, ["POST"], "下载 Chromium"),
            ("/api/vault", self.api_get_vault, ["GET"], "获取加密状态"),
            ("/api/vault/enable", self.api_enable_vault, ["POST"], "启用配置加密"),
            ("/api/vault/unlock", self.api_unlock_vault, ["POST"], "输入密钥解锁配置"),
            ("/api/vault/lock", self.api_lock_vault, ["POST"], "立即锁定配置"),
            ("/api/vault/disable", self.api_disable_vault, ["POST"], "关闭配置加密"),
            ("/api/vault/reset", self.api_reset_vault, ["POST"], "忘记密钥并清空密文"),
            ("/api/vault/slots", self.api_get_slots, ["GET"], "获取密钥槽位列表"),
            (
                "/api/vault/slots/webauthn/begin-register",
                self.api_begin_register_passkey,
                ["POST"],
                "开始注册通行密钥",
            ),
            (
                "/api/vault/slots/webauthn/finish-register",
                self.api_finish_register_passkey,
                ["POST"],
                "完成注册通行密钥",
            ),
            (
                "/api/vault/slots/webauthn/begin-unlock",
                self.api_begin_unlock_passkey,
                ["POST"],
                "开始通行密钥解锁",
            ),
            (
                "/api/vault/unlock/webauthn",
                self.api_unlock_with_passkey,
                ["POST"],
                "使用通行密钥解锁",
            ),
            ("/api/vault/slots/remove", self.api_remove_slot, ["POST"], "删除密钥槽位"),
            ("/passkey", self.page_passkey, ["GET"], "通行密钥管理页面"),
            ("/api/logs", self.api_get_logs, ["GET"], "获取打卡日志"),
            ("/api/logs/clear", self.api_clear_logs, ["POST"], "清空打卡日志"),
        ]

        for path, handler, methods, desc in routes:
            self.context.register_web_api(
                route=f"{prefix}{path}",
                view_handler=handler,
                methods=methods,
                desc=desc,
            )
            self.context.register_web_api(
                route=path,
                view_handler=handler,
                methods=methods,
                desc=desc,
            )

    async def api_get_sites(self) -> Any:
        """Web API: Get sites.

        The list is always returned so the dashboard can show what is
        configured; while the vault is locked the protected fields come back
        withheld and each site carries ``locked: true``.

        Returns:
            JSON response.
        """
        sites = self.get_sites_for_display()
        for site in sites:
            # A site's own next check-in time, for the table; absent when it
            # follows the global one.
            try:
                target = self.scheduler.site_target_info(site)
            except Exception as exc:
                logger.warning(f"Could not work out a site's check-in time: {exc}")
                target = None
            if target is not None:
                site["checkin_target"] = target
        return json_response(sites)

    async def api_save_sites(self) -> Any:
        """Web API: Save sites.

        Returns:
            JSON response.
        """
        parsed, sites = await _read_json_body()
        if not parsed:
            return error_response("请求体必须是合法 JSON")
        if not isinstance(sites, list) or not all(
            isinstance(site, dict) for site in sites
        ):
            return error_response("站点配置必须是对象数组")
        for site in sites:
            if site.get("locked"):
                continue  # a locked site's stored tasks are kept, not replaced
            for task in normalize_tasks(site.get("tasks")):
                problem = validate_task(task)
                if problem:
                    return error_response(
                        f"站点「{site.get('name') or ''}」的定时任务「{task_label(task)}」：{problem}"
                    )
        self.save_sites(sites)
        try:
            # Show a new or changed schedule's next run straight away.
            self.task_scheduler.plan()
        except Exception as exc:
            logger.warning(f"Could not schedule tasks after saving: {exc}", exc_info=True)
        return json_response({"status": "ok", "message": "站点配置保存成功"})

    async def api_preview_task_schedule(self) -> Any:
        """Web API: The next run times of a task's schedule, or why it is invalid.

        Returns:
            JSON response with ``runs`` (formatted times) and ``error``.
        """
        parsed, task = await _read_json_body()
        if not parsed or not isinstance(task, dict):
            return error_response("请求体必须是合法 JSON 对象")
        runs, error = preview_schedule(task, datetime.now())
        return json_response({"status": "ok", "runs": runs, "error": error})

    async def api_run_site_task(self) -> Any:
        """Web API: Run one scheduled task now, as the editor currently has it.

        The dashboard posts the whole site from its editor, unsaved changes
        included, and the id of the task to run; the stored OAuth secrets are
        merged in as for a connection test. The run is recorded in history and
        as the task's latest run, but leaves its schedule alone.

        Returns:
            JSON response with the result and the task's run state.
        """
        parsed, body = await _read_json_body()
        if not parsed or not isinstance(body, dict) or not isinstance(body.get("site"), dict):
            return error_response("请求体必须包含站点配置 site 与任务 task_id")
        site = body["site"]
        if self.is_config_locked() or site.get("locked"):
            return error_response(LOCKED_MESSAGE)
        task_id = str(body.get("task_id") or "").strip()
        task = next((item for item in normalize_tasks(site.get("tasks")) if item["id"] == task_id), None)
        if task is None:
            return error_response("未找到该定时任务")
        problem = validate_task(task)
        if problem:
            return error_response(problem)
        site = self.db.merge_stored_oauth_secrets(site)
        result = await self.task_scheduler.run(site, task, manual=True)
        site_id = str(site.get("id") or "").strip()
        state = self.db.get_task_states().get((site_id, task_id), {}) if site_id else {}
        return json_response({"status": "ok", "result": result.to_dict(), "state": state})

    async def api_test_site(self) -> Any:
        """Web API: Test site connection.

        Returns:
            JSON response with connection test result.
        """
        parsed, site_config = await _read_json_body()
        if not parsed:
            return error_response("请求体必须是合法 JSON")
        if not isinstance(site_config, dict):
            return error_response("站点配置必须是对象")
        if self.is_config_locked() or site_config.get("locked"):
            return error_response(LOCKED_MESSAGE)
        # The dashboard never holds a login's station secrets, and without them
        # the test could only log in again, spending the day's sign-in on
        # login-as-check-in stations.
        site_config = self.db.merge_stored_oauth_secrets(site_config)
        settings = self.get_settings()
        async with create_client_session(settings) as session:
            adapter = create_adapter(
                site_config,
                session,
                self.acw_cache_file,
                self.cloudflare_context(settings),
                RequestOptions.from_settings(settings),
            )
            result = await adapter.test_connection()
            site_id = str(site_config.get("id") or "").strip()
            if site_id:
                persist_writeback(self.db, site_id, adapter.writeback)
            self.record_history([result], log_type="test")
            return json_response(result.to_dict())

    async def api_probe_new_api_user(self) -> Any:
        """Web API: Fetch the station's numeric user id for ``new-api-user``.

        New-API scopes a Cookie session to a numeric account id via this header.
        One-API has no such concept and does not return an id, in which case the
        failure is reported plainly rather than guessed at.

        Returns:
            JSON response with the probed id, or an error explaining why not.
        """
        parsed, site_config = await _read_json_body()
        if not parsed or not isinstance(site_config, dict):
            return error_response("请求体必须是合法 JSON 对象")
        if self.is_config_locked() or site_config.get("locked"):
            return error_response(LOCKED_MESSAGE)
        if not str(site_config.get("base_url") or "").strip():
            return error_response("请先填写 Base URL")

        if normalize_site_type(site_config.get("type")) != SITE_TYPE_NEW_API:
            return error_response("仅 New-API 框架支持 new-api-user，请将框架类型设为 New-API")

        try:
            # As for a connection test: the stored session, never a login.
            site_config = self.db.merge_stored_oauth_secrets(site_config)
            settings = self.get_settings()
            async with create_client_session(settings) as session:
                adapter = create_adapter(
                    site_config,
                    session,
                    self.acw_cache_file,
                    self.cloudflare_context(settings),
                    RequestOptions.from_settings(settings),
                )
                user_id, detail = await adapter.probe_new_api_user_id()
                site_id = str(site_config.get("id") or "").strip()
                if site_id:
                    # Reusing that session may refresh its access token, which
                    # retires the refresh cookie it presented, so the rotated
                    # secrets are kept. The headers are not: they come from an
                    # editor form that may never be saved.
                    persist_writeback(
                        self.db,
                        site_id,
                        replace(adapter.writeback, checkin_headers=None, balance_headers=None),
                    )
        except Exception as exc:
            logger.error(f"Error probing new-api-user: {exc}", exc_info=True)
            return error_response(f"探测失败: {exc}")

        if not user_id:
            return error_response(
                detail or "未能获取 new-api-user。One-API 没有该字段，若站点为 One-API 可忽略此项。"
            )
        return json_response(
            {
                "status": "ok",
                "user_id": user_id,
                "header": NEW_API_USER_HEADER,
                "message": f"已获取 {NEW_API_USER_HEADER} = {user_id}",
            }
        )

    async def api_recheckin_site(self) -> Any:
        """Web API: Force a check-in for one configured site."""
        parsed, body = await _read_json_body()
        if not parsed:
            return error_response("请求体必须是合法 JSON")
        if not isinstance(body, dict):
            return error_response("重新签到请求必须是对象")
        site_id = str(body.get("site_id", "")).strip()
        if not site_id:
            return error_response("缺少站点 ID")
        if self.is_config_locked():
            return error_response(LOCKED_MESSAGE)

        result = await self.scheduler.run_check_in_site(site_id, manual=True)
        if result is None:
            return error_response("站点不存在")

        return json_response({"status": "ok", "result": result.to_dict()})

    # ------------------------------------------------------------------
    # Site Activity (calendar + balance history)
    # ------------------------------------------------------------------
    def _read_site_activity_logs(
        self,
        site_id: str,
        start_date: str,
        end_date: str,
    ) -> tuple[list[dict[str, Any]], bool]:
        """Read monthly activity logs in bounded batches.

        The activity view needs chronological aggregation, but a malformed or
        unusually busy site must not make one request load an unbounded number
        of database rows. Logs are returned newest-first and the caller sorts
        the derived events before rendering them.

        Returns:
            A tuple containing the collected logs and whether the hard cap was
            reached while more matching records remained.
        """
        logs: list[dict[str, Any]] = []
        before_id: int | None = None

        while len(logs) < SITE_ACTIVITY_MAX_RECORDS:
            batch_limit = min(
                SITE_ACTIVITY_LOG_BATCH_SIZE,
                SITE_ACTIVITY_MAX_RECORDS - len(logs),
            )
            batch = self.read_history_logs(
                limit=batch_limit,
                before_id=before_id,
                start_date=start_date,
                end_date=end_date,
                site_id=site_id,
                # A frequent task would otherwise crowd the check-ins out.
                exclude_type=LOG_TYPE_TASK,
            )
            if not batch:
                return logs, False

            logs.extend(batch)
            next_before_id = batch[-1].get("id")
            if next_before_id is None:
                return logs, False
            before_id = int(next_before_id)
            if len(batch) < batch_limit:
                return logs, False

        remaining = self.read_history_logs(
            limit=1,
            before_id=before_id,
            start_date=start_date,
            end_date=end_date,
            site_id=site_id,
        )
        return logs, bool(remaining)

    async def api_get_site_activity(self) -> Any:
        """Web API: Get one site's monthly check-in calendar and balance history."""
        site_id = ""
        month = datetime.now().strftime("%Y-%m")
        try:
            if hasattr(request, "query") and request.query:
                site_id = str(request.query.get("site_id") or "").strip()
                query_month = str(request.query.get("month") or "").strip()
                if query_month:
                    month = query_month
        except Exception as e:
            logger.warning(f"Failed to parse site activity query params: {e}")

        if not site_id:
            return error_response("缺少站点 ID")

        try:
            month_start = datetime.strptime(f"{month}-01", "%Y-%m-%d")
        except ValueError:
            return error_response("月份格式必须为 YYYY-MM")

        month_end = (month_start.replace(day=28) + timedelta(days=4)).replace(day=1) - timedelta(days=1)
        month_start_str = month_start.strftime("%Y-%m-%d")
        month_end_str = month_end.strftime("%Y-%m-%d")

        # Read from the display view so a locked vault cannot leak secrets here.
        site = next(
            (
                item
                for item in self.get_sites_for_display()
                if str(item.get("id") or "").strip() == site_id
            ),
            None,
        )
        if site is None:
            return error_response("站点不存在")

        supports_balance = normalize_site_type(site.get("type")) == SITE_TYPE_NEW_API
        logs, history_truncated = self._read_site_activity_logs(
            site_id=site_id,
            start_date=month_start_str,
            end_date=month_end_str,
        )

        def as_bool(value: Any) -> bool:
            if isinstance(value, str):
                return value.strip().lower() in {"1", "true", "yes", "on"}
            return bool(value)

        def as_balance(value: Any) -> float | None:
            if not supports_balance or value is None:
                return None
            try:
                number = float(value)
            except (TypeError, ValueError):
                return None
            return round(number, 3) if isfinite(number) else None

        events: list[dict[str, Any]] = []
        for log in logs:
            timestamp = str(log.get("timestamp") or "")
            if len(timestamp) < 10:
                continue
            details = log.get("details")
            if not isinstance(details, list):
                continue
            for detail in details:
                if not isinstance(detail, dict):
                    continue
                detail_site_id = str(detail.get("site_id") or "").strip()
                if detail_site_id != site_id:
                    continue
                success = as_bool(detail.get("success"))
                events.append(
                    {
                        "timestamp": timestamp,
                        "date": timestamp[:10],
                        "time": timestamp[11:16] if len(timestamp) >= 16 else "",
                        "type": str(log.get("type") or "scheduled"),
                        "success": success,
                        "message": str(detail.get("message") or ""),
                        "gained_quota": as_balance(detail.get("gained_quota")) if success else None,
                        "balance": as_balance(detail.get("total_quota")) if success else None,
                    }
                )

        events.sort(key=lambda item: item["timestamp"])

        # Connection tests can provide a balance, but they do not count as a
        # check-in day. A day keeps the latest real check-in result. Scheduled
        # tasks were already left out when the logs were read.
        daily_checkins: dict[str, dict[str, Any]] = {}
        for event in events:
            if event["type"] == "test":
                continue
            daily_checkins[event["date"]] = {
                "date": event["date"],
                "time": event["time"],
                "status": "success" if event["success"] else "failure",
                "message": event["message"],
                "gained_quota": event["gained_quota"],
                "balance": None,
            }

        balance_history: list[dict[str, Any]] = []
        if supports_balance:
            daily_balances: dict[str, float] = {}
            for event in events:
                if event["balance"] is not None:
                    daily_balances[event["date"]] = event["balance"]
            for date_str, day in daily_checkins.items():
                day["balance"] = daily_balances.get(date_str)

            previous_balance: float | None = None
            for event in events:
                balance = event["balance"]
                if balance is None:
                    continue
                change = None if previous_balance is None else round(balance - previous_balance, 3)
                balance_history.append(
                    {
                        "timestamp": event["timestamp"],
                        "date": event["date"],
                        "time": event["time"],
                        "type": event["type"],
                        "message": event["message"],
                        "balance": balance,
                        "change": change,
                    }
                )
                previous_balance = balance

        current_balance = as_balance(site.get("last_quota"))
        current_balance_timestamp = " ".join(
            part
            for part in (
                str(site.get("last_checkin_date") or ""),
                str(site.get("last_checkin_time") or ""),
            )
            if part
        )

        latest_balance: float | None = None
        latest_balance_timestamp = ""
        if balance_history:
            latest_balance = balance_history[-1]["balance"]
            latest_balance_timestamp = balance_history[-1]["timestamp"]
        elif month == datetime.now().strftime("%Y-%m"):
            latest_balance = current_balance
            latest_balance_timestamp = current_balance_timestamp

        calendar_days = sorted(daily_checkins.values(), key=lambda item: item["date"])
        return json_response(
            {
                "site": {
                    "id": site_id,
                    "name": str(site.get("name") or site_id),
                    "type": str(site.get("type") or ""),
                },
                "supports_balance": supports_balance,
                "history_truncated": history_truncated,
                "history_record_limit": SITE_ACTIVITY_MAX_RECORDS if history_truncated else None,
                "month": month,
                "days": calendar_days,
                "balance_history": balance_history,
                "current_balance": current_balance,
                "current_balance_timestamp": current_balance_timestamp,
                "latest_balance": latest_balance,
                "latest_balance_timestamp": latest_balance_timestamp,
                "success_days": sum(day["status"] == "success" for day in calendar_days),
                "failure_days": sum(day["status"] == "failure" for day in calendar_days),
            }
        )

    async def api_run_checkin(self) -> Any:
        """Web API: Trigger instant check-in.

        Returns:
            JSON response with results.
        """
        parsed, body = await _read_json_body()
        if not parsed:
            return error_response("请求体必须是合法 JSON")
        if not isinstance(body, dict):
            return error_response("签到请求必须是对象")
        if self.is_config_locked():
            return error_response(LOCKED_MESSAGE)
        force = bool(body.get("force", False))
        results = await self.scheduler.run_check_in_all(manual=True, force=force)
        return json_response({"status": "ok", "results": [r.to_dict() for r in results]})

    async def api_get_settings(self) -> Any:
        """Web API: Get settings.

        Returns:
            JSON response.
        """
        settings = self.get_settings()
        target_info = self.scheduler.get_next_target_info()
        settings["target_info"] = target_info
        settings["today_target_time"] = target_info.get("display_text", "")
        settings["http_impersonate_options"] = get_impersonate_options()
        # How the per-request ML-DSA option applies to each fingerprint, so the
        # site editor can say what ticking it does under the current one.
        settings["http_impersonate_mldsa"] = {
            option: mldsa_support(option) for option in settings["http_impersonate_options"]
        }
        settings["cf_browser_channels"] = list(BROWSER_CHANNELS)
        settings["cf_browser_installed"] = playwright_installed()
        settings["playwright"] = self._playwright_status()
        settings["curl_cffi"] = {**curl_cffi_status(), "reinstalling": reinstall_running()}
        settings["vault"] = self.db.vault_status()
        return json_response(settings)

    async def api_save_settings(self) -> Any:
        """Web API: Save settings.

        Returns:
            JSON response.
        """
        parsed, data = await _read_json_body()
        if not parsed:
            return error_response("请求体必须是合法 JSON")
        if not isinstance(data, dict):
            return error_response("全局设置必须是对象")
        settings = self.get_settings()
        previous_notify_session = str(settings.get("lock_notify_session") or "").strip()
        settings.update(data)
        notify_session_changed = False
        if "max_history_records" in data:
            try:
                settings["max_history_records"] = max(0, int(data["max_history_records"]))
            except (ValueError, TypeError):
                settings["max_history_records"] = 0
        if "lock_notify_session" in data:
            notify_session = str(data["lock_notify_session"] or "").strip()
            settings["lock_notify_session"] = notify_session
            notify_session_changed = notify_session != previous_notify_session
        settings["http_impersonate"] = normalize_impersonate(
            settings.get("http_impersonate")
        )
        options = RequestOptions.from_settings(settings)
        settings["http_tls_mldsa"] = options.tls_mldsa
        settings["acw_sc_v2_auto_solve"] = options.solve_acw_sc_v2
        normalize_cloudflare_settings(settings)
        if not self.save_settings(settings, rearm_lock_alert=notify_session_changed):
            return error_response("全局设置保存失败")
        self.scheduler.reset_today_target_time()
        return json_response({"status": "ok", "message": "全局设置已更新"})

    async def api_check_browser(self) -> Any:
        """Web API: Launch the headless browser with the saved settings and name it.

        Installing Playwright is not the whole setup — a browser has to be
        found or downloaded too — so this is how a user learns it works
        before a challenge depends on it.

        Returns:
            JSON response naming the browser, or why none could be launched.
        """
        settings = self.get_settings()
        # The dashboard sends its unsaved form, so a channel can be tried first.
        parsed, body = await _read_json_body()
        if parsed and isinstance(body, dict):
            settings.update({k: v for k, v in body.items() if str(k).startswith("cf_browser_")})
        options = CloudflareOptions.from_settings(settings).browser
        try:
            label = await self.browser_solver.check(options)
        except BrowserUnavailable as exc:
            return error_response(str(exc))
        except Exception as exc:
            logger.warning(f"Browser check failed: {exc}", exc_info=True)
            return error_response(f"浏览器检测失败：{exc}")
        mode = "无头模式" if options.headless else "有界面模式"
        return json_response({"status": "ok", "browser": label, "message": f"已启动 {label}（{mode}）"})

    async def api_reinstall_curl_cffi(self) -> Any:
        """Web API: Reinstall curl_cffi through AstrBot's own pip installer.

        The fingerprint list is whatever the installed build ships, so this is
        how a deployment left on an old build gets the current ones. The new
        build is only imported once AstrBot restarts.

        Returns:
            JSON response with the installed and running versions.
        """
        try:
            installer, target_dir = astrbot_pip_environment()
            version = await reinstall_curl_cffi(installer, target_dir)
        except ReinstallError as exc:
            return error_response(str(exc))
        except Exception as exc:
            logger.warning(f"curl_cffi reinstall failed: {exc}", exc_info=True)
            return error_response(f"重新安装 curl_cffi 失败：{exc}（pip 的完整输出见 AstrBot 日志）")
        status = curl_cffi_status()
        return json_response({
            "status": "ok",
            "curl_cffi": {**status, "reinstalling": False},
            "message": f"已安装 curl_cffi {version}，重启 AstrBot 后生效",
        })

    @staticmethod
    def _playwright_status() -> dict[str, Any]:
        """Playwright's state for the dashboard; see core.dependencies.playwright_status."""
        try:
            target_dir = astrbot_pip_environment()[1]
        except Exception:  # only the commands shown depend on it
            target_dir = None
        return playwright_status(target_dir)

    async def api_get_playwright_status(self) -> Any:
        """Web API: Playwright's state, polled while an install or download runs.

        Returns:
            JSON response with what is installed and downloaded.
        """
        return json_response({"status": "ok", "playwright": self._playwright_status()})

    async def api_install_playwright(self) -> Any:
        """Web API: Install Playwright through AstrBot's own pip installer.

        Playwright is optional: only the headless-browser fallback needs it.
        It has not been imported before, so it is usable without a restart
        unless something it depends on was loaded at another version.

        Returns:
            JSON response with Playwright's new state.
        """
        try:
            installer, target_dir = astrbot_pip_environment()
            version = await install_playwright(installer, target_dir)
        except ReinstallError as exc:
            return error_response(str(exc))
        except Exception as exc:
            logger.warning(f"Playwright install failed: {exc}", exc_info=True)
            return error_response(f"安装 Playwright 失败：{exc}（pip 的完整输出见 AstrBot 日志）")
        status = self._playwright_status()
        if not status["loaded"]:
            message = f"已安装 Playwright {version}，重启 AstrBot 后生效"
        elif status["chromium"]["downloaded"]:
            message = f"已安装 Playwright {version}"
        else:
            message = f"已安装 Playwright {version}。本机没有 Chrome / Edge 时，还需下载 Chromium"
        return json_response({"status": "ok", "playwright": status, "message": message})

    async def api_download_chromium(self) -> Any:
        """Web API: Download the Chromium build Playwright drives.

        Needed only where neither Chrome nor Edge is installed, as on most
        Linux servers and in Docker.

        Returns:
            JSON response with Playwright's new state.
        """
        try:
            version = await download_chromium()
        except ReinstallError as exc:
            return error_response(str(exc))
        except Exception as exc:
            logger.warning(f"Chromium download failed: {exc}", exc_info=True)
            return error_response(f"下载 Chromium 失败：{exc}（完整输出见 AstrBot 日志）")
        return json_response({
            "status": "ok",
            "playwright": self._playwright_status(),
            "message": f"已下载 Chromium {version}",
        })

    async def api_save_custom_target_time(self) -> Any:
        """Web API: Save custom manual next target check-in time.

        Returns:
            JSON response.
        """
        parsed, body = await _read_json_body()
        if not parsed:
            return error_response("请求体必须是合法 JSON")
        if not isinstance(body, dict):
            return error_response("签到时间配置必须是对象")
        target_time = str(body.get("target_time", "")).strip()
        settings = self.get_settings()
        settings["manual_target_time"] = target_time
        self.save_settings(settings)
        self.scheduler.reset_today_target_time()
        return json_response({"status": "ok", "message": "下次签到时间已设置"})

    # ------------------------------------------------------------------
    # Vault Routes
    # ------------------------------------------------------------------
    async def api_get_vault(self) -> Any:
        """Web API: Report whether config encryption is on, and unlocked.

        Returns:
            JSON response with enabled, unlocked, and locked flags.
        """
        return json_response(self.db.vault_status())

    async def api_enable_vault(self) -> Any:
        """Web API: Turn on encryption and hand the new key to the user once.

        Returns:
            JSON response containing the generated key.
        """
        try:
            key = self.db.enable_encryption()
        except RuntimeError as exc:
            return error_response(str(exc))
        except Exception as exc:
            logger.error(f"Error enabling encryption: {exc}", exc_info=True)
            return error_response(f"启用加密失败: {exc}")
        return json_response(
            {
                "status": "ok",
                "key": key,
                "message": "加密已启用，请立即保存密钥。密钥不会再次显示，丢失后只能重置。",
                "vault": self.db.vault_status(),
            }
        )

    async def api_unlock_vault(self) -> Any:
        """Web API: Validate a supplied key and unlock protected fields.

        Returns:
            JSON response with the resulting vault state.
        """
        parsed, body = await _read_json_body()
        if not parsed or not isinstance(body, dict):
            return error_response("请求体必须是合法 JSON 对象")
        key = str(body.get("key", "") or "")
        try:
            self.db.unlock_encryption(key)
        except (VaultError, RuntimeError) as exc:
            return error_response(str(exc))
        except Exception as exc:
            logger.error(f"Error unlocking vault: {exc}", exc_info=True)
            return error_response(f"解锁失败: {exc}")
        return json_response(
            {"status": "ok", "message": "解锁成功", "vault": self.db.vault_status()}
        )

    async def api_lock_vault(self) -> Any:
        """Web API: Drop the in-memory key without disabling encryption.

        Returns:
            JSON response with the resulting vault state.
        """
        self.db.lock_encryption()
        return json_response(
            {"status": "ok", "message": "已锁定，下次操作需重新输入密钥", "vault": self.db.vault_status()}
        )

    async def api_disable_vault(self) -> Any:
        """Web API: Turn encryption off, rewriting protected fields as plaintext.

        Returns:
            JSON response with the resulting vault state.
        """
        try:
            self.db.disable_encryption()
        except VaultError as exc:
            return error_response(f"{exc}（关闭加密前必须先解锁）")
        except Exception as exc:
            logger.error(f"Error disabling encryption: {exc}", exc_info=True)
            return error_response(f"关闭加密失败: {exc}")
        return json_response(
            {"status": "ok", "message": "加密已关闭，敏感字段已还原为明文", "vault": self.db.vault_status()}
        )

    async def api_reset_vault(self) -> Any:
        """Web API: Discard unreadable ciphertext after a lost key.

        Site names, URLs, and history survive; credentials, custom headers, and
        proxies are cleared because they can no longer be decrypted.

        Returns:
            JSON response with the number of sites cleared.
        """
        parsed, body = await _read_json_body()
        if not parsed or not isinstance(body, dict):
            return error_response("请求体必须是合法 JSON 对象")
        if str(body.get("confirm", "")).strip().lower() != "reset":
            return error_response("重置需要二次确认")
        try:
            affected = self.db.reset_encryption()
        except Exception as exc:
            logger.error(f"Error resetting encryption: {exc}", exc_info=True)
            return error_response(f"重置失败: {exc}")
        return json_response(
            {
                "status": "ok",
                "cleared_sites": affected,
                "message": f"已清空 {affected} 个站点的凭据、请求头与代理，并关闭加密",
                "vault": self.db.vault_status(),
            }
        )

    # ------------------------------------------------------------------
    # Key Slot Routes (WebAuthn PRF)
    # ------------------------------------------------------------------
    @staticmethod
    @staticmethod
    def _host_to_rp_id(host: str) -> str:
        """Reduce a Host-style value to a bare hostname.

        The RP ID must be a domain with no port or scheme.
        """
        value = str(host or "").strip()
        if not value:
            return ""
        # A forwarding chain is comma separated; the first entry is the client's.
        value = value.split(",")[0].strip()
        if "//" in value:
            value = value.split("//", 1)[1]
        value = value.split("/", 1)[0]
        # Strip the port, taking care not to break an IPv6 literal.
        if value.startswith("["):
            return value.partition("]")[0].lstrip("[").lower()
        return value.split(":", 1)[0].lower()

    @classmethod
    def _current_rp_id(cls, override: Any = None) -> str:
        """Determine the WebAuthn RP ID for this request.

        A reverse proxy forwards to AstrBot on its own address, so the ``Host``
        header is the upstream one — deriving the RP ID from it yields something
        like ``127.0.0.1`` while the browser is really on the public domain, and
        the credential is then rejected. The page therefore reports its own
        ``location.hostname``, which is authoritative, and that is preferred
        over any header. Forwarding headers come next, with ``Host`` last.

        Args:
            override: Hostname reported by the page, if any.

        Returns:
            A bare lowercase hostname, or an empty string when undeterminable.
        """
        reported = cls._host_to_rp_id(override)
        if reported:
            return reported

        try:
            headers = request.headers
        except Exception:
            return ""

        forwarded_host = cls._host_to_rp_id(headers.get("x-forwarded-host"))
        if forwarded_host:
            return forwarded_host

        # RFC 7239: Forwarded: for=...;host=example.com;proto=https
        forwarded = str(headers.get("forwarded") or "")
        for part in forwarded.split(";"):
            key, _, value = part.strip().partition("=")
            if key.strip().lower() == "host":
                candidate = cls._host_to_rp_id(value.strip().strip('"'))
                if candidate:
                    return candidate

        return cls._host_to_rp_id(headers.get("host"))

    async def api_get_slots(self) -> Any:
        """Web API: List key slots.

        Readable while locked: the unlock page needs the credential ids and PRF
        salts before any key is available. None of it is secret.

        Returns:
            JSON response with the slots and the current RP ID.
        """
        reported = ""
        try:
            if hasattr(request, "query") and request.query:
                reported = request.query.get("rp_id") or ""
        except Exception:
            reported = ""
        rp_id = self._current_rp_id(reported)
        slots = self.db.list_slots()
        return json_response(
            {
                "slots": slots,
                "rp_id": rp_id,
                "vault": self.db.vault_status(),
                "matching_slots": [
                    slot["id"] for slot in slots if slot["rp_id"].lower() == rp_id
                ],
            }
        )

    async def api_begin_register_passkey(self) -> Any:
        """Web API: Start passkey registration.

        Requires an unlocked vault, since registering wraps the vault key.

        Returns:
            JSON response with the ceremony parameters.
        """
        if not self.db.vault.unlocked:
            return error_response("请先解锁配置，再注册通行密钥")
        _parsed, body = await _read_json_body()
        reported = body.get("rp_id") if isinstance(body, dict) else ""
        rp_id = self._current_rp_id(reported)
        if not rp_id:
            return error_response("无法确定当前域名，无法注册通行密钥")

        slots = self.db.list_slots()
        return json_response(
            {
                "status": "ok",
                "rp_id": rp_id,
                "rp_name": "AstrBot 定时签到",
                "user_id": encode_bytes(_PASSKEY_USER_HANDLE),
                "user_name": str(getattr(request, "username", "") or "astrbot"),
                "challenge": encode_bytes(os.urandom(32)),
                "prf_salt": encode_bytes(os.urandom(32)),
                # Stops the browser from silently creating a second credential
                # on an authenticator that already has one for this vault.
                "exclude_credentials": [
                    slot["credential_id"]
                    for slot in slots
                    if slot["credential_id"] and slot["rp_id"].lower() == rp_id
                ],
            }
        )

    async def api_finish_register_passkey(self) -> Any:
        """Web API: Store a registered passkey as a new key slot.

        The PRF output is the slot secret: it wraps the vault key and is then
        discarded. Nothing key-derived is written to disk.

        Returns:
            JSON response with the created slot.
        """
        parsed, body = await _read_json_body()
        if not parsed or not isinstance(body, dict):
            return error_response("请求体必须是合法 JSON 对象")
        try:
            slot = self.db.add_webauthn_slot(
                credential_id=str(body.get("credential_id", "")),
                prf_output=str(body.get("prf_output", "")),
                prf_salt=str(body.get("prf_salt", "")),
                rp_id=self._current_rp_id(body.get("rp_id")),
                label=str(body.get("label", "")).strip(),
                transports=body.get("transports"),
            )
        except (VaultError, RuntimeError) as exc:
            return error_response(str(exc))
        except Exception as exc:
            logger.error(f"Error registering passkey: {exc}", exc_info=True)
            return error_response(f"注册通行密钥失败: {exc}")
        return json_response(
            {
                "status": "ok",
                "message": "通行密钥已注册",
                "slot": slot,
                "vault": self.db.vault_status(),
            }
        )

    async def api_begin_unlock_passkey(self) -> Any:
        """Web API: Start a passkey unlock ceremony.

        Only slots registered for the current host are offered — a credential
        from another address cannot be asserted here and would just produce an
        opaque browser error.

        Returns:
            JSON response with the ceremony parameters.
        """
        _parsed, body = await _read_json_body()
        reported = body.get("rp_id") if isinstance(body, dict) else ""
        rp_id = self._current_rp_id(reported)
        if not rp_id:
            return error_response("无法确定当前域名，无法使用通行密钥")

        matching = self.db.list_slots_for_rp(rp_id)
        if not matching:
            others = sorted(
                {
                    slot["rp_id"]
                    for slot in self.db.list_slots()
                    if slot["type"] == SLOT_WEBAUTHN and slot["rp_id"]
                }
            )
            return error_response(
                "当前地址没有已注册的通行密钥"
                + (f"，已注册的地址：{', '.join(others)}" if others else ""),
                data={"registered_rp_ids": others},
            )

        return json_response(
            {
                "status": "ok",
                "rp_id": rp_id,
                "challenge": encode_bytes(os.urandom(32)),
                "allow_credentials": [
                    {
                        "id": slot["credential_id"],
                        "prf_salt": slot["prf_salt"],
                        "transports": slot["transports"],
                        "label": slot["label"],
                    }
                    for slot in matching
                ],
            }
        )

    async def api_unlock_with_passkey(self) -> Any:
        """Web API: Unlock the vault with a passkey PRF output.

        Returns:
            JSON response with the resulting vault state.
        """
        parsed, body = await _read_json_body()
        if not parsed or not isinstance(body, dict):
            return error_response("请求体必须是合法 JSON 对象")
        try:
            slot = self.db.unlock_with_webauthn(
                credential_id=str(body.get("credential_id", "")),
                prf_output=str(body.get("prf_output", "")),
            )
        except (VaultError, RuntimeError) as exc:
            return error_response(str(exc))
        except Exception as exc:
            logger.error(f"Error unlocking with passkey: {exc}", exc_info=True)
            return error_response(f"解锁失败: {exc}")
        return json_response(
            {
                "status": "ok",
                "message": f"已通过「{slot['label'] or '通行密钥'}」解锁",
                "slot": slot,
                "vault": self.db.vault_status(),
            }
        )

    async def api_remove_slot(self) -> Any:
        """Web API: Delete a key slot.

        Returns:
            JSON response with the resulting slot list.
        """
        parsed, body = await _read_json_body()
        if not parsed or not isinstance(body, dict):
            return error_response("请求体必须是合法 JSON 对象")
        slot_id = str(body.get("slot_id", "")).strip()
        if not slot_id:
            return error_response("缺少槽位 ID")
        try:
            removed = self.db.remove_slot(slot_id)
        except RuntimeError as exc:
            return error_response(str(exc))
        except Exception as exc:
            logger.error(f"Error removing key slot: {exc}", exc_info=True)
            return error_response(f"删除槽位失败: {exc}")
        if not removed:
            return error_response("槽位不存在")
        return json_response(
            {
                "status": "ok",
                "message": "槽位已删除",
                "slots": self.db.list_slots(),
                "vault": self.db.vault_status(),
            }
        )

    async def page_passkey(self) -> Any:
        """Serve the standalone passkey page.

        This page must run at the real AstrBot origin: the dashboard hosts
        plugin pages in a sandboxed iframe without ``allow-same-origin``, which
        gives them an opaque origin where WebAuthn cannot resolve an RP ID.

        Returns:
            The HTML page.
        """
        return file_response(
            self.passkey_page_file,
            content_type="text/html; charset=utf-8",
            headers={"Cache-Control": "no-store"},
        )

    async def api_get_logs(self) -> Any:
        """Web API: Get history logs with pagination and date filtering.

        Returns:
            JSON response with items, total, has_more, and next_before_id.
        """
        limit = 20
        before_id = None
        start_date = None
        end_date = None
        try:
            if hasattr(request, "query") and request.query:
                q_limit = request.query.get("limit")
                if q_limit is not None and str(q_limit).strip():
                    limit = max(1, min(100, int(q_limit)))
                q_before_id = request.query.get("before_id")
                if q_before_id is not None and str(q_before_id).strip():
                    before_id = int(q_before_id)
                # Storage normalizes these and ignores anything unparseable.
                start_date = request.query.get("start_date") or None
                end_date = request.query.get("end_date") or None
        except Exception as e:
            logger.warning(f"Failed to parse query params for /api/logs: {e}")

        logs = self.read_history_logs(
            limit=limit,
            before_id=before_id,
            start_date=start_date,
            end_date=end_date,
        )
        total = (
            self.count_history_logs(start_date=start_date, end_date=end_date)
            if before_id is None
            else None
        )
        has_more = len(logs) == limit
        next_before_id = logs[-1]["id"] if (has_more and logs) else None

        response_data: dict[str, Any] = {
            "items": logs,
            "has_more": has_more,
            "next_before_id": next_before_id,
        }
        if total is not None:
            response_data["total"] = total

        return json_response(response_data)

    async def api_clear_logs(self) -> Any:
        """Web API: Clear history logs.

        Returns:
            JSON response.
        """
        self.clear_history_logs()
        return json_response({"status": "ok", "message": "历史日志已清空"})

    # ------------------------------------------------------------------
    # Notification & Chat Commands
    # ------------------------------------------------------------------
    async def send_notification(self, text: str, session: str | None = None) -> None:
        """Log and dispatch notification text.

        Args:
            text: Markdown report text.
            session: Optional target unified_msg_origin session. If not provided,
                reads lock_notify_session from settings.
        """
        logger.info(f"CheckIn Notification:\n{text}")
        target_session = (session or str(self.get_settings().get("lock_notify_session") or "")).strip()
        if target_session:
            sent = await self._push_session_message(target_session, text)
            if sent:
                logger.info(f"Check-in notification successfully delivered to {target_session!r}.")
            else:
                logger.warning(f"Failed to deliver check-in notification to {target_session!r}.")

    # ------------------------------------------------------------------
    # Locked-Vault Alert
    # ------------------------------------------------------------------
    def _get_lock_notify_session(self) -> str:
        """Read the session that should receive the locked-vault alert."""
        return str(self.get_settings().get("lock_notify_session") or "").strip()

    def _lock_alert_sent(self) -> bool:
        """Return whether the locked-vault alert already went out.

        Returns:
            ``True`` when it has been sent, and also when the flag cannot be
            read: treating an unreadable flag as "already sent" keeps a broken
            database from turning the alert into a message every 30 seconds.
        """
        try:
            return bool(self.db.get_lock_notify_sent())
        except Exception as e:
            logger.error(f"Error reading locked-vault alert flag: {e}", exc_info=True)
            return True

    def _set_lock_alert_sent(self, sent: bool) -> bool:
        """Persist whether the locked-vault alert has been delivered.

        Returns:
            ``True`` when the state was written successfully. The notifier
            uses ``False`` to retry the write without sending the alert again.
        """
        try:
            self.db.set_lock_notify_sent(sent)
            return True
        except Exception as e:
            logger.error(f"Error saving locked-vault alert flag: {e}", exc_info=True)
            return False

    async def _push_session_message(self, session: str, text: str) -> bool:
        """Send one plain-text message to a unified_msg_origin session.

        Args:
            session: Target ``unified_msg_origin``, as typed by the operator.
            text: Message body.

        Returns:
            Whether a platform accepted the message. A malformed session or an
            adapter error is reported as ``False`` so the caller can retry.
        """
        try:
            return bool(
                await self.context.send_message(session, MessageChain().message(text))
            )
        except ValueError as e:
            logger.warning(f"Invalid notification session {session!r}: {e}")
            return False
        except Exception as e:
            logger.error(f"Error sending message to {session!r}: {e}", exc_info=True)
            return False

    async def poll_lock_alert(self) -> None:
        """Push the locked-vault alert if the vault just closed.

        Called by the scheduler loop; see :class:`~.core.lock_notifier.LockNotifier`
        for the once-per-lock guarantee.
        """
        await self.lock_notifier.poll()

    @filter.permission_type(filter.PermissionType.ADMIN, raise_error=False)
    @filter.command("清空签到日志")
    async def cmd_clear_logs(
        self,
        event: AstrMessageEvent,
    ) -> AsyncGenerator[MessageEventResult, None]:
        """清空历史签到日志记录"""
        self.clear_history_logs()
        yield event.plain_result("历史签到日志已成功清空！")

    @filter.permission_type(filter.PermissionType.ADMIN, raise_error=False)
    @filter.command("设置签到汇报")
    async def cmd_set_report_session(
        self,
        event: AstrMessageEvent,
    ) -> AsyncGenerator[MessageEventResult, None]:
        """将当前会话设置为自动签到结果与锁定提醒的唯一发送目标"""
        session = str(event.unified_msg_origin).strip()
        if not session:
            yield event.plain_result("无法获取当前会话标识 (UMO)，设置失败。")
            return

        settings = self.get_settings()
        previous_session = str(settings.get("lock_notify_session") or "").strip()
        settings["lock_notify_session"] = session
        session_changed = session != previous_session

        self.save_settings(settings, rearm_lock_alert=session_changed)

        level_desc = "仅失败项汇报" if settings.get("report_level") == "failure_only" else "完整汇报"
        yield event.plain_result(
            f"✅ 已成功将当前会话设置为通知推送地点！\n"
            f"📌 会话标识 (UMO): {session}\n"
            f"⚙️ 汇报等级: {level_desc}（可在 Web 仪表盘中调整）\n"
            f"💡 提示: 签到结果汇报与配置锁定告警将统一推送至此会话。"
        )

    @filter.permission_type(filter.PermissionType.ADMIN, raise_error=False)
    @filter.command("取消签到汇报")
    async def cmd_cancel_report_session(
        self,
        event: AstrMessageEvent,
    ) -> AsyncGenerator[MessageEventResult, None]:
        """取消自动签到结果与锁定提醒的会话推送"""
        settings = self.get_settings()
        if not settings.get("lock_notify_session"):
            yield event.plain_result("当前未设置通知推送会话。")
            return

        settings["lock_notify_session"] = ""
        self.save_settings(settings, rearm_lock_alert=True)
        yield event.plain_result("✅ 已取消通知推送，后续定时签到结果与锁定告警将不再推送至任何会话。")

    @filter.permission_type(filter.PermissionType.ADMIN, raise_error=False)
    @filter.command("签到")
    async def cmd_checkin(
        self,
        event: AstrMessageEvent,
    ) -> AsyncGenerator[MessageEventResult, None]:
        """手动触发中转站签到打卡并回复简报结果"""
        yield event.plain_result("正在批量请求中转站签到，请稍候...")
        results = await self.scheduler.run_check_in_all(manual=True)
        report = CheckInScheduler.format_report(results)
        yield event.plain_result(report)

    @filter.permission_type(filter.PermissionType.ADMIN, raise_error=False)
    @filter.command("签到状态")
    async def cmd_status(
        self,
        event: AstrMessageEvent,
    ) -> AsyncGenerator[MessageEventResult, None]:
        """查看当前配置的所有中转站连接状态与余额明细"""
        if self.is_config_locked():
            yield event.plain_result(LOCKED_MESSAGE)
            return

        sites = self.get_sites()
        if not sites:
            yield event.plain_result("当前未配置任何中转站，请前往 Pages 页面添加！")
            return

        yield event.plain_result("正在查询各中转站余额与连通性...")
        results = []
        settings = self.get_settings()
        async with create_client_session(settings) as session:
            cloudflare = self.cloudflare_context(settings)
            options = RequestOptions.from_settings(settings)
            for site in sites:
                site_id = str(site.get("id", "")).strip()
                if not site_id:
                    logger.warning(
                        "Skipping status check for site without an ID: %s",
                        site.get("name", "<unnamed>"),
                    )
                    continue
                if site.get("enabled") is not True:
                    logger.info(
                        "Skipping status check for site %s because enabled is not true",
                        site_id,
                    )
                    continue
                adapter = create_adapter(site, session, self.acw_cache_file, cloudflare, options)
                res = await adapter.test_connection()
                persist_writeback(self.db, site_id, adapter.writeback)
                results.append(res)

        report = CheckInScheduler.format_report(results)
        yield event.plain_result(report)
