"""SQLite data storage manager for AstrBot scheduled check-in plugin."""

from __future__ import annotations

import json
import logging
import sqlite3
import threading
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from .crypto import (
    Vault,
    decode_bytes,
    decode_key,
    derive_kek,
    encode_bytes,
    generate_dek,
    generate_key,
    generate_salt,
    is_ciphertext,
    is_locked_placeholder,
    unwrap_dek,
    wrap_dek,
)
from .http_client import DEFAULT_IMPERSONATE, normalize_impersonate
from .site_schema import (
    ACTION_BALANCE,
    ACTION_CHECKIN,
    CRED_COOKIE,
    CRED_TOKEN,
    holds_refresh_cookie,
    normalize_action,
    normalize_credential_type,
    normalize_credentials,
    normalize_headers,
    normalize_path,
    normalize_provider_cookies,
    normalize_site_type,
)
from .task_schema import join_tasks, normalize_tasks, split_task

logger = logging.getLogger("astrbot")

DEFAULT_SETTINGS: dict[str, Any] = {
    "enabled": True,
    "random_enabled": True,
    "start_time": "08:00",
    "end_time": "10:30",
    "checkin_time": "08:30",
    "http_ssl_verify": True,
    "http_timeout_seconds": 15,
    "http_impersonate": DEFAULT_IMPERSONATE,
    # Add ML-DSA to the TLS handshake of fingerprints that lack it, for every
    # request of every site (see core/http_client.py RequestOptions).
    "http_tls_mldsa": False,
    # Solve an Aliyun acw_sc__v2 challenge wherever one comes back.
    "acw_sc_v2_auto_solve": True,
    "manual_target_time": "",
    "auto_cleanup_logs": True,
    "history_retention_days": 0,
    "max_history_records": 0,
    # Session (unified_msg_origin) that receives scheduled check-in result reports
    # and locked-vault alerts. Empty disables push notifications.
    "lock_notify_session": "",
    # Reporting verbosity level: "all" (full briefing) or "failure_only" (alerts on failures only).
    "report_level": "all",
    # When Cloudflare challenges a request, re-issue it directly from a headless
    # browser that solves the challenge (see core/browser.py). Needs Playwright.
    "cf_browser_fallback": True,
    "cf_browser_headless": True,
    "cf_browser_channel": "auto",
    "cf_browser_timeout_seconds": 60,
}

# Vault bookkeeping lives in the settings table but is managed separately from
# the user-facing settings dictionary.
VAULT_ENABLED_KEY = "vault_enabled"
VAULT_VERIFIER_KEY = "vault_verifier"
_VAULT_KEYS = (VAULT_ENABLED_KEY, VAULT_VERIFIER_KEY)

# Records that the locked-vault alert has already gone out for the current lock,
# so a restart cannot turn "notify once" into "notify on every startup".
LOCK_NOTIFY_SENT_KEY = "lock_notify_sent"

# Settings rows the plugin manages itself. They live in the same table but are
# kept out of the user-facing dictionary the dashboard reads and writes back.
_INTERNAL_KEYS = (*_VAULT_KEYS, LOCK_NOTIFY_SENT_KEY)

# Key slot types. The user-key slot is created with encryption and can never be
# removed, so losing every passkey can never lock the data away for good.
SLOT_USER_KEY = "user_key"
SLOT_WEBAUTHN = "webauthn_prf"
USER_KEY_SLOT_ID = "slot_user_key"

# WebAuthn PRF outputs are 32 bytes.
_PRF_BYTES = 32

# Columns holding vault-protected values.
_SENSITIVE_COLUMNS = ("proxy", "credentials", "checkin_headers", "balance_headers", "tasks_secrets")

# Columns added to the sites table after the credential-list schema, with
# their definitions, so an existing table can be brought up to date in place.
_ADDED_SITE_COLUMNS = {
    # Scheduled tasks, split like the actions: schedule, method and URL in the
    # clear; headers and body, which may carry secrets, sealed by the vault.
    "tasks_config": "TEXT NOT NULL DEFAULT ''",
    "tasks_secrets": "TEXT NOT NULL DEFAULT ''",
    # Whether the site's requests solve vsllm.cc's proof of work (core/pow.py).
    "vs_pow": "INTEGER NOT NULL DEFAULT 0",
}

_SITES_SCHEMA = """
    CREATE TABLE IF NOT EXISTS sites (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        type TEXT NOT NULL,
        base_url TEXT NOT NULL,
        proxy TEXT NOT NULL DEFAULT '',
        credentials TEXT NOT NULL DEFAULT '',
        checkin_config TEXT NOT NULL DEFAULT '',
        checkin_headers TEXT NOT NULL DEFAULT '',
        balance_config TEXT NOT NULL DEFAULT '',
        balance_headers TEXT NOT NULL DEFAULT '',
        tasks_config TEXT NOT NULL DEFAULT '',
        tasks_secrets TEXT NOT NULL DEFAULT '',
        vs_pow INTEGER NOT NULL DEFAULT 0,
        enabled INTEGER NOT NULL DEFAULT 1,
        last_checkin_date TEXT,
        last_checkin_time TEXT,
        last_checkin_success INTEGER,
        last_quota REAL,
        display_order INTEGER NOT NULL DEFAULT 0,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
    );
"""


class DatabaseManager:
    """Manages SQLite database storage for sites, settings, and check-in history."""

    def __init__(
        self,
        db_path: Path | str,
        legacy_data_dir: Path | str | None = None,
        vault: Vault | None = None,
    ) -> None:
        """Initialize the database manager.

        Args:
            db_path: Path to the SQLite database file.
            legacy_data_dir: Optional directory to look for legacy JSON files to migrate.
            vault: Vault used to protect credentials, headers, and proxies. A
                fresh disabled vault is created when omitted.
        """
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self.vault = vault if vault is not None else Vault()
        self._cleanup_settings_cache: tuple[bool, int, int] | None = None

        self._init_db()
        if legacy_data_dir:
            self._migrate_legacy_json(Path(legacy_data_dir))
        self._ensure_history_site_index()
        self.vault.adopt(self.is_encryption_enabled())

    def _get_connection(self) -> sqlite3.Connection:
        """Create and configure a SQLite connection."""
        conn = sqlite3.connect(
            str(self.db_path),
            timeout=30.0,
            check_same_thread=False,
        )
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA synchronous=NORMAL;")
        conn.execute("PRAGMA foreign_keys=ON;")
        return conn

    @contextmanager
    def _connection(self) -> Iterator[sqlite3.Connection]:
        """Open a connection that commits on success and always closes.

        Leaving the handle open keeps the database file locked on Windows and
        leaks one connection per call, so every access goes through here.
        """
        conn = self._get_connection()
        try:
            with conn:
                yield conn
        finally:
            conn.close()

    @staticmethod
    def _normalize_nonnegative_int(value: Any) -> int:
        """Normalize a user-provided non-negative integer setting."""
        try:
            return max(0, int(value))
        except (TypeError, ValueError):
            return 0

    @staticmethod
    def _normalize_cleanup_enabled(value: Any) -> bool:
        """Normalize boolean values used by automatic history cleanup."""
        if isinstance(value, str):
            return value.strip().lower() in {"1", "true", "yes", "on"}
        return bool(value)

    @staticmethod
    def _normalize_history_date(value: Any) -> str | None:
        """Normalize a history date filter to YYYY-MM-DD or ignore it."""
        if value is None:
            return None
        normalized = str(value).strip()
        if not normalized:
            return None
        try:
            return datetime.strptime(normalized, "%Y-%m-%d").strftime("%Y-%m-%d")
        except ValueError:
            return None

    @classmethod
    def _history_date_bounds(
        cls,
        start_date: Any,
        end_date: Any,
    ) -> tuple[str | None, str | None]:
        """Build normalized inclusive timestamp bounds for history queries."""
        normalized_start = cls._normalize_history_date(start_date)
        normalized_end = cls._normalize_history_date(end_date)
        return (
            f"{normalized_start} 00:00:00" if normalized_start else None,
            f"{normalized_end} 23:59:59" if normalized_end else None,
        )

    def _get_cleanup_settings(self) -> tuple[bool, int, int]:
        """Read and cache the settings used by the history cleanup hot path."""
        with self._lock:
            if self._cleanup_settings_cache is not None:
                return self._cleanup_settings_cache

        settings = self.get_settings()
        cleanup_settings = (
            self._normalize_cleanup_enabled(settings.get("auto_cleanup_logs", True)),
            self._normalize_nonnegative_int(settings.get("max_history_records", 0)),
            self._normalize_nonnegative_int(settings.get("history_retention_days", 0)),
        )
        with self._lock:
            if self._cleanup_settings_cache is None:
                self._cleanup_settings_cache = cleanup_settings
            return self._cleanup_settings_cache

    def _init_db(self) -> None:
        """Create necessary database tables and indices if not already present."""
        with self._lock, self._connection() as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS settings (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS history_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    type TEXT NOT NULL,
                    manual INTEGER NOT NULL DEFAULT 0,
                    success INTEGER NOT NULL DEFAULT 0,
                    report TEXT NOT NULL,
                    details TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_history_logs_id_desc ON history_logs(id DESC);
                CREATE INDEX IF NOT EXISTS idx_history_logs_timestamp ON history_logs(timestamp);

                CREATE TABLE IF NOT EXISTS history_log_sites (
                    history_id INTEGER NOT NULL,
                    site_id TEXT NOT NULL,
                    PRIMARY KEY (history_id, site_id),
                    FOREIGN KEY (history_id) REFERENCES history_logs(id) ON DELETE CASCADE
                );

                CREATE INDEX IF NOT EXISTS idx_history_log_sites_site_id
                    ON history_log_sites(site_id, history_id DESC);

                CREATE TABLE IF NOT EXISTS storage_metadata (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS vault_slots (
                    id TEXT PRIMARY KEY,
                    type TEXT NOT NULL,
                    label TEXT NOT NULL DEFAULT '',
                    credential_id TEXT NOT NULL DEFAULT '',
                    rp_id TEXT NOT NULL DEFAULT '',
                    transports TEXT NOT NULL DEFAULT '',
                    prf_salt TEXT NOT NULL DEFAULT '',
                    kdf_salt TEXT NOT NULL,
                    wrapped_dek TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    last_used_at TEXT
                );

                CREATE INDEX IF NOT EXISTS idx_vault_slots_credential
                    ON vault_slots(credential_id);

                -- When each scheduled task runs next and how it last went. Kept
                -- apart from the sites table, which a save rewrites whole.
                CREATE TABLE IF NOT EXISTS site_task_state (
                    site_id TEXT NOT NULL,
                    task_id TEXT NOT NULL,
                    schedule_key TEXT NOT NULL DEFAULT '',
                    next_run_at TEXT,
                    last_run_at TEXT,
                    last_success INTEGER,
                    last_message TEXT NOT NULL DEFAULT '',
                    PRIMARY KEY (site_id, task_id)
                );
            """)
            self._ensure_sites_table(conn)

    # ------------------------------------------------------------------
    # History site index
    # ------------------------------------------------------------------
    @staticmethod
    def _extract_site_ids(details: Any) -> set[str]:
        """Extract configured site IDs from one history entry's result list."""
        if not isinstance(details, list):
            return set()
        site_ids: set[str] = set()
        for detail in details:
            if not isinstance(detail, dict):
                continue
            site_id = str(detail.get("site_id") or "").strip()
            if site_id:
                site_ids.add(site_id)
        return site_ids

    def _index_history_entry_sites(
        self,
        conn: sqlite3.Connection,
        history_id: int,
        details: Any,
    ) -> None:
        """Store site IDs in the indexed history association table."""
        site_ids = self._extract_site_ids(details)
        if not site_ids:
            return
        conn.executemany(
            "INSERT OR IGNORE INTO history_log_sites (history_id, site_id) VALUES (?, ?)",
            [(history_id, site_id) for site_id in site_ids],
        )

    def _ensure_history_site_index(self) -> None:
        """Backfill the site association index once for existing history rows."""
        with self._lock, self._connection() as conn:
            marker = conn.execute(
                "SELECT value FROM storage_metadata WHERE key = ?",
                ("history_site_index_version",),
            ).fetchone()
            if marker:
                return

            batch_size = 1000
            last_id = 0
            while True:
                rows = conn.execute(
                    """
                    SELECT id, details
                    FROM history_logs
                    WHERE id > ?
                    ORDER BY id
                    LIMIT ?
                    """,
                    (last_id, batch_size),
                ).fetchall()
                if not rows:
                    break

                for row in rows:
                    try:
                        details = json.loads(row["details"])
                    except Exception:
                        details = []
                    self._index_history_entry_sites(conn, int(row["id"]), details)
                last_id = int(rows[-1]["id"])

            conn.execute(
                "INSERT INTO storage_metadata (key, value) VALUES (?, ?)",
                ("history_site_index_version", "1"),
            )

    # ------------------------------------------------------------------
    # Schema migration
    # ------------------------------------------------------------------
    def _ensure_sites_table(self, conn: sqlite3.Connection) -> None:
        """Create the sites table, upgrading the pre-credential-list schema."""
        exists = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='sites'"
        ).fetchone()
        if not exists:
            conn.executescript(_SITES_SCHEMA)
            return

        columns = {row["name"] for row in conn.execute("PRAGMA table_info(sites)").fetchall()}
        if "credentials" in columns:
            for column, definition in _ADDED_SITE_COLUMNS.items():
                if column not in columns:
                    conn.execute(f"ALTER TABLE sites ADD COLUMN {column} {definition}")
            return

        logger.info("Upgrading sites table to the credential-list schema.")
        legacy_rows = [dict(row) for row in conn.execute("SELECT * FROM sites").fetchall()]
        conn.execute("BEGIN TRANSACTION")
        try:
            conn.execute("DROP TABLE sites")
            conn.executescript(_SITES_SCHEMA)
            migrated = [_legacy_site_to_site(row) for row in legacy_rows]
            self._insert_sites_records(conn, migrated)
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        logger.info(f"Migrated {len(legacy_rows)} sites to the credential-list schema.")

    def _migrate_legacy_json(self, legacy_dir: Path) -> None:
        """Migrate legacy JSON files into SQLite and rename them to .bak.

        Args:
            legacy_dir: Directory where legacy JSON files reside.
        """
        with self._lock, self._connection() as conn:
            # 1. Migrate sites.json
            sites_file = legacy_dir / "sites.json"
            if sites_file.exists():
                try:
                    count = conn.execute("SELECT COUNT(*) FROM sites").fetchone()[0]
                    if count == 0:
                        with open(sites_file, encoding="utf-8") as f:
                            sites_data = json.load(f)
                        if isinstance(sites_data, list):
                            self._insert_sites_records(conn, sites_data)
                            logger.info(f"Migrated {len(sites_data)} sites from sites.json to SQLite.")
                    self._backup_file(sites_file)
                except Exception as e:
                    logger.error(f"Failed to migrate sites.json: {e}", exc_info=True)

            # 2. Migrate settings.json
            settings_file = legacy_dir / "settings.json"
            if settings_file.exists():
                try:
                    count = conn.execute("SELECT COUNT(*) FROM settings").fetchone()[0]
                    if count == 0:
                        with open(settings_file, encoding="utf-8") as f:
                            settings_data = json.load(f)
                        if isinstance(settings_data, dict):
                            self._save_settings_records(conn, settings_data)
                            logger.info("Migrated settings from settings.json to SQLite.")
                    self._backup_file(settings_file)
                except Exception as e:
                    logger.error(f"Failed to migrate settings.json: {e}", exc_info=True)

            # 3. Migrate history.json
            history_file = legacy_dir / "history.json"
            if history_file.exists():
                try:
                    count = conn.execute("SELECT COUNT(*) FROM history_logs").fetchone()[0]
                    if count == 0:
                        with open(history_file, encoding="utf-8") as f:
                            history_data = json.load(f)
                        if isinstance(history_data, list):
                            # history_data is newest-first in JSON, insert in chronological order
                            for item in reversed(history_data):
                                if isinstance(item, dict):
                                    conn.execute(
                                        """
                                        INSERT INTO history_logs (timestamp, type, manual, success, report, details)
                                        VALUES (?, ?, ?, ?, ?, ?)
                                        """,
                                        (
                                            item.get("timestamp", ""),
                                            item.get("type", "scheduled"),
                                            1 if item.get("manual") else 0,
                                            1 if item.get("success") else 0,
                                            item.get("report", ""),
                                            json.dumps(item.get("details", []), ensure_ascii=False),
                                        ),
                                    )
                            logger.info(f"Migrated {len(history_data)} log entries from history.json to SQLite.")
                    self._backup_file(history_file)
                except Exception as e:
                    logger.error(f"Failed to migrate history.json: {e}", exc_info=True)

    @staticmethod
    def _backup_file(file_path: Path) -> None:
        """Rename an existing file to .bak to avoid re-migration."""
        try:
            bak_path = file_path.with_suffix(file_path.suffix + ".bak")
            if bak_path.exists():
                bak_path.unlink()
            file_path.rename(bak_path)
            logger.info(f"Renamed {file_path.name} to {bak_path.name}")
        except Exception as e:
            logger.warning(f"Could not backup {file_path.name}: {e}")

    # ------------------------------------------------------------------
    # Sites Operations
    # ------------------------------------------------------------------
    def _site_row_to_dict(self, row: sqlite3.Row) -> dict[str, Any]:
        """Convert a sites table SQLite Row to a dictionary.

        Vault-protected columns are decrypted when a key is loaded. While the
        vault is locked the row is still returned so the dashboard can list the
        site, but the protected values are withheld and ``locked`` is set.
        """
        locked = any(is_ciphertext(row[column]) for column in _SENSITIVE_COLUMNS) and not self.vault.unlocked

        site_dict: dict[str, Any] = {
            "id": row["id"],
            "name": row["name"],
            "type": normalize_site_type(row["type"]),
            "base_url": row["base_url"],
            "proxy": self.vault.decrypt_or_placeholder(row["proxy"]),
            "credentials": [] if locked else self._decode_credentials(row["credentials"]),
            "checkin": self._decode_action(row["checkin_config"], row["checkin_headers"], locked, allow_oauth=True),
            "balance": self._decode_action(row["balance_config"], row["balance_headers"], locked, allow_oauth=False),
            "tasks": join_tasks(
                _load_json(row["tasks_config"], []),
                {} if locked else self._decode_json(row["tasks_secrets"], {}),
            ),
            "vs_pow": bool(row["vs_pow"]),
            "enabled": bool(row["enabled"]),
            "locked": locked,
        }
        if row["last_checkin_date"] is not None:
            site_dict["last_checkin_date"] = row["last_checkin_date"]
        if row["last_checkin_time"] is not None:
            site_dict["last_checkin_time"] = row["last_checkin_time"]
        if row["last_checkin_success"] is not None:
            site_dict["last_checkin_success"] = bool(row["last_checkin_success"])
        if row["last_quota"] is not None:
            site_dict["last_quota"] = row["last_quota"]
        if row["created_at"]:
            site_dict["created_at"] = row["created_at"]
        if row["updated_at"]:
            site_dict["updated_at"] = row["updated_at"]
        return site_dict

    def _decode_credentials(self, stored: str) -> list[dict[str, Any]]:
        """Decrypt and normalize the credential list column."""
        return normalize_credentials(self._decode_json(stored, []))

    def _decode_action(
        self,
        config_text: str,
        headers_text: str,
        locked: bool,
        allow_oauth: bool,
    ) -> dict[str, Any]:
        """Rebuild one action config from its plaintext and encrypted columns."""
        raw = _load_json(config_text, {})
        if not isinstance(raw, dict):
            raw = {}
        raw = dict(raw)
        raw["headers"] = [] if locked else self._decode_json(headers_text, [])
        return normalize_action(raw, allow_oauth=allow_oauth)

    def _decode_json(self, stored: str, default: Any) -> Any:
        """Decrypt a protected JSON column, returning ``default`` when unusable."""
        if not stored:
            return default
        if is_ciphertext(stored) and not self.vault.unlocked:
            return default
        try:
            text = self.vault.decrypt(stored)
        except Exception as exc:
            logger.warning(f"Could not decrypt protected site field: {exc}")
            return default
        return _load_json(text, default)

    def _insert_sites_records(
        self,
        conn: sqlite3.Connection,
        sites_data: list[dict[str, Any]],
        existing_rows: dict[str, sqlite3.Row | dict[str, Any]] | None = None,
    ) -> None:
        """Insert or replace a list of site dicts into the database.

        Protected values that come back as the locked placeholder are taken from
        the existing row instead, so saving a site while the vault is locked can
        never destroy credentials the caller could not see.
        """
        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        existing_rows = existing_rows or {}
        for order, raw_site in enumerate(sites_data):
            site = raw_site if isinstance(raw_site, dict) else {}
            if _is_legacy_site(site):
                site = _legacy_site_to_site(site)
            site_id = str(site.get("id") or f"site_{int(datetime.now().timestamp() * 1000)}_{order}").strip()
            previous = existing_rows.get(site_id) or {}
            keep_all = bool(site.get("locked"))

            credentials = normalize_credentials(site.get("credentials"))
            credentials = self._carry_oauth_sessions(credentials, previous)

            checkin = normalize_action(site.get("checkin"), allow_oauth=True)
            balance = normalize_action(site.get("balance"), allow_oauth=False)
            # Older clients omit PoW options; only explicit values replace them.
            vs_pow = bool(_row_value(previous, "vs_pow"))
            if not keep_all and "vs_pow" in site:
                vs_pow = site["vs_pow"] is True
            tasks = site.get("tasks")
            if isinstance(tasks, list) and previous and not keep_all:
                stored_purposes = {
                    task["id"]: task["pow_purpose"]
                    for task in normalize_tasks(
                        _load_json(_row_value(previous, "tasks_config") or "", [])
                    )
                }
                merged_tasks = []
                for index, task in enumerate(tasks):
                    if isinstance(task, dict) and "pow_purpose" not in task:
                        task_id = str(task.get("id") or f"task_{index + 1}").strip()
                        task = {**task, "pow_purpose": stored_purposes.get(task_id, "")}
                    merged_tasks.append(task)
                tasks = merged_tasks
            tasks_plain, tasks_secret = _split_tasks(tasks)

            created_at = site.get("created_at") or _row_value(previous, "created_at") or now_str
            last_success = None
            if site.get("last_checkin_success") is not None:
                last_success = 1 if site["last_checkin_success"] else 0

            conn.execute(
                """
                INSERT INTO sites (
                    id, name, type, base_url, proxy, credentials,
                    checkin_config, checkin_headers, balance_config, balance_headers,
                    tasks_config, tasks_secrets, vs_pow,
                    enabled, last_checkin_date, last_checkin_time, last_checkin_success, last_quota,
                    display_order, created_at, updated_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    name=excluded.name,
                    type=excluded.type,
                    base_url=excluded.base_url,
                    proxy=excluded.proxy,
                    credentials=excluded.credentials,
                    checkin_config=excluded.checkin_config,
                    checkin_headers=excluded.checkin_headers,
                    balance_config=excluded.balance_config,
                    balance_headers=excluded.balance_headers,
                    tasks_config=excluded.tasks_config,
                    tasks_secrets=excluded.tasks_secrets,
                    vs_pow=excluded.vs_pow,
                    enabled=excluded.enabled,
                    last_checkin_date=excluded.last_checkin_date,
                    last_checkin_time=excluded.last_checkin_time,
                    last_checkin_success=excluded.last_checkin_success,
                    last_quota=excluded.last_quota,
                    display_order=excluded.display_order,
                    updated_at=excluded.updated_at
                """,
                (
                    site_id,
                    str(site.get("name", "")).strip(),
                    normalize_site_type(site.get("type")),
                    str(site.get("base_url", "")).strip(),
                    self._seal_text(site.get("proxy"), previous, "proxy", keep_all),
                    self._seal_json(credentials, previous, "credentials", keep_all),
                    _dump_action_config(checkin),
                    self._seal_json(
                        checkin["headers"], previous, "checkin_headers", keep_all
                    ),
                    _dump_action_config(balance),
                    self._seal_json(
                        balance["headers"], previous, "balance_headers", keep_all
                    ),
                    # A locked site cannot be edited, so its stored tasks stand.
                    (_row_value(previous, "tasks_config") or "")
                    if keep_all
                    else json.dumps(tasks_plain, ensure_ascii=False),
                    self._seal_json(tasks_secret, previous, "tasks_secrets", keep_all),
                    1 if vs_pow else 0,
                    1 if site.get("enabled", True) else 0,
                    site.get("last_checkin_date"),
                    site.get("last_checkin_time"),
                    last_success,
                    site.get("last_quota"),
                    order,
                    created_at,
                    now_str,
                ),
            )

    def _carry_oauth_sessions(
        self,
        credentials: list[dict[str, Any]],
        previous: sqlite3.Row | dict[str, Any],
    ) -> list[dict[str, Any]]:
        """Preserve OAuth secrets the caller never intended to change.

        Two cases, both about the dashboard round-trip:

        * The dashboard is not given session cookies, so an unchanged credential
          arrives back with an empty ``session_cookie``.
        * An OAuth cookie the user did not edit arrives back empty on purpose,
          so that a save cannot overwrite a rotation that happened while the
          editor was open. The form refuses to submit a genuinely blank
          credential, so empty here always means "unchanged".
        """
        if not credentials:
            return credentials
        stored = _row_value(previous, "credentials")
        if not stored:
            return credentials
        known = {
            item.get("id"): item
            for item in self._decode_credentials(stored)
            if isinstance(item, dict)
        }
        if not known:
            return credentials
        for credential in credentials:
            if "session_cookie" not in credential:
                continue
            match = known.get(credential["id"])
            if not isinstance(match, dict) or match.get("type") != credential["type"]:
                continue
            if not credential["session_cookie"]:
                credential["session_cookie"] = str(match.get("session_cookie") or "")
                credential["session_updated_at"] = str(match.get("session_updated_at") or "")
            if not credential.get("access_token"):
                credential["access_token"] = str(match.get("access_token") or "")
                credential["access_expires_at"] = match.get("access_expires_at") or 0
            if not credential.get("value"):
                credential["value"] = str(match.get("value") or "")
                credential["value_updated_at"] = str(match.get("value_updated_at") or "")
            credential["provider_cookies"] = (
                match.get("provider_cookies", [])
                if credential["value"] == match.get("value")
                else []
            )
        return credentials

    def _seal_text(
        self,
        value: Any,
        previous: sqlite3.Row | dict[str, Any],
        column: str,
        keep_all: bool,
    ) -> str:
        """Encrypt a protected text value, or keep the stored ciphertext."""
        if keep_all or is_locked_placeholder(value):
            return str(_row_value(previous, column) or "")
        return self.vault.encrypt("" if value is None else str(value).strip())

    def _seal_json(
        self,
        value: Any,
        previous: sqlite3.Row | dict[str, Any],
        column: str,
        keep_all: bool,
    ) -> str:
        """Encrypt a protected JSON value, or keep the stored ciphertext."""
        if keep_all:
            return str(_row_value(previous, column) or "")
        return self.vault.encrypt_json(value)

    def get_sites(self) -> list[dict[str, Any]]:
        """Get all configured sites ordered by display_order.

        Returns:
            List of site dictionaries with decrypted credentials and headers
            when the vault is unlocked or disabled.
        """
        with self._lock, self._connection() as conn:
            cursor = conn.execute("SELECT * FROM sites ORDER BY display_order ASC, created_at ASC")
            return [self._site_row_to_dict(row) for row in cursor.fetchall()]

    def get_sites_for_display(self) -> list[dict[str, Any]]:
        """Get all sites with OAuth session tokens and scoped cookie jars withheld.

        Used by the web API: the dashboard never needs the station secrets a
        login produced, only which of them are currently held. Provider jars
        stay server-side and are restored when an unchanged credential is saved.
        """
        sites = self.get_sites()
        states = self.get_task_states()
        for site in sites:
            for task in site.get("tasks", []):
                task["state"] = states.get((site["id"], task["id"]), {})
            for credential in site.get("credentials", []):
                if "session_cookie" not in credential:
                    continue
                credential["has_session"] = bool(credential.get("session_cookie"))
                credential["has_refresh_token"] = holds_refresh_cookie(credential.get("session_cookie"))
                credential["has_access_token"] = bool(credential.get("access_token"))
                credential["session_cookie"] = ""
                credential["access_token"] = ""
                credential["provider_cookies"] = []
        return sites

    def merge_stored_oauth_secrets(self, site: dict[str, Any]) -> dict[str, Any]:
        """Fill in the OAuth secrets a site posted by the dashboard lacks.

        The display view withholds every login's station secrets, and the site
        editor omits an untouched provider cookie, so a site posted back for a
        connection test or probe arrives without them. An adapter built from it
        holds no session and can only log in again, which on login-as-check-in
        stations spends the day's sign-in. The stored site with the same id
        supplies them exactly as a save would; see ``_carry_oauth_sessions``.

        Args:
            site: Site config as the dashboard posted it. Left unmodified.

        Returns:
            A copy of ``site`` carrying the stored secrets, or ``site`` itself
            when no stored site has its id.
        """
        site_id = str(site.get("id") or "").strip()
        if not site_id:
            return site
        with self._lock, self._connection() as conn:
            row = conn.execute("SELECT credentials FROM sites WHERE id = ?", (site_id,)).fetchone()
        if row is None:
            return site
        credentials = normalize_credentials(site.get("credentials"))
        return {**site, "credentials": self._carry_oauth_sessions(credentials, row)}

    def save_sites(self, sites_data: list[dict[str, Any]]) -> None:
        """Replace the full sites configuration atomically while preserving created_at.

        Args:
            sites_data: New list of site dictionaries.
        """
        with self._lock, self._connection() as conn:
            conn.execute("BEGIN TRANSACTION")
            try:
                existing = {row["id"]: dict(row) for row in conn.execute("SELECT * FROM sites").fetchall()}
                conn.execute("DELETE FROM sites")
                self._insert_sites_records(conn, sites_data, existing_rows=existing)
                self._prune_task_states(conn)
                conn.commit()
            except Exception:
                conn.rollback()
                raise

    # ------------------------------------------------------------------
    # Scheduled task state
    # ------------------------------------------------------------------
    def get_task_states(self) -> dict[tuple[str, str], dict[str, Any]]:
        """Every task's run state, keyed by ``(site_id, task_id)``."""
        with self._lock, self._connection() as conn:
            rows = conn.execute("SELECT * FROM site_task_state").fetchall()
        return {
            (row["site_id"], row["task_id"]): {
                "schedule_key": row["schedule_key"],
                "next_run_at": row["next_run_at"],
                "last_run_at": row["last_run_at"],
                "last_success": None if row["last_success"] is None else bool(row["last_success"]),
                "last_message": row["last_message"],
            }
            for row in rows
        }

    def set_task_schedule(self, site_id: str, task_id: str, schedule_key: str, next_run_at: str | None) -> None:
        """Record when a task runs next, and under which schedule that was worked out."""
        with self._lock, self._connection() as conn:
            conn.execute(
                """
                INSERT INTO site_task_state (site_id, task_id, schedule_key, next_run_at)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(site_id, task_id) DO UPDATE SET
                    schedule_key = excluded.schedule_key,
                    next_run_at = excluded.next_run_at
                """,
                (site_id, task_id, schedule_key, next_run_at),
            )

    def record_task_run(self, site_id: str, task_id: str, run_at: str, success: bool, message: str) -> None:
        """Record how a task's latest run went."""
        with self._lock, self._connection() as conn:
            conn.execute(
                """
                INSERT INTO site_task_state (site_id, task_id, last_run_at, last_success, last_message)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(site_id, task_id) DO UPDATE SET
                    last_run_at = excluded.last_run_at,
                    last_success = excluded.last_success,
                    last_message = excluded.last_message
                """,
                (site_id, task_id, run_at, 1 if success else 0, message),
            )

    @staticmethod
    def _prune_task_states(conn: sqlite3.Connection) -> None:
        """Drop the state of tasks no longer configured."""
        configured = set()
        for row in conn.execute("SELECT id, tasks_config FROM sites").fetchall():
            for task in _load_json(row["tasks_config"], []) or []:
                if isinstance(task, dict) and task.get("id"):
                    configured.add((row["id"], str(task["id"])))
        stale = [
            (row["site_id"], row["task_id"])
            for row in conn.execute("SELECT site_id, task_id FROM site_task_state").fetchall()
            if (row["site_id"], row["task_id"]) not in configured
        ]
        conn.executemany("DELETE FROM site_task_state WHERE site_id = ? AND task_id = ?", stale)

    def update_site_checkin_state(
        self,
        site_id: str,
        last_checkin_date: str,
        last_checkin_time: str,
        last_checkin_success: bool,
        last_quota: float | None = None,
    ) -> None:
        """Update check-in status and quota for a single site.

        Args:
            site_id: ID of the site to update.
            last_checkin_date: YYYY-MM-DD string.
            last_checkin_time: HH:MM:SS string.
            last_checkin_success: Success boolean flag.
            last_quota: Balance quota float.
        """
        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with self._lock, self._connection() as conn:
            conn.execute(
                """
                UPDATE sites
                SET last_checkin_date = ?,
                    last_checkin_time = ?,
                    last_checkin_success = ?,
                    last_quota = ?,
                    updated_at = ?
                WHERE id = ?
                """,
                (
                    last_checkin_date,
                    last_checkin_time,
                    1 if last_checkin_success else 0,
                    last_quota,
                    now_str,
                    site_id.strip(),
                ),
            )

    def update_credential_session(
        self,
        site_id: str,
        credential_id: str,
        session_cookie: str,
        access_token: str | None = None,
        access_expires_at: int = 0,
    ) -> bool:
        """Write an OAuth login's station secrets back onto its own credential.

        Args:
            site_id: Owning site.
            credential_id: Credential that performed the login.
            session_cookie: Station cookie jar to remember — a session cookie,
                or on newer New-API builds the refresh-token cookie.
            access_token: Short-lived bearer token to remember alongside it.
                None leaves the stored token alone; an empty string clears it,
                which is what a login that issued none must do.
            access_expires_at: When that token expires, in unix seconds.

        Returns:
            Whether a credential was updated.
        """
        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with self._lock, self._connection() as conn:
            row = conn.execute(
                "SELECT credentials FROM sites WHERE id = ?", (site_id.strip(),)
            ).fetchone()
            if row is None:
                return False
            credentials = self._decode_credentials(row["credentials"])
            updated = False
            for credential in credentials:
                if credential.get("id") != str(credential_id).strip():
                    continue
                credential["session_cookie"] = str(session_cookie or "").strip()
                credential["session_updated_at"] = now_str
                if access_token is not None:
                    credential["access_token"] = str(access_token).strip()
                    credential["access_expires_at"] = int(access_expires_at or 0) if access_token else 0
                updated = True
                break
            if not updated:
                return False
            conn.execute(
                "UPDATE sites SET credentials = ?, updated_at = ? WHERE id = ?",
                (self.vault.encrypt_json(credentials), now_str, site_id.strip()),
            )
            return True

    def update_credential_value(
        self,
        site_id: str,
        credential_id: str,
        value: str,
        provider_cookies: list[dict[str, Any]] | None = None,
    ) -> bool:
        """Replace a credential's secret with a rotated one.

        Providers rotate session cookies as they are used. Persisting the new
        value keeps the next run from replaying one the provider has already
        retired, which is what makes a stored cookie appear to "expire" on its
        own. A blank value is refused so a bad response cannot wipe a working
        credential.

        Args:
            site_id: Owning site.
            credential_id: Credential whose value rotated.
            value: The new secret.
            provider_cookies: Scoped provider cookie jar, stored atomically
                with the legacy header. None clears old scopes on a changed
                header, and leaves them alone when the header is unchanged.

        Returns:
            Whether a credential was updated.
        """
        new_value = str(value or "").strip()
        if not new_value:
            return False

        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with self._lock, self._connection() as conn:
            row = conn.execute(
                "SELECT credentials FROM sites WHERE id = ?", (site_id.strip(),)
            ).fetchone()
            if row is None:
                return False
            credentials = self._decode_credentials(row["credentials"])
            updated = False
            for credential in credentials:
                if credential.get("id") != str(credential_id).strip():
                    continue
                cookies = (
                    normalize_provider_cookies(provider_cookies)
                    if provider_cookies is not None
                    else []
                )
                same_value = credential.get("value") == new_value
                if same_value and (
                    provider_cookies is None
                    or credential.get("provider_cookies", []) == cookies
                ):
                    return False
                credential["value"] = new_value
                if "provider_cookies" in credential:
                    credential["provider_cookies"] = cookies
                credential["value_updated_at"] = now_str
                updated = True
                break
            if not updated:
                return False
            conn.execute(
                "UPDATE sites SET credentials = ?, updated_at = ? WHERE id = ?",
                (self.vault.encrypt_json(credentials), now_str, site_id.strip()),
            )
        logger.info("Rotated credential %s on site %s.", credential_id, site_id)
        return True

    def update_action_headers(
        self,
        site_id: str,
        action: str,
        headers: Any,
    ) -> bool:
        """Replace the custom headers of one action config.

        Used to persist a probed ``new-api-user`` value back into the config
        that discovered it.

        Args:
            site_id: Owning site.
            action: ``checkin`` or ``balance``.
            headers: Header pairs to store.

        Returns:
            Whether the site exists and was updated.
        """
        if action not in (ACTION_CHECKIN, ACTION_BALANCE):
            raise ValueError(f"Unknown action: {action}")
        column = f"{action}_headers"
        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with self._lock, self._connection() as conn:
            cursor = conn.execute(
                f"UPDATE sites SET {column} = ?, updated_at = ? WHERE id = ?",
                (self.vault.encrypt_json(normalize_headers(headers)), now_str, site_id.strip()),
            )
            return cursor.rowcount > 0

    # ------------------------------------------------------------------
    # Vault Operations
    # ------------------------------------------------------------------
    def is_encryption_enabled(self) -> bool:
        """Return whether encryption at rest is turned on in storage."""
        return bool(self._read_setting(VAULT_ENABLED_KEY, False))

    def get_vault_verifier(self) -> str:
        """Return the stored verifier blob used to validate a supplied key."""
        return str(self._read_setting(VAULT_VERIFIER_KEY, "") or "")

    def get_lock_notify_sent(self) -> bool:
        """Return whether the locked-vault alert already went out for this lock.

        Persisted rather than kept in memory so that restarting AstrBot with an
        encrypted, still-locked vault does not re-send the same alert.
        """
        return bool(self._read_setting(LOCK_NOTIFY_SENT_KEY, False))

    def set_lock_notify_sent(self, sent: bool) -> None:
        """Record whether the locked-vault alert has been delivered.

        Args:
            sent: ``True`` right after a successful send, ``False`` once the
                vault is open again so the next lock can alert once more.
        """
        with self._lock, self._connection() as conn:
            self._save_settings_records(conn, {LOCK_NOTIFY_SENT_KEY: bool(sent)})

    # ------------------------------------------------------------------
    # Key Slots
    # ------------------------------------------------------------------
    @staticmethod
    def _build_slot_record(
        slot_id: str,
        slot_type: str,
        secret: bytes,
        dek: bytes,
        label: str = "",
        credential_id: str = "",
        rp_id: str = "",
        transports: Any = None,
        prf_salt: bytes | None = None,
    ) -> dict[str, Any]:
        """Wrap the vault key for one slot and build its row.

        Nothing in the returned record is secret: the wrapped key is useless
        without the slot secret, and the credential id and PRF salt are public
        values by WebAuthn's design.
        """
        kdf_salt = generate_salt()
        kek = derive_kek(secret, kdf_salt, slot_type)
        return {
            "id": slot_id,
            "type": slot_type,
            "label": str(label or ""),
            "credential_id": str(credential_id or ""),
            "rp_id": str(rp_id or ""),
            "transports": json.dumps(transports or [], ensure_ascii=False),
            "prf_salt": encode_bytes(prf_salt) if prf_salt else "",
            "kdf_salt": encode_bytes(kdf_salt),
            "wrapped_dek": wrap_dek(dek, kek, slot_id),
            "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "last_used_at": None,
        }

    @staticmethod
    def _insert_slot(conn: sqlite3.Connection, record: dict[str, Any]) -> None:
        """Insert or replace one key slot row."""
        conn.execute(
            """
            INSERT INTO vault_slots (
                id, type, label, credential_id, rp_id, transports,
                prf_salt, kdf_salt, wrapped_dek, created_at, last_used_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                type=excluded.type,
                label=excluded.label,
                credential_id=excluded.credential_id,
                rp_id=excluded.rp_id,
                transports=excluded.transports,
                prf_salt=excluded.prf_salt,
                kdf_salt=excluded.kdf_salt,
                wrapped_dek=excluded.wrapped_dek
            """,
            (
                record["id"],
                record["type"],
                record["label"],
                record["credential_id"],
                record["rp_id"],
                record["transports"],
                record["prf_salt"],
                record["kdf_salt"],
                record["wrapped_dek"],
                record["created_at"],
                record["last_used_at"],
            ),
        )

    @staticmethod
    def _slot_row_to_dict(row: sqlite3.Row) -> dict[str, Any]:
        """Convert a slot row into the shape sent to the dashboard.

        The wrapped key is deliberately withheld — it is not needed by any
        client and there is no reason to hand it out.
        """
        return {
            "id": row["id"],
            "type": row["type"],
            "label": row["label"] or "",
            "credential_id": row["credential_id"] or "",
            "rp_id": row["rp_id"] or "",
            "transports": _load_json(row["transports"], []),
            "prf_salt": row["prf_salt"] or "",
            "created_at": row["created_at"],
            "last_used_at": row["last_used_at"],
            "removable": row["type"] != SLOT_USER_KEY,
        }

    def list_slots(self) -> list[dict[str, Any]]:
        """Return every key slot, oldest first.

        Readable while the vault is locked, which is what the unlock flow needs
        to build its WebAuthn ``allowCredentials`` list. The user-key slot is
        listed first — two slots created in the same second would otherwise sort
        arbitrarily by id.
        """
        with self._lock, self._connection() as conn:
            rows = conn.execute(
                f"""
                SELECT * FROM vault_slots
                ORDER BY (type = '{SLOT_USER_KEY}') DESC, created_at ASC, id ASC
                """
            ).fetchall()
        return [self._slot_row_to_dict(row) for row in rows]

    def list_slots_for_rp(self, rp_id: str) -> list[dict[str, Any]]:
        """Return the WebAuthn slots registered for one RP ID.

        Credentials are bound to the RP ID they were created under, so offering
        a slot from a different host would only produce a confusing browser
        error.
        """
        wanted = str(rp_id or "").strip().lower()
        return [
            slot
            for slot in self.list_slots()
            if slot["type"] == SLOT_WEBAUTHN and slot["rp_id"].lower() == wanted
        ]

    def add_webauthn_slot(
        self,
        credential_id: str,
        prf_output: str,
        prf_salt: str,
        rp_id: str,
        label: str = "",
        transports: Any = None,
    ) -> dict[str, Any]:
        """Register a passkey or security key as an additional unlock method.

        Args:
            credential_id: Base64url WebAuthn credential id.
            prf_output: Base64 PRF output evaluated for ``prf_salt``.
            prf_salt: Base64 salt that must be re-used at unlock time.
            rp_id: Host the credential is bound to.
            label: Optional human-friendly name.
            transports: Optional transport hints from the authenticator.

        Returns:
            The stored slot metadata.

        Raises:
            VaultLockedError: If the vault is locked, since wrapping needs the DEK.
            InvalidVaultKeyError: If the PRF output or salt is malformed.
            RuntimeError: If encryption is off or the credential is already used.
        """
        if not self.is_encryption_enabled():
            raise RuntimeError("请先启用配置加密，再添加通行密钥")
        credential = str(credential_id or "").strip()
        if not credential:
            raise RuntimeError("缺少凭据 ID")

        secret = decode_bytes(prf_output, expected_length=_PRF_BYTES)
        salt = decode_bytes(prf_salt)
        dek = self.vault.export_dek()

        with self._lock, self._connection() as conn:
            existing = conn.execute(
                "SELECT id FROM vault_slots WHERE credential_id = ? AND rp_id = ?",
                (credential, str(rp_id or "").strip()),
            ).fetchone()
            if existing is not None:
                raise RuntimeError("该通行密钥已注册过")

            record = self._build_slot_record(
                slot_id=f"slot_{uuid.uuid4().hex[:16]}",
                slot_type=SLOT_WEBAUTHN,
                secret=secret,
                dek=dek,
                label=label,
                credential_id=credential,
                rp_id=str(rp_id or "").strip(),
                transports=transports,
                prf_salt=salt,
            )
            self._insert_slot(conn, record)
            row = conn.execute("SELECT * FROM vault_slots WHERE id = ?", (record["id"],)).fetchone()
        logger.info("Registered WebAuthn key slot %s for %s.", record["id"], record["rp_id"])
        return self._slot_row_to_dict(row)

    def unlock_with_webauthn(self, credential_id: str, prf_output: str) -> dict[str, Any]:
        """Unlock the vault using a passkey's PRF output.

        Args:
            credential_id: Base64url credential id the browser asserted.
            prf_output: Base64 PRF output for that credential's stored salt.

        Returns:
            The slot metadata that was used.

        Raises:
            RuntimeError: If encryption is off or no slot matches the credential.
            InvalidVaultKeyError: If the PRF output cannot unwrap the slot.
        """
        if not self.is_encryption_enabled():
            raise RuntimeError("当前未启用加密，无需解锁")
        credential = str(credential_id or "").strip()
        secret = decode_bytes(prf_output, expected_length=_PRF_BYTES)

        with self._lock, self._connection() as conn:
            row = conn.execute(
                "SELECT * FROM vault_slots WHERE credential_id = ? AND type = ?",
                (credential, SLOT_WEBAUTHN),
            ).fetchone()
            if row is None:
                raise RuntimeError("未找到该通行密钥对应的槽位，请重新注册")
            dek = self._unwrap_slot(row, secret)
            self._touch_slot(conn, row["id"])
        self.vault.load_dek(dek)
        logger.info("Vault unlocked with WebAuthn key slot %s.", row["id"])
        return self._slot_row_to_dict(row)

    def remove_slot(self, slot_id: str) -> bool:
        """Delete a key slot.

        The user-key slot is permanent: keeping it guarantees that losing every
        passkey can never make the data unrecoverable.

        Args:
            slot_id: Slot to delete.

        Returns:
            True when a row was deleted.

        Raises:
            RuntimeError: If the slot is the user-key slot or the only one left.
        """
        wanted = str(slot_id or "").strip()
        with self._lock, self._connection() as conn:
            row = conn.execute("SELECT * FROM vault_slots WHERE id = ?", (wanted,)).fetchone()
            if row is None:
                return False
            if row["type"] == SLOT_USER_KEY:
                raise RuntimeError("用户密钥槽位是恢复入口，不可删除")
            total = conn.execute("SELECT COUNT(*) AS total FROM vault_slots").fetchone()["total"]
            if int(total) <= 1:
                raise RuntimeError("至少需要保留一个密钥槽位")
            conn.execute("DELETE FROM vault_slots WHERE id = ?", (wanted,))
        logger.info("Removed key slot %s.", wanted)
        return True

    @staticmethod
    def _unwrap_slot(row: sqlite3.Row, secret: bytes) -> bytes:
        """Recover the vault key from one slot row."""
        kdf_salt = decode_bytes(row["kdf_salt"])
        kek = derive_kek(secret, kdf_salt, row["type"])
        return unwrap_dek(row["wrapped_dek"], kek, row["id"])

    @staticmethod
    def _touch_slot(conn: sqlite3.Connection, slot_id: str) -> None:
        """Record that a slot was just used to unlock."""
        conn.execute(
            "UPDATE vault_slots SET last_used_at = ? WHERE id = ?",
            (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), slot_id),
        )

    def enable_encryption(self) -> str:
        """Turn on encryption, sealing every existing protected value.

        A random vault key (DEK) encrypts the fields, and a user-key slot keeps
        a copy of it wrapped under the key handed back to the caller. Extra
        passkey slots can be added later, each wrapping the same DEK.

        Returns:
            The freshly generated base64 key, shown to the user exactly once.

        Raises:
            RuntimeError: If encryption is already enabled.
        """
        with self._lock, self._connection() as conn:
            if self.is_encryption_enabled():
                raise RuntimeError("加密已启用，无需重复开启")
            rows = conn.execute(f"SELECT id, {', '.join(_SENSITIVE_COLUMNS)} FROM sites").fetchall()
            plaintext = [(row["id"], [str(row[column] or "") for column in _SENSITIVE_COLUMNS]) for row in rows]

            key_text = generate_key()
            dek = generate_dek()
            verifier = self.vault.enable_with_dek(dek)
            user_slot = self._build_slot_record(
                slot_id=USER_KEY_SLOT_ID,
                slot_type=SLOT_USER_KEY,
                secret=decode_key(key_text),
                dek=dek,
                label="用户密钥",
            )
            conn.execute("BEGIN TRANSACTION")
            try:
                self._rewrite_sensitive(conn, plaintext, seal=True)
                self._save_settings_records(
                    conn, {VAULT_ENABLED_KEY: True, VAULT_VERIFIER_KEY: verifier}
                )
                conn.execute("DELETE FROM vault_slots")
                self._insert_slot(conn, user_slot)
                conn.commit()
            except Exception:
                conn.rollback()
                self.vault.disable()
                raise
        logger.info("Encryption at rest enabled for site credentials.")
        return key_text

    def disable_encryption(self) -> None:
        """Turn off encryption, writing every protected value back as plaintext.

        Raises:
            VaultLockedError: If the vault is locked, since the data is unreadable.
        """
        with self._lock, self._connection() as conn:
            if not self.is_encryption_enabled():
                return
            rows = conn.execute(f"SELECT id, {', '.join(_SENSITIVE_COLUMNS)} FROM sites").fetchall()
            decrypted = [
                (row["id"], [self.vault.decrypt(row[column]) for column in _SENSITIVE_COLUMNS])
                for row in rows
            ]
            conn.execute("BEGIN TRANSACTION")
            try:
                self._rewrite_sensitive(conn, decrypted, seal=False)
                self._clear_vault_settings(conn)
                conn.commit()
            except Exception:
                conn.rollback()
                raise
        self.vault.disable()
        logger.info("Encryption at rest disabled; protected fields rewritten as plaintext.")

    def reset_encryption(self) -> int:
        """Discard unreadable ciphertext after a lost key, keeping the sites.

        Clears credentials, custom headers, and proxies for every site, then
        turns encryption off so the user can re-enter them.

        Returns:
            Number of sites whose protected fields were cleared.
        """
        blanks = ", ".join(f"{column} = ''" for column in _SENSITIVE_COLUMNS)
        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with self._lock, self._connection() as conn:
            conn.execute("BEGIN TRANSACTION")
            try:
                cursor = conn.execute(f"UPDATE sites SET {blanks}, updated_at = ?", (now_str,))
                affected = cursor.rowcount
                self._clear_vault_settings(conn)
                conn.commit()
            except Exception:
                conn.rollback()
                raise
        self.vault.disable()
        logger.warning("Encryption reset requested; cleared protected fields for %s sites.", affected)
        return max(affected, 0)

    def vault_status(self) -> dict[str, Any]:
        """Return the vault state and slot summary for the dashboard."""
        status: dict[str, Any] = dict(self.vault.status())
        slots = self.list_slots()
        status["slot_count"] = len(slots)
        status["has_passkey"] = any(slot["type"] == SLOT_WEBAUTHN for slot in slots)
        return status

    def unlock_encryption(self, key: str) -> None:
        """Load a user-supplied key so protected fields become readable.

        Args:
            key: Base64 key text as shown when encryption was enabled.

        Raises:
            RuntimeError: If encryption is not enabled for this database.
            InvalidVaultKeyError: If the key does not match the stored data.
        """
        if not self.is_encryption_enabled():
            raise RuntimeError("当前未启用加密，无需解锁")

        secret = decode_key(key)
        with self._lock, self._connection() as conn:
            row = conn.execute(
                "SELECT * FROM vault_slots WHERE type = ? ORDER BY created_at ASC LIMIT 1",
                (SLOT_USER_KEY,),
            ).fetchone()
            if row is not None:
                dek = self._unwrap_slot(row, secret)
                self._touch_slot(conn, row["id"])
                self.vault.load_dek(dek)
                logger.info("Vault unlocked; protected site fields are readable again.")
                return

        # No slot yet: this database predates key slots, so the user's key is
        # the vault key itself. Validate it the old way, then adopt the slot
        # layout without re-encrypting a single field.
        self.vault.unlock(key, self.get_vault_verifier())
        self._adopt_user_key_slot(secret)
        logger.info("Vault unlocked; protected site fields are readable again.")

    def _adopt_user_key_slot(self, secret: bytes) -> None:
        """Create the user-key slot for a vault that predates key slots.

        The existing key becomes the vault key, so the stored ciphertext stays
        byte-for-byte identical and the key the user saved keeps working.
        """
        record = self._build_slot_record(
            slot_id=USER_KEY_SLOT_ID,
            slot_type=SLOT_USER_KEY,
            secret=secret,
            dek=secret,
            label="用户密钥",
        )
        try:
            with self._lock, self._connection() as conn:
                self._insert_slot(conn, record)
        except Exception as exc:
            # Unlocking already succeeded; a failed upgrade must not block use.
            logger.warning(f"Could not create the user key slot: {exc}")
            return
        logger.info("Upgraded the vault to the key slot layout.")

    def lock_encryption(self) -> None:
        """Drop the in-memory key, returning the vault to its locked state."""
        self.vault.lock()
        logger.info("Vault locked; protected site fields are no longer readable.")

    def _rewrite_sensitive(
        self,
        conn: sqlite3.Connection,
        records: list[tuple[str, list[str]]],
        seal: bool,
    ) -> None:
        """Rewrite protected columns for every site, sealing or opening them."""
        assignments = ", ".join(f"{column} = ?" for column in _SENSITIVE_COLUMNS)
        for site_id, values in records:
            written = [self.vault.encrypt(value) if seal else value for value in values]
            conn.execute(f"UPDATE sites SET {assignments} WHERE id = ?", (*written, site_id))

    def _clear_vault_settings(self, conn: sqlite3.Connection) -> None:
        """Remove vault bookkeeping keys and every key slot.

        Both disabling and resetting encryption go through here, so the slots
        can never outlive the vault key they wrap.
        """
        conn.execute(
            f"DELETE FROM settings WHERE key IN ({', '.join('?' * len(_VAULT_KEYS))})",
            _VAULT_KEYS,
        )
        conn.execute("DELETE FROM vault_slots")

    def _read_setting(self, key: str, default: Any) -> Any:
        """Read a single raw settings value."""
        with self._lock, self._connection() as conn:
            row = conn.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
        if row is None:
            return default
        return _load_json(row["value"], row["value"])

    # ------------------------------------------------------------------
    # Settings Operations
    # ------------------------------------------------------------------
    def _save_settings_records(self, conn: sqlite3.Connection, settings_data: dict[str, Any]) -> None:
        """Internal helper to save settings key-values into database."""
        for key, value in settings_data.items():
            conn.execute(
                "INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                (key, json.dumps(value, ensure_ascii=False)),
            )

    def get_settings(self) -> dict[str, Any]:
        """Read plugin settings from SQLite.

        Returns:
            Settings dictionary merged with defaults. Vault bookkeeping keys are
            excluded; use ``is_encryption_enabled`` and ``get_vault_verifier``.
        """
        settings = dict(DEFAULT_SETTINGS)
        with self._lock, self._connection() as conn:
            cursor = conn.execute("SELECT key, value FROM settings")
            for row in cursor.fetchall():
                if row["key"] in _INTERNAL_KEYS:
                    continue
                settings[row["key"]] = _load_json(row["value"], row["value"])

        settings.pop("cf_fingerprint_fallback", None)
        settings["http_impersonate"] = normalize_impersonate(
            settings.get("http_impersonate")
        )
        return settings

    def save_settings(
        self,
        settings_data: dict[str, Any],
        *,
        rearm_lock_alert: bool = False,
    ) -> None:
        """Save settings dictionary to SQLite.

        Args:
            settings_data: Settings dictionary. Vault bookkeeping keys are ignored.
            rearm_lock_alert: Also clear the persisted one-shot alert flag in
                the same transaction when the alert target changes.
        """
        payload = {key: value for key, value in settings_data.items() if key not in _INTERNAL_KEYS}
        with self._lock, self._connection() as conn:
            conn.execute("BEGIN TRANSACTION")
            try:
                self._save_settings_records(conn, payload)
                if rearm_lock_alert:
                    self._save_settings_records(conn, {LOCK_NOTIFY_SENT_KEY: False})
                conn.commit()
                # Drop the cleanup cache so the next write re-reads the new values.
                self._cleanup_settings_cache = None
            except Exception:
                conn.rollback()
                raise

    # ------------------------------------------------------------------
    # History Logs Operations
    # ------------------------------------------------------------------
    def record_history(
        self,
        entry: dict[str, Any],
        max_records: int | None = None,
        retention_days: int | None = None,
    ) -> None:
        """Record a single check-in result history log and optionally prune old entries.

        Args:
            entry: Log dictionary with keys timestamp, type, manual, success, report, details.
            max_records: Maximum number of history records to retain. If None, use the
                global "max_history_records" setting. A value of 0 disables row-count
                cleanup without affecting age-based cleanup.
            retention_days: Maximum age of history records in days. If None, use the
                global "history_retention_days" setting. A value of 0 disables age-based
                cleanup without affecting row-count cleanup. The global
                "auto_cleanup_logs" setting is the master switch: when disabled, it
                suppresses both global and per-call cleanup values.
        """
        self.record_history_entries([entry], max_records, retention_days)

    def record_history_entries(
        self,
        entries: list[dict[str, Any]],
        max_records: int | None = None,
        retention_days: int | None = None,
    ) -> None:
        """Record several history logs in one transaction, then prune once.

        A batch check-in writes one entry per site, so inserting them together
        avoids reopening the database and re-running cleanup for every site.

        Args:
            entries: Log dictionaries, oldest first.
            max_records: See :meth:`record_history`.
            retention_days: See :meth:`record_history`.
        """
        if not entries:
            return

        cleanup_enabled, configured_max_records, configured_retention_days = self._get_cleanup_settings()
        if max_records is None:
            max_records = configured_max_records
        if retention_days is None:
            retention_days = configured_retention_days
        # Per-call values only override their corresponding numeric settings. The
        # global auto_cleanup_logs switch remains authoritative for every write.
        if not cleanup_enabled:
            max_records = 0
            retention_days = 0
        max_records = self._normalize_nonnegative_int(max_records)
        retention_days = self._normalize_nonnegative_int(retention_days)

        with self._lock, self._connection() as conn:
            for entry in entries:
                details = entry.get("details", [])
                cursor = conn.execute(
                    """
                    INSERT INTO history_logs (timestamp, type, manual, success, report, details)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        entry.get("timestamp", datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
                        entry.get("type", "scheduled"),
                        1 if entry.get("manual") else 0,
                        1 if entry.get("success") else 0,
                        entry.get("report", ""),
                        json.dumps(details, ensure_ascii=False),
                    ),
                )
                if cursor.lastrowid is not None:
                    self._index_history_entry_sites(conn, int(cursor.lastrowid), details)

            if retention_days > 0:
                cutoff = datetime.now() - timedelta(days=retention_days)
                conn.execute(
                    "DELETE FROM history_logs WHERE timestamp < ?",
                    (cutoff.strftime("%Y-%m-%d %H:%M:%S"),),
                )

            # Apply the row limit as a separate rule. When both rules are configured,
            # age cleanup runs first and the row limit then applies to the remaining logs.
            if max_records > 0:
                conn.execute(
                    """
                    DELETE FROM history_logs
                    WHERE id NOT IN (
                        SELECT id FROM history_logs ORDER BY id DESC LIMIT ?
                    )
                    """,
                    (max_records,),
                )

    def read_history_logs(
        self,
        limit: int | None = 100,
        before_id: int | None = None,
        start_date: str | None = None,
        end_date: str | None = None,
        site_id: str | None = None,
        exclude_type: str | None = None,
    ) -> list[dict[str, Any]]:
        """Read recent history log records ordered from newest to oldest.

        Args:
            limit: Maximum number of logs to return. ``None`` returns all matching logs.
            before_id: Optional log ID cursor for pagination. When provided, returns logs with id < before_id.
            start_date: Optional inclusive start date in YYYY-MM-DD format.
            end_date: Optional inclusive end date in YYYY-MM-DD format.
            site_id: Optional site ID used to filter through the indexed association table.
            exclude_type: Optional log type to leave out.

        Returns:
            List of history log dictionaries.
        """
        with self._lock, self._connection() as conn:
            start_bound, end_bound = self._history_date_bounds(start_date, end_date)
            site_filter = str(site_id).strip() if site_id is not None else None
            if not site_filter:
                site_filter = None
            if site_filter:
                cursor = conn.execute(
                    """
                    SELECT history_logs.*
                    FROM history_logs
                    INNER JOIN history_log_sites AS indexed_sites
                        ON indexed_sites.history_id = history_logs.id
                    WHERE indexed_sites.site_id = ?
                      AND (? IS NULL OR history_logs.timestamp >= ?)
                      AND (? IS NULL OR history_logs.timestamp <= ?)
                      AND (? IS NULL OR history_logs.id < ?)
                      AND (? IS NULL OR history_logs.type != ?)
                    ORDER BY history_logs.id DESC
                    LIMIT ?
                    """,
                    (
                        site_filter,
                        start_bound,
                        start_bound,
                        end_bound,
                        end_bound,
                        before_id,
                        before_id,
                        exclude_type,
                        exclude_type,
                        limit if limit is not None else -1,
                    ),
                )
            else:
                cursor = conn.execute(
                    """
                    SELECT * FROM history_logs
                    WHERE (? IS NULL OR timestamp >= ?)
                      AND (? IS NULL OR timestamp <= ?)
                      AND (? IS NULL OR id < ?)
                      AND (? IS NULL OR type != ?)
                    ORDER BY id DESC
                    LIMIT ?
                    """,
                    (
                        start_bound,
                        start_bound,
                        end_bound,
                        end_bound,
                        before_id,
                        before_id,
                        exclude_type,
                        exclude_type,
                        limit if limit is not None else -1,
                    ),
                )
            logs = []
            for row in cursor.fetchall():
                logs.append({
                    "id": row["id"],
                    "timestamp": row["timestamp"],
                    "type": row["type"],
                    "manual": bool(row["manual"]),
                    "success": bool(row["success"]),
                    "report": row["report"],
                    "details": _load_json(row["details"], []),
                })
            return logs

    def count_history_logs(
        self,
        start_date: str | None = None,
        end_date: str | None = None,
    ) -> int:
        """Count history log records, optionally within an inclusive date range.

        Returns:
            Total record count integer.
        """
        with self._lock, self._connection() as conn:
            start_bound, end_bound = self._history_date_bounds(start_date, end_date)
            cursor = conn.execute(
                """
                SELECT COUNT(*) FROM history_logs
                WHERE (? IS NULL OR timestamp >= ?)
                  AND (? IS NULL OR timestamp <= ?)
                """,
                (
                    start_bound,
                    start_bound,
                    end_bound,
                    end_bound,
                ),
            )
            row = cursor.fetchone()
            return int(row[0]) if row else 0

    def clear_history_logs(self) -> None:
        """Clear all history log records from SQLite."""
        with self._lock, self._connection() as conn:
            conn.execute("DELETE FROM history_logs")


def _load_json(text: Any, default: Any) -> Any:
    """Parse JSON text, returning ``default`` when it is missing or malformed."""
    if text in (None, ""):
        return default
    try:
        return json.loads(text)
    except (TypeError, ValueError):
        return default


def _dump_action_config(action: dict[str, Any]) -> str:
    """Serialize the non-sensitive half of an action config."""
    return json.dumps(
        {
            "path": action.get("path", ""),
            "protocol": action.get("protocol", "auto"),
            "credential_id": action.get("credential_id", ""),
        },
        ensure_ascii=False,
    )


def _split_tasks(raw: Any) -> tuple[list[dict[str, Any]], dict[str, dict[str, Any]]]:
    """Split a task list into its plain config and its secrets, keyed by task id.

    A task without headers or a body gets no secret entry, so a site without
    any stays unencrypted, as an empty header list does.
    """
    plain: list[dict[str, Any]] = []
    secrets: dict[str, dict[str, Any]] = {}
    for task in normalize_tasks(raw):
        task_plain, task_secret = split_task(task)
        plain.append(task_plain)
        if task_secret["headers"] or task_secret["body"]:
            secrets[task["id"]] = task_secret
    return plain, secrets


def _row_value(row: sqlite3.Row | dict[str, Any], key: str) -> Any:
    """Read a column from a Row or dict, tolerating a missing key."""
    if isinstance(row, dict):
        return row.get(key)
    try:
        return row[key]
    except (IndexError, KeyError):
        return None


def _is_legacy_site(row: dict[str, Any]) -> bool:
    """Return whether a site dict predates the credential list.

    Legacy rows carry ``auth_type``/``auth_value`` and none of the current
    ``credentials``/``checkin``/``balance`` keys. Detecting them here means the
    JSON migration, an in-place schema upgrade, and a hand-fed payload all take
    the same conversion path.
    """
    if any(key in row for key in ("credentials", "checkin", "balance")):
        return False
    return any(
        key in row
        for key in ("auth_type", "auth_value", "checkin_endpoint", "custom_headers", "solve_acw_sc_v2")
    )


def _legacy_site_to_site(row: dict[str, Any]) -> dict[str, Any]:
    """Convert a pre-credential-list site row into the current shape.

    The single ``auth_type``/``auth_value`` pair becomes one credential; the
    legacy endpoint becomes the check-in path; custom headers apply to both
    the check-in and balance actions. The acw_sc__v2 flag is dropped: solving
    is a global setting now.
    """
    auth_value = str(row.get("auth_value") or "").strip()
    cred_type = normalize_credential_type(row.get("auth_type"))
    if cred_type not in (CRED_TOKEN, CRED_COOKIE):
        cred_type = CRED_TOKEN

    credentials: list[dict[str, Any]] = []
    credential_id = ""
    if auth_value:
        credential_id = "cred_1"
        credential: dict[str, Any] = {
            "id": credential_id,
            "type": cred_type,
            "label": "",
            "value": auth_value,
        }
        if cred_type == CRED_TOKEN:
            credential["auto_bearer"] = True
        credentials.append(credential)

    headers = normalize_headers(row.get("custom_headers"))
    shared = {
        "protocol": "auto",
        "credential_id": credential_id,
        "headers": headers,
    }

    site: dict[str, Any] = {
        "id": row.get("id"),
        "name": row.get("name", ""),
        "type": normalize_site_type(row.get("type")),
        "base_url": str(row.get("base_url") or "").strip(),
        "proxy": str(row.get("proxy") or "").strip(),
        "credentials": credentials,
        "checkin": {"path": normalize_path(row.get("checkin_endpoint")), **shared},
        "balance": {"path": "", **shared},
        "enabled": bool(row.get("enabled", True)),
        "created_at": row.get("created_at"),
    }
    for key in ("last_checkin_date", "last_checkin_time", "last_quota"):
        if row.get(key) is not None:
            site[key] = row[key]
    if row.get("last_checkin_success") is not None:
        site["last_checkin_success"] = bool(row["last_checkin_success"])
    return site
