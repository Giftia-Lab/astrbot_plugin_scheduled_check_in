"""Canonical shapes and normalization helpers for site configuration.

A site owns three things:

* a **credential list** — Authorization Tokens, Cookies, and OAuth logins;
* a **check-in action** — path, protocol, chosen credential, extra headers;
* a **balance action** — same structure, minus the OAuth protocol.

Storage, the HTTP adapters, and the web API all normalize through this module
so a hand-edited database row and a freshly submitted form end up identical.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

# ----------------------------------------------------------------------
# Credential types
# ----------------------------------------------------------------------
CRED_TOKEN = "token"
CRED_COOKIE = "cookie"
CRED_GITHUB_OAUTH = "github_oauth"
CRED_LINUXDO_OAUTH = "linuxdo_oauth"

CREDENTIAL_TYPES: tuple[str, ...] = (
    CRED_TOKEN,
    CRED_COOKIE,
    CRED_GITHUB_OAUTH,
    CRED_LINUXDO_OAUTH,
)

# OAuth credentials, in the order tried when no credential is named.
OAUTH_CREDENTIAL_TYPES: tuple[str, ...] = (CRED_GITHUB_OAUTH, CRED_LINUXDO_OAUTH)

# Direct-request credentials, in the order tried when no credential is named.
REQUEST_CREDENTIAL_TYPES: tuple[str, ...] = (CRED_TOKEN, CRED_COOKIE)

CREDENTIAL_LABELS: dict[str, str] = {
    CRED_TOKEN: "Authorization Token",
    CRED_COOKIE: "Cookie",
    CRED_GITHUB_OAUTH: "Github OAuth",
    CRED_LINUXDO_OAUTH: "LinuxDO OAuth",
}

# ----------------------------------------------------------------------
# Action protocols
# ----------------------------------------------------------------------
PROTOCOL_AUTO = "auto"
PROTOCOL_GET = "get"
PROTOCOL_POST = "post"
PROTOCOL_OAUTH = "oauth"

CHECKIN_PROTOCOLS: tuple[str, ...] = (PROTOCOL_AUTO, PROTOCOL_GET, PROTOCOL_POST, PROTOCOL_OAUTH)
BALANCE_PROTOCOLS: tuple[str, ...] = (PROTOCOL_AUTO, PROTOCOL_GET, PROTOCOL_POST)

# ----------------------------------------------------------------------
# Site frameworks
# ----------------------------------------------------------------------
SITE_TYPE_NEW_API = "new-api"
SITE_TYPE_GENERIC = "generic_rest"
SITE_TYPES: tuple[str, ...] = (SITE_TYPE_NEW_API, SITE_TYPE_GENERIC)

# Header New-API uses to scope a Cookie session to a numeric user id.
NEW_API_USER_HEADER = "new-api-user"

# Cookie newer New-API builds keep their refresh token in.
REFRESH_COOKIE_NAME = "new_api_refresh"

ACTION_CHECKIN = "checkin"
ACTION_BALANCE = "balance"

# ----------------------------------------------------------------------
# Check-in schedule
# ----------------------------------------------------------------------
# A site checks in at the global time unless its check-in action names its
# own: a fixed time of day, or a random one within a range.
CHECKIN_SCHEDULE_GLOBAL = "global"
CHECKIN_SCHEDULE_FIXED = "fixed"
CHECKIN_SCHEDULE_RANGE = "range"
CHECKIN_SCHEDULE_MODES: tuple[str, ...] = (
    CHECKIN_SCHEDULE_GLOBAL,
    CHECKIN_SCHEDULE_FIXED,
    CHECKIN_SCHEDULE_RANGE,
)
DEFAULT_CHECKIN_SCHEDULE: dict[str, str] = {
    "mode": CHECKIN_SCHEDULE_GLOBAL,
    "time": "08:30",
    "start": "08:00",
    "end": "10:30",
}


# ----------------------------------------------------------------------
# Headers
# ----------------------------------------------------------------------
def parse_header_text(text: str) -> list[dict[str, str]]:
    """Parse ``Key: Value`` lines (the legacy storage format) into pairs."""
    pairs: list[dict[str, str]] = []
    for line in str(text or "").splitlines():
        stripped = line.strip()
        if not stripped or ":" not in stripped:
            continue
        key, _, value = stripped.partition(":")
        key = key.strip()
        if key:
            pairs.append({"key": key, "value": value.strip()})
    return pairs


def normalize_headers(raw: Any) -> list[dict[str, str]]:
    """Coerce any supported header representation into a list of pairs.

    Accepts the current list-of-pairs form, a plain mapping, and the legacy
    newline-separated ``Key: Value`` text. Entries without a key are dropped.
    """
    if raw is None or raw == "":
        return []
    if isinstance(raw, str):
        return parse_header_text(raw)
    if isinstance(raw, dict):
        return [
            {"key": str(key).strip(), "value": "" if value is None else str(value)}
            for key, value in raw.items()
            if str(key).strip()
        ]
    if not isinstance(raw, list):
        return []

    pairs: list[dict[str, str]] = []
    for item in raw:
        if isinstance(item, dict):
            key = str(item.get("key", "")).strip()
            value = item.get("value")
        elif isinstance(item, (list, tuple)) and len(item) == 2:
            key = str(item[0]).strip()
            value = item[1]
        else:
            continue
        if key:
            pairs.append({"key": key, "value": "" if value is None else str(value)})
    return pairs


def headers_to_mapping(pairs: Any) -> dict[str, str]:
    """Flatten header pairs into a mapping, later entries winning."""
    mapping: dict[str, str] = {}
    for pair in normalize_headers(pairs):
        mapping[pair["key"]] = pair["value"]
    return mapping


def find_header(pairs: Any, key: str) -> str:
    """Return a header value by case-insensitive name, or an empty string."""
    wanted = str(key or "").strip().lower()
    for pair in normalize_headers(pairs):
        if pair["key"].lower() == wanted:
            return pair["value"]
    return ""


def upsert_header(pairs: Any, key: str, value: str) -> list[dict[str, str]]:
    """Return header pairs with ``key`` set to ``value`` (case-insensitive)."""
    normalized = normalize_headers(pairs)
    wanted = str(key or "").strip()
    if not wanted:
        return normalized
    lowered = wanted.lower()
    for pair in normalized:
        if pair["key"].lower() == lowered:
            pair["value"] = "" if value is None else str(value)
            return normalized
    normalized.append({"key": wanted, "value": "" if value is None else str(value)})
    return normalized


# ----------------------------------------------------------------------
# Credentials
# ----------------------------------------------------------------------
def normalize_credential_type(raw: Any) -> str:
    """Map a credential type onto a supported value, defaulting to token."""
    candidate = str(raw or "").strip().lower().replace("-", "_")
    aliases = {
        "bearer_token": CRED_TOKEN,
        "authorization": CRED_TOKEN,
        "authorization_token": CRED_TOKEN,
        "github": CRED_GITHUB_OAUTH,
        "linuxdo": CRED_LINUXDO_OAUTH,
        "linux_do": CRED_LINUXDO_OAUTH,
        "linux_do_oauth": CRED_LINUXDO_OAUTH,
    }
    candidate = aliases.get(candidate, candidate)
    return candidate if candidate in CREDENTIAL_TYPES else CRED_TOKEN


def is_oauth_credential(credential: Any) -> bool:
    """Return whether a credential dict uses an OAuth login flow."""
    if not isinstance(credential, dict):
        return False
    return credential.get("type") in OAUTH_CREDENTIAL_TYPES


def credential_label(credential: Any) -> str:
    """Return a human-friendly name for a credential."""
    if not isinstance(credential, dict):
        return ""
    label = str(credential.get("label") or "").strip()
    if label:
        return label
    return CREDENTIAL_LABELS.get(str(credential.get("type") or ""), "凭据")


def holds_refresh_cookie(cookie: Any) -> bool:
    """Whether a stored station cookie jar can be refreshed without a login.

    Newer New-API builds keep a thirty-day refresh token in this cookie and
    authenticate with short-lived bearer tokens minted from it.
    """
    for part in str(cookie or "").split(";"):
        name, sep, _value = part.strip().partition("=")
        if sep and name.strip() == REFRESH_COOKIE_NAME:
            return True
    return False


def _to_int(raw: Any) -> int:
    """Coerce a stored number to a non-negative int, 0 when unusable."""
    if isinstance(raw, bool):
        return 0
    try:
        return max(int(float(raw)), 0)
    except (TypeError, ValueError):
        return 0


def normalize_provider_cookies(raw: Any) -> list[dict[str, Any]]:
    """Normalize a provider cookie jar without discarding cookie scope.

    Args:
        raw: Browser cookie records, or URL-based records used to seed a jar.

    Returns:
        JSON-safe cookies keyed by name, domain and path. Expired records are
        retained so an old header cannot resurrect a deleted scoped cookie.
    """
    if not isinstance(raw, list):
        return []
    cookies: dict[tuple[str, str, str], dict[str, Any]] = {}
    for item in raw:
        if not isinstance(item, dict):
            continue
        try:
            origin = urlsplit(str(item.get("url") or ""))
        except ValueError:
            continue
        name = str(item.get("name") or "")
        domain = str(item.get("domain") or origin.hostname or "").strip().lower()
        path = str(item.get("path") or "/")
        value = str(item.get("value") or "")
        if (
            not name
            or not domain.lstrip(".")
            or not path.startswith("/")
            or any(c in name for c in "\r\n;= \t")
            or any(c in domain for c in "/\r\n; \t")
            or any(c in value for c in "\r\n")
        ):
            continue
        try:
            expires = float(item.get("expires", -1))
        except (ValueError, TypeError):
            continue
        if not math.isfinite(expires):
            continue
        same_site = str(item.get("sameSite") or "Lax").capitalize()
        cookie = {
            "name": name,
            "value": value,
            "domain": domain,
            "path": path,
            "secure": item.get("secure", origin.scheme == "https") is True,
            "httpOnly": item.get("httpOnly") is True,
            "sameSite": same_site if same_site in ("Strict", "Lax", "None") else "Lax",
            "expires": -1.0 if expires < 0 else expires,
        }
        cookies[(name, domain, path)] = cookie
    return list(cookies.values())


def normalize_credential(raw: Any, index: int = 0) -> dict[str, Any]:
    """Normalize one credential entry.

    Args:
        raw: Raw credential mapping.
        index: Position in the list, used to synthesize a missing id.

    Returns:
        A credential dict with a stable id, type, and type-specific fields.
    """
    source = raw if isinstance(raw, dict) else {}
    cred_type = normalize_credential_type(source.get("type"))
    cred_id = str(source.get("id") or "").strip() or f"cred_{index + 1}"
    credential: dict[str, Any] = {
        "id": cred_id,
        "type": cred_type,
        "label": str(source.get("label") or "").strip(),
        "value": str(source.get("value") or "").strip(),
    }
    if cred_type == CRED_TOKEN:
        # Users paste raw tokens far more often than "Bearer <token>".
        credential["auto_bearer"] = bool(source.get("auto_bearer", True))
    if cred_type == CRED_COOKIE:
        # The OAuth credential whose login wrote this station cookie, empty
        # for one the user pasted; see DatabaseManager.upsert_station_cookie.
        credential["source_credential_id"] = str(source.get("source_credential_id") or "").strip()
        credential["value_updated_at"] = str(source.get("value_updated_at") or "").strip()
    if cred_type in OAUTH_CREDENTIAL_TYPES:
        credential["provider_cookies"] = normalize_provider_cookies(
            source.get("provider_cookies")
        )
        # The station cookie jar the login produced. On newer New-API builds it
        # holds the refresh token (``new_api_refresh``) rather than a session.
        credential["session_cookie"] = str(source.get("session_cookie") or "").strip()
        credential["session_updated_at"] = str(source.get("session_updated_at") or "").strip()
        # The short-lived bearer token those builds authenticate with instead,
        # and when it expires (unix seconds, 0 when unknown).
        credential["access_token"] = str(source.get("access_token") or "").strip()
        credential["access_expires_at"] = _to_int(source.get("access_expires_at"))
        # When the provider last rotated the cookie we hold. Kept here because
        # normalization runs on every read and write, and an unlisted field
        # would be dropped on the next save.
        credential["value_updated_at"] = str(source.get("value_updated_at") or "").strip()
    return credential


def normalize_credentials(raw: Any) -> list[dict[str, Any]]:
    """Normalize a credential list, dropping malformed entries and duplicate ids."""
    if not isinstance(raw, list):
        return []
    credentials: list[dict[str, Any]] = []
    seen: set[str] = set()
    for index, item in enumerate(raw):
        credential = normalize_credential(item, index)
        if credential["id"] in seen:
            credential["id"] = f"{credential['id']}_{index + 1}"
        seen.add(credential["id"])
        credentials.append(credential)
    return credentials


def find_credential(credentials: Any, credential_id: str) -> dict[str, Any] | None:
    """Look a credential up by id."""
    wanted = str(credential_id or "").strip()
    if not wanted or not isinstance(credentials, list):
        return None
    for credential in credentials:
        if isinstance(credential, dict) and str(credential.get("id") or "") == wanted:
            return credential
    return None


def _first_of_type(credentials: list[Any], types: tuple[str, ...]) -> dict[str, Any] | None:
    """Return the first credential matching ``types`` in preference order."""
    for wanted in types:
        for credential in credentials:
            if isinstance(credential, dict) and credential.get("type") == wanted:
                return credential
    return None


@dataclass
class CredentialPlan:
    """How an action should authenticate."""

    # "request" sends the credential directly; "oauth" logs in first and uses
    # the resulting station session cookie.
    mode: str
    credential: dict[str, Any] | None
    reason: str = ""


def resolve_credential(credentials: Any, protocol: str) -> CredentialPlan:
    """Pick the credential an action should use.

    Explicit selection wins. Otherwise Authorization Token is preferred over
    Cookie for direct requests, and Github over LinuxDO for OAuth. An action
    that finds no direct credential falls back to an OAuth login when one is
    configured, since that is the only remaining way to authenticate.

    Args:
        credentials: Normalized credential list.
        protocol: Action protocol (``auto``/``get``/``post``/``oauth``).

    Returns:
        A ``CredentialPlan``; ``credential`` is None when nothing is usable.
    """
    items = [item for item in credentials if isinstance(item, dict)] if isinstance(credentials, list) else []
    if not items:
        return CredentialPlan("request", None, "站点未配置任何凭据")

    if protocol == PROTOCOL_OAUTH:
        chosen = _first_of_type(items, OAUTH_CREDENTIAL_TYPES)
        if chosen is None:
            return CredentialPlan("oauth", None, "签到协议为 OAuth，但未配置 OAuth 凭据")
        return CredentialPlan("oauth", chosen)

    chosen = _first_of_type(_pickable(items), REQUEST_CREDENTIAL_TYPES)
    if chosen is not None:
        return CredentialPlan("request", chosen)

    fallback = _first_of_type(items, OAUTH_CREDENTIAL_TYPES)
    if fallback is not None:
        return CredentialPlan("oauth", fallback, "未配置 Token/Cookie 凭据，改用 OAuth 登录")
    return CredentialPlan("request", None, "站点未配置可用凭据")


def _pickable(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Credentials an action may pick when it names none.

    A Cookie a login wrote back is left out. Picking it would quietly turn
    the action away from the OAuth login it came from, which logs in again
    when the session expires, to a copy that cannot. It is still used when
    an action names it.
    """
    return [
        item for item in items
        if not (item.get("type") == CRED_COOKIE and item.get("source_credential_id"))
    ]


def resolve_action_credential(credentials: Any, action: Any) -> CredentialPlan:
    """Resolve the credential for one action config, honouring its explicit pick."""
    protocol = normalize_protocol(action.get("protocol") if isinstance(action, dict) else None, allow_oauth=True)
    explicit_id = str((action or {}).get("credential_id") or "").strip() if isinstance(action, dict) else ""
    if explicit_id:
        chosen = find_credential(credentials, explicit_id)
        if chosen is not None:
            mode = "oauth" if is_oauth_credential(chosen) else "request"
            return CredentialPlan(mode, chosen)
    return resolve_credential(credentials, protocol)


# ----------------------------------------------------------------------
# Actions
# ----------------------------------------------------------------------
def normalize_protocol(raw: Any, allow_oauth: bool) -> str:
    """Map a protocol onto a supported value, defaulting to framework detection."""
    candidate = str(raw or "").strip().lower()
    allowed = CHECKIN_PROTOCOLS if allow_oauth else BALANCE_PROTOCOLS
    if candidate in ("", "follow", "framework"):
        return PROTOCOL_AUTO
    return candidate if candidate in allowed else PROTOCOL_AUTO


def normalize_path(raw: Any) -> str:
    """Normalize a custom endpoint path, keeping absolute URLs intact."""
    path = str(raw or "").strip()
    if not path:
        return ""
    if path.startswith(("http://", "https://")):
        return path
    return path if path.startswith("/") else f"/{path}"


def normalize_action(raw: Any, allow_oauth: bool, scheduled: bool = False) -> dict[str, Any]:
    """Normalize one action (check-in or balance) config block.

    Args:
        raw: Raw action mapping.
        allow_oauth: Whether the OAuth protocol is selectable.
        scheduled: Whether the action carries its own time of day, as the
            check-in action does.

    Returns:
        An action dict with path, protocol, credential_id and headers, plus
        the schedule when ``scheduled``. The acw_sc__v2 and ML-DSA options
        are global settings, so the per-action flags earlier versions stored
        are dropped.
    """
    source = raw if isinstance(raw, dict) else {}
    action = {
        "path": normalize_path(source.get("path")),
        "protocol": normalize_protocol(source.get("protocol"), allow_oauth=allow_oauth),
        "credential_id": str(source.get("credential_id") or "").strip(),
        "headers": normalize_headers(source.get("headers")),
    }
    if scheduled:
        action["schedule"] = normalize_checkin_schedule(source.get("schedule"))
    return action


def normalize_time_of_day(raw: Any, default: str) -> str:
    """Normalize ``H:MM`` / ``HH:MM`` to ``HH:MM``, ``default`` when invalid."""
    hours, sep, minutes = str(raw or "").strip().partition(":")
    if not sep or not hours.isdigit() or not minutes.isdigit():
        return default
    hour, minute = int(hours), int(minutes)
    if hour > 23 or minute > 59:
        return default
    return f"{hour:02d}:{minute:02d}"


def time_of_day_minutes(text: str) -> int:
    """Minutes since midnight of a normalized ``HH:MM``."""
    hours, _, minutes = text.partition(":")
    return int(hours) * 60 + int(minutes)


def normalize_checkin_schedule(raw: Any) -> dict[str, str]:
    """Normalize a site's own check-in time.

    Every field is kept whatever the mode, so the editor can switch modes
    without losing what was typed. A range given backwards is put the right
    way round here, so a stored one can always be run; a save is refused
    one first, see :func:`validate_checkin_schedule`.
    """
    source = raw if isinstance(raw, dict) else {}
    mode = str(source.get("mode") or "").strip().lower()
    start = normalize_time_of_day(source.get("start"), DEFAULT_CHECKIN_SCHEDULE["start"])
    end = normalize_time_of_day(source.get("end"), DEFAULT_CHECKIN_SCHEDULE["end"])
    if time_of_day_minutes(end) < time_of_day_minutes(start):
        start, end = end, start
    return {
        "mode": mode if mode in CHECKIN_SCHEDULE_MODES else CHECKIN_SCHEDULE_GLOBAL,
        "time": normalize_time_of_day(source.get("time"), DEFAULT_CHECKIN_SCHEDULE["time"]),
        "start": start,
        "end": end,
    }


def validate_checkin_schedule(raw: Any) -> str:
    """Why a submitted check-in time cannot be saved as given, or ``""``.

    Only the fields the chosen mode uses are checked, and against what was
    sent rather than its normalized form, which would hide the mistake.
    """
    if not isinstance(raw, dict):
        return ""
    mode = str(raw.get("mode") or "").strip().lower()
    if mode == CHECKIN_SCHEDULE_FIXED:
        if normalize_time_of_day(raw.get("time"), "") == "":
            return "签到时间应为 HH:MM"
    elif mode == CHECKIN_SCHEDULE_RANGE:
        start = normalize_time_of_day(raw.get("start"), "")
        end = normalize_time_of_day(raw.get("end"), "")
        if not start or not end:
            return "签到时间范围应为 HH:MM ~ HH:MM"
        if time_of_day_minutes(end) < time_of_day_minutes(start):
            return "签到时间范围的结束不能早于开始"
    return ""


def site_checkin_schedule(site: Any) -> dict[str, str] | None:
    """A site's own check-in time, None when it follows the global one."""
    checkin = site.get("checkin") if isinstance(site, dict) else None
    schedule = normalize_checkin_schedule(checkin.get("schedule") if isinstance(checkin, dict) else None)
    return None if schedule["mode"] == CHECKIN_SCHEDULE_GLOBAL else schedule


def normalize_site_type(raw: Any) -> str:
    """Map a framework type onto a supported value.

    Aliases cover the names earlier versions stored, so an untouched database
    row still selects the adapter it always used.
    """
    candidate = str(raw or "").strip().lower()
    aliases = {
        "one-api": SITE_TYPE_NEW_API,
        "one_api": SITE_TYPE_NEW_API,
        "new_api": SITE_TYPE_NEW_API,
        "generic": SITE_TYPE_GENERIC,
        "generic-rest": SITE_TYPE_GENERIC,
        "rest": SITE_TYPE_GENERIC,
        "custom": SITE_TYPE_GENERIC,
    }
    candidate = aliases.get(candidate, candidate)
    return candidate if candidate in SITE_TYPES else SITE_TYPE_NEW_API


def wants_new_api_user_probe(site: Any, action: Any) -> bool:
    """Return whether ``new-api-user`` should be probed and written back.

    Only New-API style sites following the framework protocol qualify, and only
    while the header is still unset.
    """
    if not isinstance(site, dict) or not isinstance(action, dict):
        return False
    if normalize_site_type(site.get("type")) != SITE_TYPE_NEW_API:
        return False
    if normalize_protocol(action.get("protocol"), allow_oauth=True) != PROTOCOL_AUTO:
        return False
    return not find_header(action.get("headers"), NEW_API_USER_HEADER).strip()
