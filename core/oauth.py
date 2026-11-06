"""OAuth login flows used to refresh relay-station session cookies.

New-API style stations expose a standard four-legged flow:

1. ``GET  {base_url}/api/status``          reveals whether a provider is enabled
   and its ``client_id``.
2. ``GET  {base_url}/api/oauth/state``     issues a short-lived ``state``. Most
   builds also bind it to a *server-side session*, so the cookie that response
   sets has to be carried to leg 4 or the station rejects the callback with
   ``state is empty or not same``. Newer branches serve the same route over
   ``POST``; older ones have no such route at all. vsllm.cc guards it with a
   proof of work (see core/pow.py), solved first when the site asks for it.
3. ``GET  {authorize_url}``                is called with the user's *third
   party* session cookie (``user_session`` for Github, ``_t`` for LinuxDO) and
   redirects back with an authorization ``code``. The query string mirrors the
   station's own login page exactly — the callback is inferred from the
   registered application, so sending a guessed ``redirect_uri`` is refused.
4. ``GET  {base_url}/api/oauth/{provider}`` exchanges the code and returns the
   station's own session cookie.

The third-party leg only redirects when the user has already approved the
station's OAuth application in a browser at least once; otherwise the provider
answers with a consent page, which is reported back as an actionable error.

A provider that bounces to its own login page has rejected the *session*; one
that answers 401/403 with no redirect has refused the *request*, which usually
means something other than an expired cookie. The two are reported apart.
"""

from __future__ import annotations

import json
import logging
import re
import secrets
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import parse_qs, urlencode, urljoin, urlparse

from curl_cffi.requests import AsyncSession

from .browser import BrowserRequest, _cookie_specs, _in_zone, _zone, request_body
from .cloudflare import CloudflareContext, is_cloudflare_challenge
from .http_client import MLDSA_ADDED, mldsa_extra_fp, mldsa_support
from .pow import POW_PURPOSE_OAUTH, is_refusal, refusal_message, send_with_proof
from .site_schema import holds_refresh_cookie, normalize_provider_cookies

logger = logging.getLogger("astrbot")

# Field names forks use for the OAuth state token, in preference order.
_STATE_KEYS = ("flow_token", "state", "token", "oauth_state", "flowToken")

# Longest response body quoted back in an error message.
_ERROR_BODY_LIMIT = 300


def _abridge(text: str, limit: int = _ERROR_BODY_LIMIT) -> str:
    """Shorten a response body for inclusion in an error message."""
    body = " ".join(str(text or "").split())
    if len(body) <= limit:
        return body
    return f"{body[:limit]}…"


def _extract_flow_token(payload: Any) -> str:
    """Pull the OAuth state token out of any shape a fork might return.

    Accepts ``data.flow_token``, a bare ``data`` string, the same keys at the
    top level, and the ``state``/``token`` aliases.
    """
    if isinstance(payload, str):
        return payload.strip()
    if not isinstance(payload, dict):
        return ""

    data = payload.get("data")
    if isinstance(data, str) and data.strip():
        return data.strip()
    for source in (data, payload):
        if isinstance(source, dict):
            for key in _STATE_KEYS:
                value = source.get(key)
                if isinstance(value, str) and value.strip():
                    return value.strip()
    return ""

GITHUB_OAUTH = "github_oauth"
LINUXDO_OAUTH = "linuxdo_oauth"


class OAuthError(RuntimeError):
    """Raised when an OAuth login cannot be completed."""

    def __init__(self, message: str, *, blames_credential: bool = True) -> None:
        super().__init__(message)
        # False for a failure that says nothing about the user's cookie, such
        # as a proof of work refused before the cookie was ever sent.
        self.blames_credential = blames_credential


@dataclass(frozen=True)
class OAuthProvider:
    """Static description of one upstream identity provider."""

    # Path segment used by ``/api/oauth/{provider}`` on the relay station.
    slug: str
    label: str
    authorize_url: str
    # Keys published by ``/api/status``.
    enabled_key: str
    client_id_key: str
    # Cookie the user copies out of their browser for the provider's domain.
    cookie_hint: str
    # Additional cookies the provider needs before it treats a non-browser
    # request as signed in. Github in particular answers a request carrying only
    # user_session with a redirect to its login page.
    companion_cookies: tuple[str, ...] = ()
    # Cookie that carries a solved bot-management challenge. Deliberately not in
    # all_cookies: it is only needed when the host actually challenges, so
    # demanding it up front would report a working credential as incomplete.
    challenge_cookie: str = "cf_clearance"
    # Query parameters beyond client_id and state. These mirror the station's own
    # browser flow exactly: every provider validates the authorize request
    # against the registered application, so a parameter the browser omits is not
    # a harmless extra — supplying a guessed one is grounds for rejection.
    extra_authorize_params: dict[str, str] = field(default_factory=dict)
    # Redirects the authorize endpoint sends a browser through to rebuild its
    # own session from the account's main-site cookies, as exact ``host/path``
    # strings. A browser follows them silently; stopping at the first one
    # reports a signed-in account as needing to log in.
    relay_redirects: tuple[str, ...] = ()
    # Cookies set along those redirects that are worth keeping even though the
    # user never copied them: holding the authorize host's own session lets the
    # next run skip the relay entirely.
    adopted_cookies: tuple[str, ...] = ()
    # Pattern for the approve link on a consent page the provider shows on
    # every authorize, remembered grant or not. Following it is the click the
    # user would make for the application they set this credential up for.
    consent_approve: str = ""

    @property
    def all_cookies(self) -> tuple[str, ...]:
        """Every cookie name worth copying, primary first."""
        return (self.cookie_hint, *self.companion_cookies)

    @property
    def authorize_host(self) -> str:
        """Host whose cookies the user must copy, e.g. ``github.com``."""
        return urlparse(self.authorize_url).netloc or self.authorize_url


PROVIDERS: dict[str, OAuthProvider] = {
    GITHUB_OAUTH: OAuthProvider(
        slug="github",
        label="Github OAuth",
        authorize_url="https://github.com/login/oauth/authorize",
        enabled_key="github_oauth",
        client_id_key="github_client_id",
        cookie_hint="user_session",
        # user_session on its own is not enough: Github checks the same-site
        # mirror and its session cookie before honouring an authorize request,
        # and otherwise redirects to its own login page.
        companion_cookies=("__Host-user_session_same_site", "_gh_sess", "logged_in"),
        extra_authorize_params={"scope": "user:email"},
    ),
    LINUXDO_OAUTH: OAuthProvider(
        slug="linuxdo",
        label="LinuxDO OAuth",
        authorize_url="https://connect.linux.do/oauth2/authorize",
        enabled_key="linuxdo_oauth",
        client_id_key="linuxdo_client_id",
        cookie_hint="_t",
        companion_cookies=("_forum_session",),
        extra_authorize_params={"response_type": "code"},
        # Without its own auth.session-token, connect.linux.do bounces through
        # Discourse SSO on linux.do (where _t signs in) and back to authorize.
        relay_redirects=(
            "linux.do/session/sso_provider",
            "connect.linux.do/discourse/sso_callback",
            "connect.linux.do/oauth2/authorize",
        ),
        adopted_cookies=("auth.session-token",),
        # "允许" on connect.linux.do's consent page, a plain link.
        consent_approve=r'href="(/oauth2/approve/[A-Za-z0-9_-]+)"',
    ),
}


@dataclass
class OAuthLoginResult:
    """Outcome of one OAuth login attempt."""

    success: bool
    message: str
    session_cookie: str = ""
    # The provider cookie after any rotation, when it changed during the flow.
    # Empty means "unchanged"; the caller must not overwrite a working value
    # with an empty string.
    rotated_provider_cookie: str = ""
    # Station account id from the callback body, empty when it carried none.
    # New-API refuses a cookie-authenticated request without it in the
    # ``New-Api-User`` header, and this is the only place it can be learned.
    user_id: str = ""
    # Short-lived dashboard bearer token newer New-API builds issue instead of
    # honouring the session cookie, and when it expires (unix seconds, 0 when
    # unknown). Empty on builds that still authenticate by cookie.
    access_token: str = ""
    access_expires_at: int = 0
    # None means no jar update; scopes are stored separately from the legacy
    # header so same-name cookies on different SSO hosts survive a round-trip.
    provider_cookies: list[dict[str, Any]] | None = None
    # On a failure, whether it points at the credential; see OAuthError.
    blames_credential: bool = True


@dataclass
class TokenRefreshResult:
    """Outcome of trading a refresh cookie for a new access token."""

    success: bool
    message: str
    # The station cookie jar with the rotated refresh cookie merged in. The old
    # refresh token is retired by this very call, so this must be persisted.
    session_cookie: str = ""
    access_token: str = ""
    access_expires_at: int = 0
    user_id: str = ""


def parse_cookie_header(value: str) -> dict[str, str]:
    """Parse a ``Cookie`` header into a mapping, keeping the last of duplicates."""
    jar: dict[str, str] = {}
    for part in str(value or "").split(";"):
        name, sep, cookie_value = part.strip().partition("=")
        name = name.strip()
        if name and sep:
            jar[name] = cookie_value.strip()
    return jar


def format_cookie_header(jar: dict[str, str]) -> str:
    """Render a cookie mapping back into a ``Cookie`` header value."""
    return "; ".join(f"{name}={value}" for name, value in jar.items() if name)


def merge_rotated_cookies(
    current: str, response_cookies: Any, adopt: tuple[str, ...] = ()
) -> str:
    """Merge a response's ``Set-Cookie`` values over the stored cookie.

    Providers rotate session cookies as they are used, and a browser stays
    signed in precisely because it keeps the rotated values. Replaying one
    frozen snapshot forever goes stale on its own and looks like a replayed
    session. Only the names the response actually set are replaced, so a
    partial response cannot drop the rest of the jar.

    Args:
        current: The cookie header currently stored for the credential.
        response_cookies: Cookie jar from a provider response.
        adopt: Names to add even when the stored cookie lacks them.

    Returns:
        The merged cookie header, or an empty string when nothing changed.
    """
    jar = parse_cookie_header(current)
    if not jar:
        return ""

    changed = False
    try:
        items = list(response_cookies.items())
    except Exception:
        return ""

    for name, raw in items:
        name = str(name or "").strip()
        if not name or (name not in jar and name not in adopt):
            # Only refresh cookies we already hold. A provider may set unrelated
            # cookies (analytics, flash messages) that add noise and no value.
            continue
        value = str(getattr(raw, "value", raw) or "")
        # An expiry is signalled by a blank or sentinel value; keeping the old
        # one is safer than storing a deletion.
        if not value or value in ("deleted", '""'):
            continue
        if jar.get(name) != value:
            jar[name] = value
            changed = True

    return format_cookie_header(jar) if changed else ""


def get_provider(credential_type: str) -> OAuthProvider | None:
    """Return the provider description for a credential type."""
    return PROVIDERS.get(str(credential_type or "").strip().lower())


def _is_relay(provider: OAuthProvider, url: str) -> bool:
    """Whether ``url`` is one of the provider's session-rebuilding redirects."""
    parsed = urlparse(url)
    if parsed.scheme != "https":
        return False
    return f"{parsed.netloc}{parsed.path}" in provider.relay_redirects


def _cookie_string(cookies: Any) -> str:
    """Render a curl_cffi cookie jar as a ``Cookie`` header value."""
    parts = []
    for name, value in cookies.items():
        raw = getattr(value, "value", value)
        if name:
            parts.append(f"{name}={raw}")
    return "; ".join(parts)


def _extract_code(location: str) -> str:
    """Pull the authorization ``code`` out of a redirect target."""
    if not location:
        return ""
    query = parse_qs(urlparse(location).query)
    values = query.get("code") or []
    return str(values[0]).strip() if values else ""


@dataclass(frozen=True)
class _LoginFields:
    """Identity and token fields a station login or refresh response carries."""

    user_id: str = ""
    access_token: str = ""
    access_expires_at: int = 0


def _extract_login_fields(body: str) -> _LoginFields:
    """Pull the account id and any access token out of a login response body.

    Released New-API answers with the user record as ``data``. Newer builds
    answer with ``data.access_token`` and nest the user under ``data.user``.
    """
    try:
        payload = json.loads(body)
    except (TypeError, ValueError):
        return _LoginFields()
    data = payload.get("data") if isinstance(payload, dict) else None
    if not isinstance(data, dict):
        return _LoginFields()

    user = data.get("user") if isinstance(data.get("user"), dict) else data
    user_id = user.get("id")
    if user_id in (None, "") or isinstance(user_id, bool):
        user_id = ""

    token = data.get("access_token")
    token = token.strip() if isinstance(token, str) else ""
    expires_at = data.get("access_expires_at")
    if not isinstance(expires_at, (int, float)) or isinstance(expires_at, bool):
        expires_at = 0
    elif expires_at > 10**12:  # milliseconds
        expires_at = expires_at / 1000
    return _LoginFields(str(user_id).strip(), token, int(expires_at) if token else 0)


def _extract_error(location: str) -> str:
    """Pull an OAuth error description out of a redirect target."""
    query = parse_qs(urlparse(location).query)
    for key in ("error_description", "error"):
        values = query.get(key) or []
        if values:
            return str(values[0]).strip()
    return ""


def _safe_location(location: str) -> str:
    """Render a redirect target for the trace with secrets removed.

    A redirect can carry the authorization code and the state, neither of which
    belongs in a stored log.
    """
    try:
        parsed = urlparse(str(location or ""))
    except ValueError:
        return ""
    if not parsed.scheme and not parsed.netloc and not parsed.path:
        return ""
    redacted = {}
    for key, values in parse_qs(parsed.query).items():
        redacted[key] = "***" if key in ("code", "state", "flow_token") else (values[0] if values else "")
    query = "&".join(f"{k}={v}" for k, v in redacted.items())
    base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}" if parsed.netloc else parsed.path
    return f"{base}?{query}" if query else base


def _cookie_names(cookie: str) -> set[str]:
    """Return the cookie names present in a raw ``Cookie`` header value."""
    names = set()
    for part in str(cookie or "").split(";"):
        name, _, _value = part.strip().partition("=")
        if name.strip():
            names.add(name.strip())
    return names


def _missing_cookies(provider: OAuthProvider, cookie: str) -> list[str]:
    """Return the recommended cookies absent from what the user pasted."""
    present = _cookie_names(cookie)
    return [name for name in provider.all_cookies if name not in present]


def _refused_request_message(
    provider: OAuthProvider,
    cookie: str,
    status: int,
    body: str,
) -> str:
    """Explain an authorize request refused outright, with no redirect.

    Distinct from a bounce to the login page: the session may well be valid
    while the request itself is refused, so this lists the plausible causes
    instead of asserting the cookie is dead. Any message the provider supplied
    comes first — it is better evidence than any guess made here.
    """
    detail = _abridge(_strip_html(body), 160)
    missing = _missing_cookies(provider, cookie)

    reasons = []
    if missing:
        reasons.append(f"Cookie 缺少 {', '.join(missing)}")
    reasons.append("该账号尚未在浏览器中授权过此站点的 OAuth 应用")
    reasons.append(f"{provider.authorize_host} 拒绝了服务端发起的请求（风控 / 频率限制）")
    reasons.append("会话 Cookie 已失效")

    message = (
        f"{provider.label} 拒绝了授权请求 (HTTP {status})，未返回跳转。可能原因："
        + "；".join(f"{index}. {reason}" for index, reason in enumerate(reasons, 1))
        + f"。请先在浏览器完成一次 {provider.authorize_host} 的 OAuth 授权，"
        f"并复制该域名的完整 Cookie（至少 {', '.join(provider.all_cookies)}）。"
    )
    if detail:
        message += f" 站点返回：{detail}"
    return message


def _strip_html(text: str) -> str:
    """Reduce an HTML error page to its readable text."""
    without_scripts = re.sub(
        r"<(script|style)\b.*?</\1>", " ", str(text or ""), flags=re.S | re.I
    )
    return " ".join(re.sub(r"<[^>]+>", " ", without_scripts).split())


def _cloudflare_challenge_message(
    provider: OAuthProvider,
    status: int,
    detail: str = "",
    remedy: str = "",
) -> str:
    """Explain a Cloudflare interstitial that remains after browser handling.

    Two things users get wrong here. A challenge says nothing about the
    credential, so every remedy for an expired session is the wrong advice. And
    the clearance cookie is bound to the IP address and fingerprint that solved
    the challenge, so copying it from a browser on another machine — or leaving
    a proxy in the way — invalidates it. Say both, and say what was already
    tried, so nobody re-copies a working cookie waiting for a different result.

    Args:
        provider: The OAuth provider that returned the challenge.
        status: HTTP status of the challenged response.
        detail: What browser handling tried, if anything.
        remedy: A setting that would have changed the handshake Cloudflare
            judged, when there is one; it goes before the stopgaps.

    Returns:
        The challenge failure message and available remedies.
    """
    tried = f"{detail}。" if detail else ""
    return (
        f"{provider.authorize_host} 由 Cloudflare 托管，本次返回了人机验证页 (HTTP {status})，"
        f"并非凭据失效。{tried}{remedy}"
        "Cloudflare 的判定随出口 IP 与时段变化，机房 IP 更容易被拦，可稍后重试。"
        f"应急办法：在浏览器通过验证后，把 {provider.challenge_cookie} 与 "
        f"{', '.join(provider.all_cookies)} 一起复制进该凭据；"
        "该 Cookie 绑定出口 IP 与浏览器指纹，需与浏览器同一出口（通常要清空站点代理），"
        "且「全局设置」的浏览器指纹要与该浏览器一致，通常仅数十分钟有效。"
        "需要长期稳定请给该站点改用 Github OAuth 或普通 Token / Cookie 凭据。"
    )


def _rejected_session_message(provider: OAuthProvider, cookie: str) -> str:
    """Explain a provider bouncing an authorize request to its login page.

    An expired cookie and an incomplete one look identical from here, and in
    practice the second is more common: people copy only the cookie named in
    the hint. So name the missing ones instead of only claiming expiry.
    """
    missing = _missing_cookies(provider, cookie)
    if missing:
        return (
            f"{provider.label} 未接受该会话 Cookie（缺少 {', '.join(missing)}）。"
            f"请从浏览器开发者工具复制 {provider.authorize_host} 的完整 Cookie，"
            f"至少包含 {', '.join(provider.all_cookies)}，而不是只复制 {provider.cookie_hint}。"
        )
    return (
        f"{provider.label} 会话 Cookie 已失效或被拒绝，"
        f"请重新从浏览器复制 {provider.authorize_host} 的完整 Cookie。"
    )


class OAuthLoginClient:
    """Runs the relay-station OAuth login flow for one site."""

    def __init__(
        self,
        session: AsyncSession,
        base_url: str,
        impersonate: str,
        proxy: str | None = None,
        on_attempt: Callable[..., None] | None = None,
        cloudflare: CloudflareContext | None = None,
        mldsa: bool = False,
        vs_pow: bool = False,
    ) -> None:
        """Initialize the client.

        Args:
            session: Active curl_cffi session.
            base_url: Relay station root URL without a trailing slash.
            impersonate: Browser fingerprint to reuse for every leg.
            proxy: Site-wide proxy, applied to the third-party legs too.
            on_attempt: Optional callback recording each leg in the caller's
                request trace. Without it an OAuth failure is invisible in the
                log detail view, which is the only place a user can see what
                the station actually replied.
            cloudflare: The run's Cloudflare context. Every leg is routed
                through it, so a challenge — most often on connect.linux.do —
                is retried directly in the headless browser.
            mldsa: Add ML-DSA to the TLS handshake of every leg when the
                fingerprint lacks it — what Cloudflare in front of
                connect.linux.do looks for in a Chrome handshake.
            vs_pow: Solve vsllm.cc's proof of work before the state request,
                as the site's own login page does. Off, the challenge endpoint
                is never contacted.
        """
        self.session = session
        self.base_url = base_url.rstrip("/")
        self.impersonate = impersonate
        self.proxy = proxy or None
        self.mldsa = mldsa
        self.vs_pow = vs_pow
        self._on_attempt = on_attempt
        self._cloudflare = cloudflare
        # What the Cloudflare context tried on the latest leg, for the message
        # shown when a challenge survives.
        self._cloudflare_detail = ""
        # Set by the authorize leg. Held here rather than returned, because a
        # rejected login still needs its rotation persisted — replaying a value
        # the provider has already retired guarantees the next failure.
        self._rotated_provider_cookie = ""
        self._provider_cookies: list[dict[str, Any]] = []
        self._provider_cookies_changed = False

    def _record(
        self,
        step: str,
        method: str,
        url: str,
        *,
        status: int | None = None,
        success: bool = False,
        response_text: str = "",
        message: str = "",
        error: str = "",
    ) -> None:
        """Forward one leg to the caller's trace, if it wants them."""
        if self._on_attempt is None:
            return
        try:
            self._on_attempt(
                step=step,
                method=method,
                endpoint=url,
                status=status,
                success=success,
                response_text=response_text,
                message=message,
                error=error,
            )
        except Exception:  # tracing must never break the login
            pass

    async def _request(
        self,
        method: str,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        json_body: dict[str, Any] | None = None,
        params: dict[str, str] | None = None,
        allow_redirects: bool = True,
        navigate: bool = False,
        provider_cookies: list[dict[str, Any]] | None = None,
    ) -> Any:
        """Issue one request with the site's proxy and fingerprint applied.

        A Cloudflare challenge is handed to the run's context, which may answer
        with the response of a retry from a headless browser.

        Args:
            provider_cookies: Scoped cookies for a provider navigation.
            navigate: The request is a browser navigation — the authorize leg —
                so a browser retry opens it as a page, rather than calling it
                with fetch(), and stops at the redirect off the provider.
        """

        response = await self.session.request(
            method,
            url,
            headers=headers or {},
            json=json_body,
            params=params,
            proxy=self.proxy,
            impersonate=self.impersonate,
            extra_fp=mldsa_extra_fp(self.impersonate, self.mldsa),
            allow_redirects=allow_redirects,
        )
        self._cloudflare_detail = ""
        if self._cloudflare is None:
            return response
        resolution = await self._cloudflare.resolve(
            response=response,
            record=self._record,
            browser_request=BrowserRequest(
                method,
                f"{url}{'&' if '?' in url else '?'}{urlencode(params)}"
                if params
                else url,
                dict(headers or {}),
                body=request_body(json_body),
                proxy=self.proxy,
                verify=getattr(self.session, "verify", True) is not False,
                navigate=navigate,
                provider_cookies=provider_cookies,
            ),
        )
        self._cloudflare_detail = resolution.detail
        return resolution.response

    def _mldsa_remedy(self) -> str:
        """Point at the global ML-DSA option, when it would have mattered.

        Only for a leg that went out without ML-DSA on a fingerprint the option
        adds it to; with ML-DSA already in the handshake the advice is moot.
        """
        profile = self.impersonate
        if self.mldsa or mldsa_support(profile) != MLDSA_ADDED:
            return ""
        return (
            f"本次 TLS 握手（{profile}）未携带 ML-DSA 签名算法，"
            "Cloudflare 会拦截不带它的 Chrome 握手：可在「全局设置 → 网络与常规」开启「TLS 携带 ML-DSA」，"
            "或把浏览器指纹改为 chrome150。"
        )

    async def _fetch_client_id(self, provider: OAuthProvider) -> str:
        """Read the provider's ``client_id`` from ``/api/status``."""
        url = f"{self.base_url}/api/status"
        try:
            response = await self._request("GET", url)
        except Exception as exc:
            self._record("探测 OAuth 配置", "GET", url, error=str(exc))
            raise OAuthError(f"探测站点 OAuth 配置失败: {exc}") from exc

        status = getattr(response, "status_code", None)
        body = getattr(response, "text", "") or ""

        def fail(detail: str) -> OAuthError:
            self._record("探测 OAuth 配置", "GET", url, status=status,
                         response_text=body, error=detail)
            return OAuthError(detail)

        if is_cloudflare_challenge(status or 0, body, getattr(response, "headers", None)):
            # Otherwise reported as "not JSON", which sends the user looking
            # at the station's configuration instead of its firewall.
            tried = f"；{self._cloudflare_detail}" if self._cloudflare_detail else ""
            remedy = self._mldsa_remedy()
            raise fail(
                f"站点 /api/status 返回了 Cloudflare 人机验证页 (HTTP {status}){tried}"
                + (f"。{remedy}" if remedy else "")
            )

        try:
            payload = json.loads(body)
        except (TypeError, ValueError) as exc:
            raise fail("站点 /api/status 未返回 JSON，无法探测 OAuth 配置") from exc

        data = payload.get("data") if isinstance(payload, dict) else None
        if not isinstance(data, dict):
            raise fail("站点 /api/status 响应缺少 data 字段")

        if data.get(provider.enabled_key) is False:
            raise fail(f"站点未启用 {provider.label}")

        client_id = str(data.get(provider.client_id_key) or "").strip()
        if not client_id:
            raise fail(f"站点未配置 {provider.label} 的 client_id")

        self._record("探测 OAuth 配置", "GET", url, status=status, success=True,
                     response_text=body)
        return client_id

    async def _fetch_flow_token(self, provider: OAuthProvider) -> tuple[str, str]:
        """Ask the station for a single-use OAuth ``state`` token.

        Classic one-api / New-API registers this as ``GET`` and answers with the
        state as a bare ``data`` string, while storing it in a **server-side
        session** keyed by a cookie set on this very response. That cookie has
        to travel to the callback, or the station compares the returned state
        against an empty session and answers ``state is empty or not same``.
        Newer forks use ``POST`` and nest the value under ``data.flow_token``,
        so both methods are tried.

        Returns:
            Tuple of ``(state, station_cookie)``. The cookie is empty when the
            station did not set one.
        """
        url = f"{self.base_url}/api/oauth/state"
        attempts: list[tuple[str, int | None, str]] = []

        for method in ("GET", "POST"):
            step = "获取 OAuth state"
            try:
                response, proof, error = await self._request_state(method, url, provider)
            except Exception as exc:
                self._record(step, method, url, error=str(exc))
                raise OAuthError(f"获取 OAuth state 失败: {exc}") from exc
            if error:
                raise OAuthError(f"获取 OAuth state 失败：{error}", blames_credential=False)

            status = getattr(response, "status_code", None)
            body = getattr(response, "text", "") or ""

            if is_refusal(body):
                detail = refusal_message(self.vs_pow, bool(proof))
                self._record(step, method, url, status=status, response_text=body, error=detail)
                raise OAuthError(f"获取 OAuth state 失败：{detail}", blames_credential=False)

            # A 404/405 here means the route is not registered for this verb;
            # the other verb may still work, so keep going before giving up.
            if status in (404, 405):
                attempts.append((method, status, body))
                self._record(
                    step, method, url, status=status, response_text=body,
                    message="该方法不被支持，尝试其他方法",
                )
                continue

            try:
                payload = json.loads(body)
            except (TypeError, ValueError):
                attempts.append((method, status, body))
                self._record(step, method, url, status=status,
                             response_text=body, error="响应非 JSON")
                continue

            flow_token = _extract_flow_token(payload)
            if flow_token:
                station_cookie = _cookie_string(getattr(response, "cookies", {}) or {})
                self._record(
                    step, method, url, status=status, success=True,
                    response_text=body,
                    message=("已取得 state 与会话 Cookie" if station_cookie
                             else "已取得 state（站点未下发会话 Cookie）"),
                )
                return flow_token, station_cookie

            message = ""
            if isinstance(payload, dict):
                message = str(payload.get("message") or "").strip()
            detail = message or f"响应中没有可用的 state 字段：{_abridge(body)}"
            self._record(step, method, url, status=status,
                         response_text=body, error=detail)
            raise OAuthError(f"OAuth state 接口未返回 state（{detail}）")

        # Neither verb exists. Older builds validated nothing, so a local state
        # is worth trying, but a station that does validate will reject it.
        local_state = secrets.token_urlsafe(24)
        tried = ", ".join(f"{m} HTTP {s}" for m, s, _ in attempts)
        self._record(
            "获取 OAuth state", "-", url, success=True,
            message=f"站点无 state 接口（{tried}），改用本地生成的 state",
        )
        logger.info("No /api/oauth/state on %s (%s); using a local state.", self.base_url, tried)
        return local_state, ""

    async def _request_state(
        self, method: str, url: str, provider: OAuthProvider
    ) -> tuple[Any, dict[str, str], str]:
        """Request a state, with a solved Vs PoW when the site asks for one.

        Only with ``vs_pow`` on; otherwise one plain request. The challenge is
        asked for anonymously, like the state itself.

        Returns:
            Tuple of the last response, the proof it carried, and an error when
            a challenge could not be solved in time; the response is then None.
        """
        if method == "GET":
            headers: dict[str, str] = {}
            extra: dict[str, Any] = {"params": {"provider": provider.slug}}
        else:
            headers = {"Content-Type": "application/json"}
            extra = {"json_body": {"provider": provider.slug, "intent": "login"}}

        async def send(proof: dict[str, str]) -> Any:
            return await self._request(method, url, headers={**headers, **proof}, **extra)

        if not self.vs_pow:
            return await send({}), {}, ""

        async def fetch(challenge: str) -> tuple[int, str]:
            got = await self._request("GET", challenge)
            return getattr(got, "status_code", 0) or 0, getattr(got, "text", "") or ""

        return await send_with_proof(
            self.base_url, POW_PURPOSE_OAUTH, fetch, self._record, send,
            refused=lambda sent: is_refusal(getattr(sent, "text", "") or ""),
        )

    def _remember_provider_cookies(
        self, provider: OAuthProvider, response: Any, url: str, cookie: str
    ) -> None:
        """Merge a response's provider cookies without losing their scopes.

        Args:
            provider: Provider whose cookies may be retained.
            response: Browser snapshot or curl response cookie jar.
            url: URL that issued a curl response.
            cookie: Legacy header defining the cookie names the user holds.
        """
        allowed = set(parse_cookie_header(cookie)) | set(provider.adopted_cookies)
        zone = _zone(urlparse(provider.authorize_url).hostname or "")
        snapshot = getattr(response, "provider_cookies", None)
        full_snapshot = snapshot is not None
        if not full_snapshot:
            snapshot = []
            jar = getattr(getattr(response, "cookies", None), "jar", None)
            if jar is not None:
                for held in jar:
                    snapshot.append(
                        {
                            "name": held.name,
                            "value": held.value,
                            "domain": ("." if held.domain_specified else "")
                            + held.domain.lstrip("."),
                            "path": held.path or "/",
                            "secure": held.secure,
                            "expires": held.expires if held.expires is not None else -1,
                            "httpOnly": held.has_nonstandard_attr("HttpOnly")
                            or str(
                                held.get_nonstandard_attr("http_only", "False")
                            ).lower()
                            == "true",
                            "sameSite": held.get_nonstandard_attr("SameSite", "Lax"),
                        }
                    )
            else:
                # Test doubles and older response implementations expose only
                # name/value pairs. Such a response belongs to its exact host.
                for name, value in getattr(response, "cookies", {}).items():
                    snapshot.append(
                        {
                            "name": name,
                            "value": getattr(value, "value", value),
                            "url": url,
                        }
                    )
        incoming = [
            item
            for item in normalize_provider_cookies(snapshot)
            if item["name"] in allowed and _in_zone(item["domain"].lstrip("."), zone)
        ]
        if not incoming and not full_snapshot:
            return
        changed = {(c["name"], c["domain"], c["path"]): c for c in incoming}
        merged = []
        for previous in self._provider_cookies:
            key = (previous["name"], previous["domain"], previous["path"])
            if key in changed:
                continue
            # A browser snapshot omits deleted cookies. Keep their scope as a
            # tombstone, so the old header cannot recreate them next time.
            merged.append({**previous, "expires": 1.0} if full_snapshot else previous)
        merged = normalize_provider_cookies([*merged, *incoming])
        if merged != self._provider_cookies:
            self._provider_cookies = merged
            self._provider_cookies_changed = True

    async def _authorize(
        self,
        provider: OAuthProvider,
        client_id: str,
        state: str,
        third_party_cookie: str,
    ) -> tuple[str, str]:
        """Exchange the third-party session cookie for an authorization code.

        Returns:
            Tuple of ``(code, rotated_cookie)``. The rotated cookie is empty
            unless the provider refreshed one of the cookies we already hold.
        """
        params: dict[str, str] | None = {
            "client_id": client_id,
            "state": state,
            **provider.extra_authorize_params,
        }
        url = provider.authorize_url
        cookie = third_party_cookie
        step = f"{provider.label} 授权"
        referer, fetch_site = f"{self.base_url}/", "cross-site"
        consented = False

        # Each relay hop is sent by hand rather than with allow_redirects, so
        # every one gets the Cloudflare handling and the cookies it sets are
        # carried to the next, as a browser's jar would.
        for _ in range(len(provider.relay_redirects) + 3):
            parts = urlparse(url)
            host, path = parts.hostname or "", parts.path or "/"
            known = {item["name"] for item in self._provider_cookies}
            fallback = {
                name: value
                for name, value in parse_cookie_header(cookie).items()
                if name not in known
            }
            scoped = []
            for item in self._provider_cookies:
                domain = item["domain"]
                matches = (
                    _in_zone(host, domain.lstrip("."))
                    if domain.startswith(".")
                    else host == domain
                )
                if (
                    matches
                    and (
                        path == item["path"]
                        or (
                            path.startswith(item["path"])
                            and (
                                item["path"].endswith("/")
                                or path[len(item["path"]) :].startswith("/")
                            )
                        )
                    )
                    and (not item["secure"] or parts.scheme == "https")
                    and (item["expires"] < 0 or item["expires"] > time.time())
                ):
                    scoped.append(item)
            scoped.sort(key=lambda item: len(item["path"]), reverse=True)
            header = "; ".join(
                [
                    *(f"{item['name']}={item['value']}" for item in scoped),
                    *(f"{name}={value}" for name, value in fallback.items()),
                ]
            )
            try:
                response = await self._request(
                    "GET",
                    url,
                    headers={
                        "Cookie": header,
                        # A browser reaches this page by clicking the provider button
                        # on the station's login page. Send that navigation's full
                        # signature — a Referer without the matching Sec-Fetch-Site
                        # describes a request no browser can make, and bot scoring
                        # reads the inconsistency. Everything else (Accept,
                        # Sec-Ch-Ua, Accept-Language) is left to the impersonation,
                        # which already sends the real Chrome values; overriding one
                        # by hand only makes the header set disagree with the
                        # User-Agent it claims.
                        "Referer": referer,
                        "Sec-Fetch-Site": fetch_site,
                    },
                    params=params,
                    allow_redirects=False,
                    navigate=True,
                    provider_cookies=self._provider_cookies,
                )
            except Exception as exc:
                self._record(step, "GET", url, error=str(exc))
                raise OAuthError(f"请求 {provider.label} 授权端点失败: {exc}") from exc

            # Capture rotation even on failure paths: the provider may have moved
            # the session on before rejecting, and storing the new value keeps the
            # next run from replaying one it has already retired.
            self._remember_provider_cookies(provider, response, url, cookie)
            merged = merge_rotated_cookies(
                cookie, getattr(response, "cookies", {}), provider.adopted_cookies
            )
            if merged:
                cookie = merged
            location = str(response.headers.get("location") or "")
            target = urljoin(url, location) if location else ""
            if (300 <= response.status_code < 400 and _is_relay(provider, target)
                    and not _extract_code(location)):
                parsed = urlparse(target)
                self._record(step, "GET", url, status=response.status_code, success=True,
                             message=f"会话中转至 {parsed.netloc}{parsed.path}")
                url, params = target, None
                continue
            approve = (
                re.search(provider.consent_approve, getattr(response, "text", "") or "")
                if provider.consent_approve and response.status_code == 200 and not consented
                else None
            )
            if not approve:
                break
            consented = True
            self._record(step, "GET", url, status=200, success=True,
                         message="授权确认页，代为点击「允许」")
            # The click is a same-origin navigation from the consent page.
            referer = f"{url}?{urlencode(params)}" if params else url
            fetch_site = "same-origin"
            url, params = urljoin(url, approve.group(1)), None

        rotated = cookie if cookie != third_party_cookie else ""
        if rotated:
            self._rotated_provider_cookie = rotated
            # A legacy header update must be stored with its authoritative
            # scopes, even when only its flattened view changed this time.
            self._provider_cookies_changed = True

        status = response.status_code
        body = getattr(response, "text", "") or ""

        def fail(detail: str) -> OAuthError:
            # A redirect carries its reason in the Location header, and the body
            # is a full consent or login page worth no space. A non-redirect
            # rejection has no Location at all, so there the body is the only
            # evidence — record an abridged copy rather than nothing.
            self._record(
                step, "GET", url, status=status,
                message=f"Location: {_safe_location(location)}" if location else "",
                response_text="" if location else _abridge(body, 400),
                error=detail,
            )
            return OAuthError(detail)

        code = _extract_code(location)
        if code:
            self._record(step, "GET", url, status=status, success=True,
                         message="已取得授权码" + ("（凭据 Cookie 已轮换，将回写）" if rotated else ""))
            return code, rotated

        redirect_error = _extract_error(location)
        if redirect_error:
            raise fail(f"{provider.label} 拒绝授权: {redirect_error}")

        if 300 <= status < 400 and "login" in location.lower():
            # Bounced to the provider's own login page: the session was not
            # accepted, so an expired or incomplete cookie is the likely cause.
            raise fail(_rejected_session_message(provider, third_party_cookie))
        if is_cloudflare_challenge(status, body, getattr(response, "headers", None)):
            # Checked before the generic refusal: a challenge page says nothing
            # about the credential, so every remedy for a bad cookie is wrong
            # advice here and would send the user re-copying it for nothing.
            raise fail(_cloudflare_challenge_message(
                provider, status, self._cloudflare_detail, self._mldsa_remedy()
            ))
        if status in (401, 403):
            # No redirect at all. The session may be fine while the *request* is
            # refused — a blocked client, a rate limit, or an application that
            # has not been authorized for this account — so do not assert that
            # the cookie is dead when the body may say otherwise.
            raise fail(_refused_request_message(provider, third_party_cookie, status, body))
        if status >= 400:
            # An error page of the provider's own, perhaps on a relay hop the
            # browser followed: what it says beats any guess made here.
            answered = urlparse(str(getattr(response, "url", "") or ""))
            page = f"{answered.netloc}{answered.path}" if answered.netloc else provider.authorize_host
            detail = _abridge(_strip_html(body), 160)
            raise fail(
                f"{provider.label} 授权未完成：{page} 返回 HTTP {status}"
                + (f"，页面内容：{detail}" if detail else "")
            )
        raise fail(
            f"{provider.label} 未直接返回授权码 (HTTP {status})，"
            f"请先在浏览器登录该站点并完成一次 OAuth 授权"
        )

    async def _exchange(
        self,
        provider: OAuthProvider,
        code: str,
        state: str,
        station_cookie: str = "",
    ) -> tuple[str, _LoginFields]:
        """Trade the authorization code for the station's session cookie.

        Args:
            provider: Identity provider being used.
            code: Authorization code from the provider.
            state: State that was sent to the provider.
            station_cookie: Cookie the station set when it issued the state. It
                keys the server-side session holding that state, so without it
                the station compares against an empty session and rejects the
                callback with ``state is empty or not same``.

        Returns:
            Tuple of the station cookie jar and the identity and token fields
            of the response body. On newer New-API builds the jar holds the
            refresh cookie and the body the short-lived access token.
        """
        url = f"{self.base_url}/api/oauth/{provider.slug}"
        headers = {"Cookie": station_cookie} if station_cookie else None
        try:
            response = await self._request(
                "GET",
                url,
                headers=headers,
                params={"code": code, "state": state},
                allow_redirects=False,
            )
        except Exception as exc:
            self._record("OAuth 回调", "GET", url, error=str(exc))
            raise OAuthError(f"回调站点 OAuth 接口失败: {exc}") from exc

        status = getattr(response, "status_code", None)
        body = getattr(response, "text", "") or ""
        session_cookie = _cookie_string(response.cookies)
        fields = _extract_login_fields(body)
        if session_cookie or fields.access_token:
            obtained = []
            if session_cookie:
                refreshable = holds_refresh_cookie(session_cookie)
                obtained.append("刷新令牌 Cookie" if refreshable else "会话 Cookie")
            if fields.access_token:
                obtained.append("访问令牌")
            # A body carrying a token is not worth storing in the trace.
            self._record("OAuth 回调", "GET", url, status=status, success=True,
                         response_text="" if fields.access_token else body,
                         message=f"已取得站点{'与'.join(obtained)}")
            return session_cookie, fields

        message = ""
        try:
            payload = json.loads(body)
            if isinstance(payload, dict):
                message = str(payload.get("message") or "").strip()
        except (TypeError, ValueError):
            message = ""
        detail = message or f"站点未在 OAuth 回调中下发会话 Cookie (HTTP {status})"
        self._record("OAuth 回调", "GET", url, status=status,
                     response_text=body, error=detail)
        raise OAuthError(detail)

    async def login(
        self,
        credential_type: str,
        third_party_cookie: str,
        provider_cookies: list[dict[str, Any]] | None = None,
    ) -> OAuthLoginResult:
        """Run the full flow and return the station's session cookie.

        Args:
            credential_type: ``github_oauth`` or ``linuxdo_oauth``.
            third_party_cookie: Provider-domain session cookie from the user.
            provider_cookies: Previously retained provider cookie scopes.

        Returns:
            An ``OAuthLoginResult`` describing success or the failure reason.
        """
        provider = get_provider(credential_type)
        if provider is None:
            return OAuthLoginResult(False, f"不支持的 OAuth 凭据类型: {credential_type}")

        cookie = str(third_party_cookie or "").strip().replace("\n", "").replace("\r", "")
        if not cookie:
            return OAuthLoginResult(
                False,
                f"{provider.label} 凭据为空，请填入 {provider.authorize_host} 的完整 Cookie"
                f"（至少包含 {', '.join(provider.all_cookies)}）",
            )

        zone = _zone(urlparse(provider.authorize_url).hostname or "")
        scoped = [
            item
            for item in normalize_provider_cookies(provider_cookies)
            if _in_zone(item["domain"].lstrip("."), zone)
        ]
        self._provider_cookies = normalize_provider_cookies(
            [
                *scoped,
                *_cookie_specs(
                    provider.authorize_url,
                    parse_cookie_header(cookie).items(),
                    zone_wide=True,
                    provider_cookies=scoped,
                ),
            ]
        )
        self._provider_cookies_changed = False
        self._rotated_provider_cookie = ""

        # Warn rather than refuse: a provider may still accept a partial cookie,
        # and guessing wrong would block a working setup.
        missing = _missing_cookies(provider, cookie)
        if missing:
            logger.info(
                "%s cookie for %s is missing %s; the authorize leg may be rejected.",
                provider.label,
                self.base_url,
                ", ".join(missing),
            )
            self._record(
                f"{provider.label} 凭据检查",
                "-",
                provider.authorize_host,
                success=True,
                message=f"Cookie 缺少 {', '.join(missing)}，若授权被拒请补全",
            )

        try:
            client_id = await self._fetch_client_id(provider)
            state, station_cookie = await self._fetch_flow_token(provider)
            code, rotated_cookie = await self._authorize(provider, client_id, state, cookie)
            session_cookie, fields = await self._exchange(provider, code, state, station_cookie)
        except OAuthError as exc:
            logger.info("OAuth login failed for %s at %s: %s", provider.slug, self.base_url, exc)
            return OAuthLoginResult(
                False,
                str(exc),
                rotated_provider_cookie=self._rotated_provider_cookie,
                provider_cookies=self._provider_cookies
                if self._provider_cookies_changed
                else None,
                blames_credential=exc.blames_credential,
            )

        if rotated_cookie:
            logger.info("%s rotated its session cookie for %s; writing it back.",
                        provider.label, self.base_url)
        logger.info("OAuth login succeeded for %s at %s", provider.slug, self.base_url)
        return OAuthLoginResult(
            True,
            f"{provider.label} 登录成功",
            session_cookie,
            rotated_provider_cookie=rotated_cookie or self._rotated_provider_cookie,
            user_id=fields.user_id,
            access_token=fields.access_token,
            access_expires_at=fields.access_expires_at,
            provider_cookies=self._provider_cookies
            if self._provider_cookies_changed
            else None,
        )

    async def refresh(self, session_cookie: str) -> TokenRefreshResult:
        """Trade the stored refresh cookie for a new access token.

        Newer New-API builds authenticate the dashboard with a bearer token that
        lives fifteen minutes, backed by a thirty-day ``new_api_refresh`` cookie.
        Refreshing is not a login, so it never consumes a login-granted daily
        bonus. Every refresh retires the presented refresh token and sets a new
        one; the caller must persist the returned jar or the next run replays a
        retired token, which the station treats as theft and revokes the session.

        Args:
            session_cookie: The station cookie jar holding ``new_api_refresh``.
        """
        url = f"{self.base_url}/api/user/auth/refresh"
        step = "刷新访问令牌"
        try:
            response = await self._request(
                "POST",
                url,
                headers={
                    "Cookie": session_cookie,
                    # The station rejects a cookie-authenticated refresh whose
                    # Origin is not its own, exactly as for a browser.
                    "Origin": self.base_url,
                    "Referer": f"{self.base_url}/",
                },
            )
        except Exception as exc:
            self._record(step, "POST", url, error=str(exc))
            return TokenRefreshResult(False, f"刷新访问令牌失败: {exc}")

        status = getattr(response, "status_code", None)
        body = getattr(response, "text", "") or ""
        # Merge the rotation before judging the response: a rejection may
        # still have rotated or cleared the cookie.
        jar = merge_rotated_cookies(session_cookie, getattr(response, "cookies", {})) or session_cookie
        fields = _extract_login_fields(body)
        if status == 200 and fields.access_token:
            self._record(step, "POST", url, status=status, success=True, message="已取得新的访问令牌")
            return TokenRefreshResult(
                True, "访问令牌已刷新", jar,
                fields.access_token, fields.access_expires_at, fields.user_id,
            )

        detail = ""
        try:
            payload = json.loads(body)
            if isinstance(payload, dict):
                detail = str(payload.get("code") or payload.get("message") or "").strip()
        except (TypeError, ValueError):
            pass
        message = f"刷新访问令牌失败 (HTTP {status}{f'，{detail}' if detail else ''})"
        self._record(step, "POST", url, status=status, response_text=body, error=message)
        return TokenRefreshResult(False, message, jar)
