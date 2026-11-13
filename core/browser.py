"""Getting past a Cloudflare managed challenge in a real, headless browser.

A managed challenge is solved by the widget's JavaScript, and its clearance is
bound to the TLS fingerprint and IP address that solved it: a curl_cffi session
can neither solve one nor reuse a clearance a browser obtained. So a challenged
request is re-issued from inside a Playwright-driven Chrome, which solves the
challenge itself, and the response is handed back looking like a curl_cffi one.

Two shapes of request are supported:

* **Navigation** (the OAuth authorize leg). The page is opened the way a user
  clicking "log in" would, and the first navigation that leaves the provider's
  domain — the redirect back to the station, carrying the code — is caught and
  never followed, so the station's own page cannot consume the code first. It
  comes back as a 302 whose ``Location`` is that target.
* **API call** (station endpoints). The challenge is solved by opening the
  endpoint with no credentials, whatever the request's method, then the real
  request is made with ``fetch()`` from that page, so it goes out with the
  browser's own handshake and cookies.

Apart from challenges, a site's own Turnstile widget can be made to issue a
token for a request the site guards with one; see
:meth:`BrowserSolver.turnstile_token`.

What a page can see of this browser was measured against the same Chrome run
headed, and only the differences found are covered, by launch options rather
than script: patching navigator properties from JavaScript leaves its own
traces (non-native getters, own properties), and new-headless Chrome already
matches its headed self on ``webdriver``, plugins, ``window.chrome``,
permissions, WebGL and client hints. What remained was the User-Agent, the
window geometry and the scrollbars. An interactive challenge's checkbox is
ticked with a mouse that travels to it.

Playwright is optional, and not in requirements.txt: the dashboard installs it,
and downloads Chromium, on request (see :mod:`core.dependencies`). It is
imported on first use rather than with this module, so an install made while
AstrBot runs takes effect without a restart. Without it, or without a browser
it can drive, every call raises :class:`BrowserUnavailable` and the caller
reports why.
"""

from __future__ import annotations

import asyncio
import contextlib
import html
import importlib
import json
import logging
import os
import random
import time
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import unquote, urljoin, urlsplit

from .site_schema import normalize_provider_cookies

logger = logging.getLogger("astrbot")

# Playwright's entry point, once imported; see load_playwright().
async_playwright: Any = None
# Why the last import attempt failed, if it did.
_import_error = ""

# Deployments differ (Windows desktop, Linux server, Docker), so the hint names
# where to act rather than assuming a `python` on PATH that runs AstrBot.
INSTALL_HINT = (
    "可在插件面板「设置 → 网络与通用」中一键安装 Playwright 并下载 Chromium，"
    "或在 AstrBot 所用的 Python 环境中执行 pip install playwright；运行 AstrBot 的机器上没有 Chrome / Edge 时，"
    "再在该环境中执行 python -m playwright install --no-shell chromium 下载 Chromium（Linux 另加 --with-deps 安装系统依赖）"
)

CHANNEL_AUTO = "auto"
# Real Chrome first: its client hints carry the "Google Chrome" brand, which
# the bundled Chromium cannot claim. "chromium" is Playwright's full build in
# new-headless mode, never the stripped headless shell, whose brands and empty
# plugin list give it away.
BROWSER_CHANNELS: tuple[str, ...] = (CHANNEL_AUTO, "chrome", "msedge", "chromium")
AUTO_ORDER: tuple[str, ...] = ("chrome", "msedge", "chromium")
CHANNEL_NAMES = {"chrome": "Chrome", "msedge": "Edge", "chromium": "Chromium"}

DEFAULT_TIMEOUT_SECONDS = 60.0
MIN_TIMEOUT_SECONDS = 15.0
MAX_TIMEOUT_SECONDS = 300.0
# The browser is kept between requests of a run, and closed once idle.
IDLE_CLOSE_SECONDS = 300.0
_POLL_SECONDS = 0.5
# How long a navigation that settled on a page is still watched for a scripted
# move off the domain.
_GRACE_SECONDS = 2.0

_LAUNCH_ARGS = ("--disable-blink-features=AutomationControlled",)
# Headless, the window has no frame (outer size equals inner), no scrollbars,
# and under Playwright's viewport emulation a screen exactly the size of the
# viewport. A window sized by itself (contexts get no viewport) over a desktop
# screen with a taskbar, scrollbars left on, has a real window's proportions.
_HEADLESS_ARGS = ("--window-size=1536,864", "--screen-info={0,0 1920x1080 workAreaBottom=48}")
_IGNORED_DEFAULT_ARGS = ("--enable-automation", "--hide-scrollbars")

# How often a challenge page is looked over for a checkbox to tick, and how
# long a tick is given to take before the next one.
_LOOK_SECONDS = 1.0
_PRESS_RETRY_SECONDS = 6.0

# Cookies Cloudflare sets for a solved challenge. They are carried from one
# request of a run to the next, so the challenge is solved once per run rather
# than once per request; every other cookie stays with the request it came in.
_CLOUDFLARE_COOKIES = ("cf_clearance", "__cf_bm", "_cfuvid")
# Hosts the challenge itself runs on, which a navigation may visit freely.
_CHALLENGE_HOST_SUFFIXES = ("challenges.cloudflare.com",)

# Headers fetch() may not set; the browser supplies its own. Cookie goes into
# the cookie jar instead, and Referer into fetch's referrer option.
_FORBIDDEN_HEADERS = frozenset({
    "accept-charset", "accept-encoding", "connection", "content-length", "cookie",
    "cookie2", "date", "dnt", "expect", "host", "keep-alive", "origin", "referer",
    "te", "trailer", "transfer-encoding", "upgrade", "user-agent", "via",
})
_FORBIDDEN_PREFIXES = ("sec-", "proxy-")

# Second-level labels under which a registrable domain takes three labels.
_SECOND_LEVELS = frozenset({"ac", "co", "com", "edu", "gov", "net", "org"})

_FETCH_SCRIPT = """
async ({url, method, headers, body, referrer}) => {
  const init = {method, headers, credentials: 'include', redirect: 'follow'};
  if (body !== null) init.body = body;
  if (referrer) init.referrer = referrer;
  const response = await fetch(url, init);
  const out = {};
  response.headers.forEach((value, name) => { out[name] = value; });
  return {status: response.status, url: response.url, headers: out, text: await response.text()};
}
"""

# A page holding nothing but a site's Turnstile widget, answered in place of
# the site's own. The empty icon keeps the browser from asking the site for one.
_TURNSTILE_PAGE = """<!doctype html><html><head><meta charset="utf-8"><title>Turnstile</title>
<link rel="icon" href="data:,">
<script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script></head>
<body><div class="cf-turnstile" data-sitekey="{sitekey}"></div></body></html>"""
# The widget writes its token into a hidden input beside itself.
_TURNSTILE_TOKEN_SCRIPT = "() => (document.querySelector('[name=\"cf-turnstile-response\"]') || {}).value || ''"


class BrowserUnavailable(RuntimeError):
    """Playwright is missing, or no browser could be launched."""


def load_playwright() -> Any:
    """Playwright's ``async_playwright``, imported now if it was not yet; else ``None``.

    A failed import is retried on the next call, so a package installed since
    is picked up.
    """
    global async_playwright, _import_error
    if async_playwright is None:
        importlib.invalidate_caches()
        try:
            from playwright.async_api import async_playwright as entry
        except Exception as exc:  # a broken install raises more than ImportError
            _import_error = "" if isinstance(exc, ModuleNotFoundError) and exc.name == "playwright" else str(exc)
            return None
        async_playwright, _import_error = entry, ""
    return async_playwright


def playwright_installed() -> bool:
    """Whether the Playwright package can be imported."""
    return load_playwright() is not None


def playwright_import_error() -> str:
    """Why Playwright, though present, could not be imported; ``""`` otherwise."""
    return _import_error


def normalize_channel(value: Any) -> str:
    """Validate a configured browser channel, falling back to ``auto``."""
    channel = str(value or "").strip().lower()
    return channel if channel in BROWSER_CHANNELS else CHANNEL_AUTO


def normalize_timeout(value: Any) -> float:
    """Read and clamp the configured browser timeout."""
    try:
        timeout = float(value)
    except (TypeError, ValueError):
        return DEFAULT_TIMEOUT_SECONDS
    if timeout != timeout:  # NaN
        return DEFAULT_TIMEOUT_SECONDS
    return max(MIN_TIMEOUT_SECONDS, min(timeout, MAX_TIMEOUT_SECONDS))


@dataclass(frozen=True)
class BrowserOptions:
    """How the browser is launched."""

    headless: bool = True
    channel: str = CHANNEL_AUTO
    timeout: float = DEFAULT_TIMEOUT_SECONDS


@dataclass
class BrowserRequest:
    """One request, described fully enough to be re-issued from a browser."""

    method: str
    url: str
    headers: dict[str, str] = field(default_factory=dict)
    # Request body as text; JSON for every caller today.
    body: str | None = None
    proxy: str | None = None
    verify: bool = True
    # A top-level navigation that must stop at the first redirect off the
    # target's domain (OAuth authorize), rather than an API call.
    navigate: bool = False
    # Scoped provider cookies from a previous authorization, including expired
    # records that suppress stale values in the legacy Cookie header.
    provider_cookies: list[dict[str, Any]] | None = None


class BrowserResponse:
    """What a browser request came back with, shaped like a curl_cffi response."""

    via_browser = True

    def __init__(
        self,
        status: int,
        text: str = "",
        headers: dict[str, str] | None = None,
        cookies: dict[str, str] | None = None,
        url: str = "",
        provider_cookies: list[dict[str, Any]] | None = None,
    ) -> None:
        self.status_code = status
        self.text = text
        self.headers = {str(k).lower(): str(v) for k, v in (headers or {}).items()}
        self.cookies = dict(cookies or {})
        self.url = url
        self.provider_cookies = provider_cookies


@dataclass
class BrowserOutcome:
    """A browser request's response, with what it learned for later requests."""

    response: BrowserResponse
    # Cloudflare cookies the context held afterwards, as Playwright reports them.
    clearance: list[dict[str, Any]]
    # The browser that went out, e.g. "Chrome 153", for the trace.
    browser: str
    elapsed: float
    # Whether a challenge page was seen and then left behind.
    solved: bool = False


def _zone(host: str) -> str:
    """The registrable domain of ``host``, approximately: ``connect.linux.do`` → ``linux.do``."""
    host = host.lower().strip(".")
    labels = host.split(".")
    if len(labels) <= 2 or host.replace(".", "").isdigit() or ":" in host:
        return host
    if len(labels[-1]) == 2 and labels[-2] in _SECOND_LEVELS:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def _in_zone(host: str, zone: str) -> bool:
    host = host.lower()
    return host == zone or host.endswith(f".{zone}")


def _is_challenge_host(host: str) -> bool:
    host = host.lower()
    return any(host == s or host.endswith(f".{s}") for s in _CHALLENGE_HOST_SUFFIXES)


def _origin(url: str) -> str:
    parts = urlsplit(url)
    return f"{parts.scheme}://{parts.netloc}"


def _same_page(first: str, second: str) -> bool:
    """Whether two URLs name the same page, ignoring the query the challenge adds."""
    a, b = urlsplit(first), urlsplit(second)
    return (a.scheme, a.netloc.lower(), a.path or "/") == (b.scheme, b.netloc.lower(), b.path or "/")


def _header(headers: dict[str, str], name: str) -> str:
    for key, value in headers.items():
        if key.lower() == name:
            return str(value)
    return ""


def _parse_cookie_header(value: str) -> list[tuple[str, str]]:
    pairs = []
    for part in str(value or "").split(";"):
        name, sep, cookie_value = part.strip().partition("=")
        if name.strip() and sep:
            pairs.append((name.strip(), cookie_value.strip()))
    return pairs


def _cookie_specs(
    url: str,
    pairs: Iterable[tuple[str, str]],
    *,
    zone_wide: bool,
    provider_cookies: list[dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    """Turn ``Cookie`` header pairs into cookies Playwright can add.

    Cookies are made host-only (Playwright makes one from a URL), as linux.do
    and connect.linux.do set their sessions, so a value the site sets afresh
    replaces the pasted one. A domain-wide copy would stay beside it, and with
    a name sent twice the site reads the older, pasted value: connect.linux.do
    then turns its own SSO callback away with "Invalid state".

    Args:
        url: Initial request URL.
        pairs: Legacy header values whose scopes are not yet known.
        zone_wide: The cookies are a provider's, pasted as one jar for its
            whole domain, so they go on the registrable domain as well as on
            the host — ``_t`` belongs to linux.do, where the SSO relay of a
            ``connect.linux.do`` authorize reads it. Cloudflare's own go on the
            domain itself: a clearance holds for the whole zone. Otherwise
            every cookie goes on the exact host.
        provider_cookies: Known scopes, which override legacy values by name.

    Returns:
        Live cookie records accepted by Playwright.
    """
    parts = urlsplit(url)
    host = parts.hostname or ""
    zone = _zone(host)
    port = f":{parts.port}" if parts.port else ""
    origins = [f"{parts.scheme}://{parts.netloc}/"]
    if zone_wide and zone != host:
        origins.append(f"{parts.scheme}://{zone}{port}/")
    specs: list[dict[str, Any]] = []
    scoped = normalize_provider_cookies(provider_cookies)
    known = {cookie["name"] for cookie in scoped}
    for name, value in pairs:
        if name in known:
            continue
        if zone_wide and name in _CLOUDFLARE_COOKIES:
            specs.append({"name": name, "value": value, "domain": f".{zone}", "path": "/",
                          "secure": parts.scheme == "https"})
            continue
        # A __Host- cookie belongs to its host alone.
        for origin in origins[:1] if name.startswith("__Host-") else origins:
            specs.append({"name": name, "value": value, "url": origin})
    specs.extend(
        cookie
        for cookie in scoped
        if cookie["expires"] < 0 or cookie["expires"] > time.time()
    )
    return specs


def _site_cookies(cookies: Iterable[dict[str, Any]], pasted: dict[str, str]) -> dict[str, str]:
    """Provide the legacy header view; the scoped jar controls future requests.

    The jar may hold a name twice — the pasted copy on one host, the site's
    rotation of it on another (``_t`` on connect.linux.do and on linux.do) —
    and the rotation is the value worth keeping.

    Args:
        cookies: Browser cookie records, kept separately with their scopes.
        pasted: Header values used to seed the navigation.

    Returns:
        A legacy name/value view for the credential editor. Authorization
        replays the separate scoped jar instead of this flattened view.
    """
    held: dict[str, str] = {}
    for cookie in cookies:
        name, value = cookie["name"], cookie["value"]
        if name not in held or held[name] == pasted.get(name):
            held[name] = value
    return held


def _proxy_settings(proxy: str | None) -> dict[str, str] | None:
    """Playwright's proxy settings for a proxy URL, credentials split out."""
    proxy = (proxy or "").strip()
    if not proxy:
        # curl_cffi honours these (trust_env); the browser should go out the
        # same way, or its clearance is minted for a different IP.
        for name in ("HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy", "HTTP_PROXY", "http_proxy"):
            if os.environ.get(name, "").strip():
                proxy = os.environ[name].strip()
                break
    if not proxy:
        return None
    if "://" not in proxy:
        proxy = f"http://{proxy}"
    parts = urlsplit(proxy)
    scheme = "socks5" if parts.scheme.startswith("socks5") else parts.scheme
    server = f"{scheme}://{parts.hostname}" + (f":{parts.port}" if parts.port else "")
    settings = {"server": server}
    if parts.username:
        settings["username"] = unquote(parts.username)
        settings["password"] = unquote(parts.password or "")
    return settings


def _page_is_challenge(status: int, text: str, headers: dict[str, str]) -> bool:
    # Imported here: core.cloudflare imports this module.
    from .cloudflare import is_cloudflare_challenge

    return is_cloudflare_challenge(status, text, headers)


async def _checkbox_point(page: Any, frame: Any) -> tuple[float, float] | None:
    """Where on the page an unticked checkbox in ``frame`` is, if it shows one.

    The widget keeps its checkbox in a closed shadow root, out of reach of
    selectors; the accessibility tree reaches it, and names it by role in any
    language.
    """
    owner = await (await frame.frame_element()).bounding_box()
    if not owner:
        return None
    # The widget is cross-site, so an out-of-process frame with a session of its own.
    session = await page.context.new_cdp_session(frame)
    try:
        tree = await session.send("Accessibility.getFullAXTree")
        node = next((
            n for n in tree.get("nodes", [])
            if (n.get("role") or {}).get("value") == "checkbox"
            and not n.get("ignored")
            and n.get("backendDOMNodeId")
            and not any(
                p.get("name") == "checked" and (p.get("value") or {}).get("value") in (True, "true", "mixed")
                for p in n.get("properties", [])
            )
        ), None)
        if node is None:
            return None
        model = await session.send("DOM.getBoxModel", {"backendNodeId": node["backendDOMNodeId"]})
    finally:
        with contextlib.suppress(Exception):
            await session.detach()
    quad = model["model"]["border"]
    left, top, bottom = quad[0], quad[1], quad[5]
    side = bottom - top
    if side <= 0:
        return None
    # The box is square at the left end of its label: aim for it, a little off centre.
    return (
        owner["x"] + left + side / 2 + random.uniform(-side, side) / 5,
        owner["y"] + top + side / 2 + random.uniform(-side, side) / 5,
    )


async def _press_checkbox(page: Any) -> bool:
    """Tick a challenge widget's checkbox, moving the mouse there first.

    Returns:
        Whether one was found and clicked.
    """
    for frame in page.frames:
        if not _is_challenge_host(urlsplit(frame.url).hostname or ""):
            continue
        try:
            point = await _checkbox_point(page, frame)
            if point is None:
                continue
            x, y = point
            # A glance at the widget, then a hand coming in from below left.
            await asyncio.sleep(random.uniform(0.4, 1.0))
            await page.mouse.move(max(0.0, x - random.uniform(80, 240)), y + random.uniform(60, 180))
            await page.mouse.move(x, y, steps=random.randint(18, 30))
            await asyncio.sleep(random.uniform(0.15, 0.4))
            await page.mouse.click(x, y, delay=random.uniform(60, 150))
        except Exception as exc:  # the frame may have gone meanwhile
            logger.debug("Could not tick the challenge checkbox: %s", exc)
            continue
        logger.info("Ticked the Cloudflare challenge checkbox")
        return True
    return False


class _Document:
    """The latest main-frame document response of a page."""

    def __init__(self) -> None:
        self.status = 0
        self.url = ""
        self.headers: dict[str, str] = {}

    def update(self, status: int, url: str, headers: dict[str, str]) -> None:
        self.status, self.url, self.headers = status, url, {k.lower(): v for k, v in headers.items()}


class BrowserSolver:
    """One headless browser, launched on first use and closed once idle.

    Lives as long as the plugin, so consecutive runs reuse the process. Every
    request gets a fresh context: credentials of one site never share a cookie
    jar with another's. Requests are serialised; a challenge is a matter of
    seconds and running them side by side only invites rate limiting.
    """

    def __init__(self, idle_close: float = IDLE_CLOSE_SECONDS) -> None:
        self._idle_close = idle_close
        self._lock = asyncio.Lock()
        self._playwright: Any = None
        self._browser: Any = None
        self._launched_with: tuple[bool, str] | None = None
        self._label = ""
        self._user_agent = ""
        self._idle_task: asyncio.Task | None = None

    async def aclose(self) -> None:
        """Close the browser and the Playwright driver, if running."""
        if self._idle_task is not None and self._idle_task is not asyncio.current_task():
            self._idle_task.cancel()
        self._idle_task = None
        browser, playwright = self._browser, self._playwright
        self._browser = self._playwright = None
        self._launched_with = None
        if browser is not None:
            with contextlib.suppress(Exception):
                await browser.close()
        if playwright is not None:
            with contextlib.suppress(Exception):
                await playwright.stop()

    async def check(self, options: BrowserOptions) -> str:
        """Launch the browser if needed and name it; raises BrowserUnavailable."""
        async with self._lock:
            await self._ensure(options)
            self._arm_idle_close()
            return self._label

    async def request(
        self,
        request: BrowserRequest,
        options: BrowserOptions,
        clearance: Iterable[dict[str, Any]] = (),
    ) -> BrowserOutcome:
        """Issue ``request`` from a fresh browser context.

        Args:
            clearance: Cloudflare cookies from an earlier request of the run.

        Raises:
            BrowserUnavailable: Playwright or a browser is missing.
            Exception: Anything else the browser raised; the caller reports it.
        """
        async with self._lock:
            await self._ensure(options)
            started = time.monotonic()
            try:
                context = await self._browser.new_context(
                    user_agent=self._user_agent or None,
                    # The window's own size, not an emulated viewport: see _HEADLESS_ARGS.
                    no_viewport=True,
                    proxy=_proxy_settings(request.proxy),
                    ignore_https_errors=not request.verify,
                )
                try:
                    clearance = list(clearance)
                    if clearance:
                        await context.add_cookies(clearance)
                    if request.navigate:
                        response, solved = await self._navigate(context, request, options.timeout)
                    else:
                        response, solved = await self._fetch(context, request, options.timeout)
                    held = await context.cookies()
                finally:
                    with contextlib.suppress(Exception):
                        await context.close()
            finally:
                self._arm_idle_close()
            return BrowserOutcome(
                response=response,
                clearance=[c for c in held if c.get("name") in _CLOUDFLARE_COOKIES],
                browser=self._label,
                elapsed=time.monotonic() - started,
                solved=solved,
            )

    async def turnstile_token(
        self,
        url: str,
        sitekey: str,
        options: BrowserOptions,
        proxy: str | None = None,
        verify: bool = True,
    ) -> tuple[str, str]:
        """Have a site's own Turnstile widget issue a token.

        Unlike a managed challenge, a widget a site embeds (New-API puts one in
        front of its check-in) hands the page a token, which the site verifies
        with Cloudflare when it arrives with the guarded request. Turnstile
        checks no more of the page than its hostname, so ``url`` is answered
        here with a page holding only the widget and the site is never
        contacted. A checkbox the widget asks for is ticked.

        Args:
            url: A page of the site the widget belongs to.
            sitekey: The widget's public site key.
            proxy: The proxy the guarded request goes out through.
            verify: Whether TLS certificates are checked. The widget's script
                comes over the same connection the guarded request uses, which
                an intercepting proxy may re-sign.

        Returns:
            Tuple of the token, empty when none came within ``options.timeout``,
            and the browser that went out, e.g. "Chrome 153".

        Raises:
            BrowserUnavailable: Playwright or a browser is missing.
            Exception: Anything else the browser raised; the caller reports it.
        """
        async with self._lock:
            await self._ensure(options)
            try:
                context = await self._browser.new_context(
                    user_agent=self._user_agent or None,
                    no_viewport=True,
                    proxy=_proxy_settings(proxy),
                    ignore_https_errors=not verify,
                )
                try:
                    page = await context.new_page()
                    body = _TURNSTILE_PAGE.replace("{sitekey}", html.escape(sitekey, quote=True))
                    await page.route(
                        lambda requested: _same_page(requested, url),
                        lambda route: route.fulfill(status=200, content_type="text/html; charset=utf-8", body=body),
                    )
                    deadline = time.monotonic() + options.timeout
                    await page.goto(url, wait_until="commit", timeout=options.timeout * 1000)
                    token, next_look = "", 0.0
                    # A page that stopped answering must not hold the browser,
                    # and every request queued behind it, past the deadline.
                    with contextlib.suppress(asyncio.TimeoutError):
                        while not token and time.monotonic() < deadline:
                            await asyncio.sleep(_POLL_SECONDS)
                            token = str(await asyncio.wait_for(
                                page.evaluate(_TURNSTILE_TOKEN_SCRIPT), max(0.1, deadline - time.monotonic())
                            ) or "")
                            if not token and time.monotonic() >= next_look:
                                pressed = await asyncio.wait_for(
                                    _press_checkbox(page), max(0.1, deadline - time.monotonic())
                                )
                                next_look = time.monotonic() + (_PRESS_RETRY_SECONDS if pressed else _LOOK_SECONDS)
                finally:
                    with contextlib.suppress(Exception):
                        await context.close()
            finally:
                self._arm_idle_close()
            return token, self._label

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------
    async def _ensure(self, options: BrowserOptions) -> None:
        wanted = (options.headless, options.channel)
        if self._browser is not None and self._launched_with == wanted and self._browser.is_connected():
            return
        await self.aclose()
        entry = load_playwright()
        if entry is None:
            if _import_error:
                raise BrowserUnavailable(f"Playwright 无法加载：{_import_error}（重启 AstrBot 后再试）")
            raise BrowserUnavailable(f"未安装 Playwright（{INSTALL_HINT}）")
        try:
            self._playwright = await entry().start()
        except NotImplementedError as exc:
            # A selector event loop cannot start the driver subprocess.
            raise BrowserUnavailable("当前事件循环不支持子进程，无法启动 Playwright") from exc
        except Exception as exc:
            raise BrowserUnavailable(f"Playwright 启动失败：{exc}") from exc

        channels = AUTO_ORDER if options.channel == CHANNEL_AUTO else (options.channel,)
        failures = []
        for channel in channels:
            try:
                browser = await self._playwright.chromium.launch(
                    channel=channel,
                    headless=options.headless,
                    args=[*_LAUNCH_ARGS, *(_HEADLESS_ARGS if options.headless else ())],
                    ignore_default_args=list(_IGNORED_DEFAULT_ARGS),
                )
            except Exception as exc:
                failures.append(f"{CHANNEL_NAMES[channel]}：{str(exc).splitlines()[0][:160]}")
                continue
            self._browser = browser
            self._launched_with = wanted
            self._label = f"{CHANNEL_NAMES[channel]} {browser.version.split('.')[0]}"
            self._user_agent = await self._headful_user_agent(browser)
            logger.info("Launched %s for Cloudflare challenges (headless=%s)", self._label, options.headless)
            return
        await self.aclose()
        raise BrowserUnavailable(f"无法启动浏览器（{'；'.join(failures)}）。{INSTALL_HINT}")

    @staticmethod
    async def _headful_user_agent(browser: Any) -> str:
        """The browser's User-Agent without the ``HeadlessChrome`` token.

        Headless Chrome announces itself only there; its client hints already
        name the real brand. Playwright derives matching hints from an
        overridden User-Agent, so replacing the token is the whole fix.
        """
        context = await browser.new_context()
        try:
            page = await context.new_page()
            user_agent = await page.evaluate("navigator.userAgent")
        finally:
            await context.close()
        return str(user_agent).replace("HeadlessChrome/", "Chrome/")

    def _arm_idle_close(self) -> None:
        if self._idle_task is not None:
            self._idle_task.cancel()
        if self._browser is None or self._idle_close <= 0:
            self._idle_task = None
            return
        self._idle_task = asyncio.get_running_loop().create_task(self._close_when_idle())

    async def _close_when_idle(self) -> None:
        await asyncio.sleep(self._idle_close)
        async with self._lock:
            if self._idle_task is asyncio.current_task():
                self._idle_task = None
                logger.info("Closing the idle Cloudflare browser")
                await self.aclose()

    # ------------------------------------------------------------------
    # Requests
    # ------------------------------------------------------------------
    @staticmethod
    def _watch(page: Any) -> _Document:
        """Follow the page's main-frame documents as they arrive."""
        document = _Document()

        def on_response(response: Any) -> None:
            try:
                if response.request.resource_type == "document" and response.frame == page.main_frame:
                    document.update(response.status, response.url, response.headers)
            except Exception:  # a detached frame must not break the watch
                pass

        page.on("response", on_response)
        return document

    @staticmethod
    async def _settle(
        page: Any, document: _Document, deadline: float, done: asyncio.Event | None = None
    ) -> bool:
        """Wait until the page is off any challenge, ``done`` is set, or time runs out.

        Only the document's status counts, never its markup alone: Cloudflare
        injects its challenge-platform script into ordinary pages too. While
        on a challenge, a checkbox it asks to have ticked is ticked.

        Returns:
            Whether a challenge page was seen along the way.
        """
        seen_challenge = False
        next_look = 0.0
        while True:
            if done is not None and done.is_set():
                return seen_challenge
            if document.status:
                text = ""
                with contextlib.suppress(Exception):
                    text = await page.content()
                if not _page_is_challenge(document.status, text, document.headers):
                    with contextlib.suppress(Exception):
                        await page.wait_for_load_state(
                            "domcontentloaded", timeout=max(1.0, deadline - time.monotonic()) * 1000
                        )
                    if done is not None:
                        # A page may still move on by script; give it a moment.
                        grace = min(_GRACE_SECONDS, max(0.0, deadline - time.monotonic()))
                        with contextlib.suppress(asyncio.TimeoutError):
                            await asyncio.wait_for(done.wait(), timeout=grace)
                    return seen_challenge
                seen_challenge = True
                if time.monotonic() >= next_look:
                    pressed = await _press_checkbox(page)
                    next_look = time.monotonic() + (_PRESS_RETRY_SECONDS if pressed else _LOOK_SECONDS)
            if time.monotonic() >= deadline:
                return seen_challenge
            await asyncio.sleep(_POLL_SECONDS)

    @staticmethod
    async def _goto(page: Any, url: str, deadline: float, referer: str = "") -> str:
        """Start a navigation; returns its error, if it failed before any response."""
        timeout = max(1.0, deadline - time.monotonic()) * 1000
        try:
            await page.goto(url, referer=referer or None, wait_until="commit", timeout=timeout)
        except Exception as exc:
            # A navigation the challenge replaced aborts the goto as well; what
            # the page ends up showing is judged afterwards.
            logger.debug("Browser navigation to %s ended early: %s", url, exc)
            return str(exc).splitlines()[0]
        return ""

    async def _navigate(self, context: Any, request: BrowserRequest, timeout: float) -> tuple[BrowserResponse, bool]:
        """Open ``request.url`` as a user would, stopping where it leaves the domain."""
        deadline = time.monotonic() + timeout
        parts = urlsplit(request.url)
        zone = _zone(parts.hostname or "")
        cookies = _parse_cookie_header(_header(request.headers, "cookie"))
        specs = _cookie_specs(
            request.url,
            cookies,
            zone_wide=True,
            provider_cookies=request.provider_cookies,
        )
        if specs:
            await context.add_cookies(specs)

        page = await context.new_page()
        document = self._watch(page)
        captured: list[str] = []
        left_domain = asyncio.Event()
        cdp = await context.new_cdp_session(page)
        frame_tree = await cdp.send("Page.getFrameTree")
        main_frame = frame_tree["frameTree"]["frame"]["id"]

        async def on_paused(event: dict[str, Any]) -> None:
            request_id = event["requestId"]
            target = str(event.get("request", {}).get("url") or "")
            host = (urlsplit(target).hostname or "").lower()
            try:
                if (
                    event.get("frameId") == main_frame
                    and host
                    and not _in_zone(host, zone)
                    and not _is_challenge_host(host)
                ):
                    # The way back to the station. Answer it here: the real page
                    # would spend the authorization code before we could.
                    captured.append(target)
                    left_domain.set()
                    await cdp.send("Fetch.fulfillRequest", {
                        "requestId": request_id,
                        "responseCode": 200,
                        "responseHeaders": [{"name": "Content-Type", "value": "text/html"}],
                        "body": "",
                    })
                else:
                    await cdp.send("Fetch.continueRequest", {"requestId": request_id})
            except Exception as exc:  # the page may have gone away meanwhile
                logger.debug("Could not answer a paused browser request: %s", exc)

        cdp.on("Fetch.requestPaused", lambda event: asyncio.ensure_future(on_paused(event)))
        # Paused at the request stage, a redirect's target is seen too, which
        # Playwright's own routing never does: page.route() skips redirects.
        await cdp.send("Fetch.enable", {"patterns": [{"urlPattern": "*", "resourceType": "Document"}]})

        error = await self._goto(page, request.url, deadline, _header(request.headers, "referer"))
        if error and not document.status and not captured:
            raise RuntimeError(f"浏览器打开 {parts.hostname} 失败：{error}")
        solved = await self._settle(page, document, deadline, done=left_domain)
        # The domain's own host too: the SSO relay rotates _t there, on linux.do.
        jar = normalize_provider_cookies(
            [
                cookie
                for cookie in await context.cookies()
                if _in_zone(str(cookie.get("domain") or "").lstrip("."), zone)
            ]
        )
        held = _site_cookies(jar, dict(cookies))

        if captured:
            return BrowserResponse(
                302, "", {"location": captured[0]}, held, request.url, jar
            ), solved
        text = ""
        with contextlib.suppress(Exception):
            text = await page.content()
        final_url = page.url
        if document.status == 200 and final_url and not _same_page(final_url, request.url):
            # Redirected within the provider — to its login page, say. Report
            # the hop a non-browser client would have seen.
            return BrowserResponse(
                302, text, {"location": final_url}, held, final_url, jar
            ), solved
        return BrowserResponse(
            document.status, text, document.headers, held, final_url, jar
        ), solved

    async def _fetch(self, context: Any, request: BrowserRequest, timeout: float) -> tuple[BrowserResponse, bool]:
        """Solve the challenge on the endpoint, then make the call with fetch()."""
        deadline = time.monotonic() + timeout
        method = request.method.upper()
        origin = _origin(request.url)
        # Solved on the endpoint whatever the method: a firewall rule may cover
        # that path alone — vsllm.cc challenges /api/user/checkin, GET and POST,
        # and not even its root — while the clearance it earns holds for the
        # whole zone. The solving navigation is a plain GET without credentials,
        # so it cannot act for the user: with their cookies attached a GET
        # endpoint would run twice, and a POST-only one just refuses the GET.
        solve_url = request.url

        page = await context.new_page()
        document = self._watch(page)
        error = await self._goto(page, solve_url, deadline)
        if error and not document.status:
            raise RuntimeError(f"浏览器打开 {urlsplit(solve_url).hostname} 失败：{error}")
        solved = await self._settle(page, document, deadline)
        text = ""
        with contextlib.suppress(Exception):
            text = await page.content()
        if _page_is_challenge(document.status, text, document.headers):
            held = {c["name"]: c["value"] for c in await context.cookies(request.url)}
            return BrowserResponse(document.status, text, document.headers, held, page.url), solved
        if _origin(page.url) != origin:
            # fetch() only carries cookies to its own origin.
            await self._goto(page, f"{origin}/", deadline)

        pairs = _parse_cookie_header(_header(request.headers, "cookie"))
        if pairs:
            await context.add_cookies(_cookie_specs(request.url, pairs, zone_wide=False))
        headers = {
            name: value for name, value in request.headers.items()
            if name.lower() not in _FORBIDDEN_HEADERS and not name.lower().startswith(_FORBIDDEN_PREFIXES)
        }
        referer = _header(request.headers, "referer")
        if referer and _origin(urljoin(request.url, referer)) != origin:
            referer = ""
        result = await asyncio.wait_for(
            page.evaluate(_FETCH_SCRIPT, {
                "url": request.url,
                "method": method,
                "headers": headers,
                "body": request.body,
                "referrer": referer,
            }),
            timeout=max(1.0, deadline - time.monotonic()),
        )
        injected = dict(pairs)
        # Everything the jar holds that the request did not bring, which is
        # what a Set-Cookie would have told a non-browser client — including
        # cookies set while solving, which belong to the same session.
        set_cookies = {
            c["name"]: c["value"] for c in await context.cookies(request.url)
            if injected.get(c["name"]) != c["value"]
        }
        return BrowserResponse(
            int(result.get("status") or 0),
            str(result.get("text") or ""),
            result.get("headers") or {},
            set_cookies,
            str(result.get("url") or request.url),
        ), solved


def request_body(json_body: Any) -> str | None:
    """Serialise a JSON body the way curl_cffi's ``json=`` would."""
    if json_body is None:
        return None
    return json.dumps(json_body, separators=(",", ":"), ensure_ascii=False)
