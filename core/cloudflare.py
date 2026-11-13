"""Recognising a Cloudflare challenge, and getting a request past it.

A challenged request is re-issued directly from a headless browser that
solves the challenge (see :mod:`core.browser`), when Playwright is installed
and the option is on. The same browser gets the token a site's own Turnstile
widget guards a request with.
"""

from __future__ import annotations

import logging
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

from .browser import (
    CHANNEL_AUTO,
    BrowserOptions,
    BrowserRequest,
    BrowserSolver,
    BrowserUnavailable,
    normalize_channel,
    normalize_timeout,
)
from .browser import DEFAULT_TIMEOUT_SECONDS as DEFAULT_BROWSER_TIMEOUT

logger = logging.getLogger("astrbot")

# Markers of a Cloudflare interstitial. The visible title is localised, so match
# the machine-readable pieces too — the challenge script path and the form the
# challenge posts back are stable across languages.
_CLOUDFLARE_MARKERS: tuple[str, ...] = (
    "just a moment",
    "enable javascript and cookies to continue",
    "/cdn-cgi/challenge-platform/",
    "cf-browser-verification",
    "cf_chl_opt",
    "__cf_chl_",
    "checking if the site connection is secure",
    "attention required! | cloudflare",
)

# Appends a step to the caller's request trace:
# ``record(step, method, url, *, status=None, success=False, message="")``.
Recorder = Callable[..., None]


def is_cloudflare_challenge(status: int, body: str, headers: Any = None) -> bool:
    """Recognise Cloudflare's bot-management interstitial.

    Worth telling apart from any other refusal: nothing about the user's cookie
    is wrong, so every remedy for an expired session is the wrong advice. The
    ``cf-mitigated`` header states it outright when present; otherwise the body
    of the challenge page is the evidence.
    """
    if status not in (403, 503, 429):
        return False
    try:
        mitigated = str((headers or {}).get("cf-mitigated") or "").strip().lower()
    except Exception:
        mitigated = ""
    if mitigated == "challenge":
        return True
    text = str(body or "").lower()
    return any(marker in text for marker in _CLOUDFLARE_MARKERS)


def is_response_challenge(response: Any) -> bool:
    """Apply :func:`is_cloudflare_challenge` to a curl_cffi-style response."""
    return is_cloudflare_challenge(
        getattr(response, "status_code", 0),
        getattr(response, "text", "") or "",
        getattr(response, "headers", None),
    )


def _as_bool(value: Any, default: bool) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in {"1", "true", "yes", "on"}:
            return True
        if lowered in {"0", "false", "no", "off"}:
            return False
    return default


@dataclass(frozen=True)
class CloudflareOptions:
    """User settings governing challenge handling."""

    # Re-issue a challenged request directly from a headless browser.
    # Only takes effect with a browser handed to the context.
    browser_fallback: bool = True
    browser_headless: bool = True
    browser_channel: str = CHANNEL_AUTO
    browser_timeout: float = DEFAULT_BROWSER_TIMEOUT

    @classmethod
    def from_settings(cls, settings: Mapping[str, Any] | None) -> CloudflareOptions:
        """Read the options out of the plugin settings."""
        settings = settings or {}
        return cls(
            browser_fallback=_as_bool(settings.get("cf_browser_fallback"), True),
            browser_headless=_as_bool(settings.get("cf_browser_headless"), True),
            browser_channel=normalize_channel(settings.get("cf_browser_channel")),
            browser_timeout=normalize_timeout(
                settings.get("cf_browser_timeout_seconds", DEFAULT_BROWSER_TIMEOUT)
            ),
        )

    @property
    def browser(self) -> BrowserOptions:
        """How the browser is to be launched."""
        return BrowserOptions(
            headless=self.browser_headless,
            channel=self.browser_channel,
            timeout=self.browser_timeout,
        )


def normalize_cloudflare_settings(settings: dict[str, Any]) -> dict[str, Any]:
    """Coerce the Cloudflare keys of a settings dict in place, and return it."""
    options = CloudflareOptions.from_settings(settings)
    settings.pop("cf_fingerprint_fallback", None)
    settings["cf_browser_fallback"] = options.browser_fallback
    settings["cf_browser_headless"] = options.browser_headless
    settings["cf_browser_channel"] = options.browser_channel
    timeout = options.browser_timeout
    settings["cf_browser_timeout_seconds"] = (
        int(timeout) if timeout.is_integer() else timeout
    )
    return settings


def _host(url: str) -> str:
    return (urlsplit(url).hostname or "").lower()


@dataclass
class Resolution:
    """What :meth:`CloudflareContext.resolve` settled on."""

    response: Any
    # When the returned response is still a challenge: what was tried against
    # it, phrased to be appended to a failure message as it stands.
    detail: str = ""


class CloudflareContext:
    """Challenge handling shared by every request of one run.

    Browser clearance is carried to the next request of the run. Each
    challenged request gets one browser attempt, even after an earlier failure.
    """

    def __init__(
        self,
        options: CloudflareOptions | None = None,
        *,
        browser: BrowserSolver | None = None,
    ) -> None:
        """Initialize the context.

        Args:
            options: Settings; the defaults enable the headless browser.
            browser: The plugin's headless browser. Without one a challenge
                is only reported.
        """
        self.options = options or CloudflareOptions()
        self._browser = browser
        # Cloudflare cookies the browser holds, by the proxy it went out
        # through: a clearance is bound to the IP address that earned it.
        self._clearance: dict[str, list[dict[str, Any]]] = {}
        # Why the browser cannot run, once that is known; not retried this run.
        self._browser_unavailable = ""

    async def resolve(
        self,
        *,
        response: Any,
        record: Recorder | None = None,
        browser_request: BrowserRequest | None = None,
    ) -> Resolution:
        """Return ``response``, or a replacement that got past its challenge.

        The browser retry is appended to the trace through ``record``; the response
        that comes back is left for the caller to record, since the caller
        knows what the request was for.

        Args:
            response: The original curl_cffi response.
            record: Optional callback for the browser's request trace.
            browser_request: The same request, described for the browser.

        Returns:
            The browser response when it passes the challenge, otherwise the
            original response with the reason the browser could not pass.
        """
        if not is_response_challenge(response):
            return Resolution(response)
        if not self.options.browser_fallback:
            return Resolution(response, "无头浏览器验证已在全局设置中关闭")
        if self._browser is None:
            return Resolution(response, "无头浏览器不可用：未配置浏览器")
        if browser_request is None:
            return Resolution(response, "无头浏览器无法重试：缺少原始请求信息")

        passed, summary = await self._browse(
            _host(browser_request.url), browser_request, record
        )
        if passed is not None:
            return Resolution(passed)
        return Resolution(response, f"已自动尝试：{summary}")

    async def _browse(
        self,
        host: str,
        request: BrowserRequest,
        record: Recorder | None,
    ) -> tuple[Any | None, str]:
        """Re-issue the request from the headless browser.

        Returns:
            Tuple of the response that got through (None if it did not) and a
            summary of what happened.
        """
        step = "Cloudflare 无头浏览器"
        if self._browser_unavailable:
            return None, self._browser_unavailable
        proxy_key = request.proxy or ""
        try:
            outcome = await self._browser.request(
                request, self.options.browser, self._clearance.get(proxy_key, ())
            )
        except BrowserUnavailable as exc:
            self._browser_unavailable = f"无头浏览器不可用：{exc}"
            _record(
                record,
                step,
                request.method,
                request.url,
                message=self._browser_unavailable,
            )
            logger.warning("Cloudflare browser unavailable: %s", exc)
            return None, self._browser_unavailable
        except Exception as exc:
            message = f"无头浏览器请求异常：{exc}"
            _record(
                record,
                step,
                request.method,
                request.url,
                message=message,
                error=str(exc),
            )
            logger.warning(
                "Cloudflare browser failed on %s: %s", host, exc, exc_info=True
            )
            return None, message

        if outcome.clearance:
            self._clearance[proxy_key] = outcome.clearance
        candidate = outcome.response
        status = getattr(candidate, "status_code", "?")
        took = f"用时 {outcome.elapsed:.1f} 秒"
        if not is_response_challenge(candidate):
            verdict = "通过人机验证" if outcome.solved else "未遇到人机验证"
            _record(
                record,
                step,
                request.method,
                request.url,
                status=status,
                success=True,
                message=f"{outcome.browser} {verdict} (HTTP {status})，{took}，本轮后续请求沿用其 Cookie",
            )
            logger.info(
                "Cloudflare let %s through in %s (%s)", host, outcome.browser, took
            )
            return candidate, ""

        message = (
            f"{outcome.browser} 在 {self.options.browser_timeout:g} 秒内未能通过人机验证 "
            f"(HTTP {status})"
        )
        _record(
            record, step, request.method, request.url, status=status, message=message
        )
        return None, message

    async def turnstile_token(
        self,
        page_url: str,
        sitekey: str,
        proxy: str | None = None,
        record: Recorder | None = None,
    ) -> tuple[str, str]:
        """Have the headless browser get a token from a site's Turnstile widget.

        Follows the same setting as challenge handling: it is the same browser
        doing Cloudflare's verification.

        Args:
            page_url: A page of the site the widget belongs to.
            sitekey: The widget's public site key.
            proxy: The proxy the guarded request goes out through.
            record: Optional callback for the browser's trace.

        Returns:
            Tuple of ``(token, error)``; the error says why there is no token.
        """
        step = "Turnstile 无头浏览器"
        if not self.options.browser_fallback:
            return "", "无头浏览器验证已在全局设置中关闭"
        if self._browser is None:
            return "", "无头浏览器不可用：未配置浏览器"
        if self._browser_unavailable:
            return "", self._browser_unavailable
        started = time.monotonic()
        try:
            token, browser = await self._browser.turnstile_token(
                page_url, sitekey, self.options.browser, proxy
            )
        except BrowserUnavailable as exc:
            self._browser_unavailable = f"无头浏览器不可用：{exc}"
            _record(record, step, "GET", page_url, message=self._browser_unavailable)
            logger.warning("Cloudflare browser unavailable: %s", exc)
            return "", self._browser_unavailable
        except Exception as exc:
            message = f"无头浏览器请求异常：{exc}"
            _record(record, step, "GET", page_url, message=message, error=str(exc))
            logger.warning(
                "Turnstile browser failed on %s: %s",
                _host(page_url),
                exc,
                exc_info=True,
            )
            return "", message
        if not token:
            message = f"{browser} 在 {self.options.browser_timeout:g} 秒内未取得 Turnstile token"
            _record(record, step, "GET", page_url, message=message)
            return "", message
        took = time.monotonic() - started
        # The page is answered by the browser itself, so there is no status.
        _record(
            record,
            step,
            "GET",
            page_url,
            success=True,
            message=f"{browser} 取得 Turnstile token，用时 {took:.1f} 秒",
        )
        logger.info("Turnstile issued a token for %s in %s", _host(page_url), browser)
        return token, ""


def _record(
    record: Recorder | None, step: str, method: str, url: str, **fields: Any
) -> None:
    if record is None:
        return
    try:
        record(step, method, url, **fields)
    except Exception:  # tracing must never break the request
        logger.debug("Could not record the Cloudflare step %s", step, exc_info=True)
