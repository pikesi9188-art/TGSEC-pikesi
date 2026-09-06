#!/usr/bin/env python3
"""tools/ops 共享 HTTP 薄封装。

目的：替代散落在 50+ probe 脚本里各自实现的 `_req/_get/_sess`（超时不一、
异常一律吞成 None、TLS 关不关各写各的）。新 probe 一律 `from probe_http import ...`。

用法：
    from probe_http import get, post, session, HttpResult
    r = get("https://target/actuator", timeout=8)
    if r.ok and r.status == 200:
        ...
    # 复用连接：
    s = session()
    r = get("...", sess=s)

授权闸门请在入口先调用 scope_lib.require_in_scope(host)。
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

try:
    import requests
    from requests.adapters import HTTPAdapter

    try:
        from urllib3.util.retry import Retry
    except Exception:  # pragma: no cover
        Retry = None  # type: ignore
    import urllib3

    urllib3.disable_warnings()
    _HAVE_REQUESTS = True
except Exception:  # pragma: no cover
    requests = None  # type: ignore
    _HAVE_REQUESTS = False

DEFAULT_UA = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0 Safari/537.36 大爱仙尊-Probe/1.0"
)
DEFAULT_TIMEOUT = 12.0


@dataclass
class HttpResult:
    """统一结果：区分成功 / 网络错误，避免各脚本把超时和 404 混为 None。"""

    ok: bool
    status: int = 0
    text: str = ""
    headers: dict[str, str] = None  # type: ignore
    url: str = ""
    error: str = ""
    elapsed: float = 0.0
    raw: Any = None

    def __post_init__(self) -> None:
        if self.headers is None:
            self.headers = {}

    def json(self) -> Any:
        if self.raw is not None:
            try:
                return self.raw.json()
            except Exception:
                return None
        return None


def _require_requests() -> None:
    if not _HAVE_REQUESTS:
        raise RuntimeError("probe_http 需要 requests：pip install -r requirements.txt")


def session(
    *,
    ua: str = DEFAULT_UA,
    retries: int = 1,
    pool: int = 20,
    headers: dict[str, str] | None = None,
) -> requests.Session:
    _require_requests()
    s = requests.Session()
    s.verify = False
    s.headers.update({"User-Agent": ua})
    if headers:
        s.headers.update(headers)
    if Retry is not None and retries > 0:
        retry = Retry(
            total=retries,
            backoff_factor=0.3,
            status_forcelist=(429, 502, 503, 504),
            allowed_methods=frozenset(["GET", "HEAD", "OPTIONS", "POST"]),
        )
        adapter = HTTPAdapter(pool_connections=pool, pool_maxsize=pool, max_retries=retry)
        s.mount("http://", adapter)
        s.mount("https://", adapter)
    return s


def request(
    method: str,
    url: str,
    *,
    timeout: float = DEFAULT_TIMEOUT,
    verify: bool = False,
    sess: requests.Session | None = None,
    allow_redirects: bool = True,
    **kwargs: Any,
) -> HttpResult:
    """统一请求。异常不抛，落到 HttpResult.error（带类型），调用方可区分超时/DNS/TLS。"""
    _require_requests()
    import time as _t

    caller = sess or session()
    t0 = _t.monotonic()
    try:
        resp = caller.request(
            method.upper(),
            url,
            timeout=timeout,
            verify=verify,
            allow_redirects=allow_redirects,
            **kwargs,
        )
        return HttpResult(
            ok=True,
            status=resp.status_code,
            text=resp.text or "",
            headers=dict(resp.headers),
            url=resp.url,
            elapsed=round(_t.monotonic() - t0, 3),
            raw=resp,
        )
    except requests.exceptions.Timeout:
        return HttpResult(ok=False, error="timeout", url=url, elapsed=round(_t.monotonic() - t0, 3))
    except requests.exceptions.SSLError as e:
        return HttpResult(ok=False, error=f"tls:{e}", url=url)
    except requests.exceptions.ConnectionError as e:
        return HttpResult(ok=False, error=f"conn:{e}", url=url)
    except requests.RequestException as e:
        return HttpResult(ok=False, error=f"req:{e}", url=url)


def get(url: str, **kwargs: Any) -> HttpResult:
    return request("GET", url, **kwargs)


def post(url: str, **kwargs: Any) -> HttpResult:
    return request("POST", url, **kwargs)


def head(url: str, **kwargs: Any) -> HttpResult:
    return request("HEAD", url, **kwargs)


def options(url: str, **kwargs: Any) -> HttpResult:
    return request("OPTIONS", url, **kwargs)
