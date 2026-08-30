"""TSecBench 答题 API 客户端。

对接 CHALLENGES_API.md 定义的 5 个接口：
  list_challenges / start_challenge / get_hint / submit_flag / close_challenge

认证：HTTP header `BENCHMARK_TOKEN`。
所有业务错误抛出 BenchmarkError 子类，code 字段与平台错误码一致。
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field

import requests


class BenchmarkError(Exception):
    """平台业务错误。code 与平台错误码一致（task_not_found / invalid_state / ...）。"""

    def __init__(self, code: str, message: str, status: int = 0, detail: dict | None = None):
        super().__init__(f"[{code}] {message}")
        self.code = code
        self.message = message
        self.status = status
        self.detail = detail or {}


class TaskNotFound(BenchmarkError):
    pass


class ChallengeNotFound(BenchmarkError):
    pass


class InvalidState(BenchmarkError):
    pass


class DuplicateSubmit(BenchmarkError):
    pass


class ResourceUnavailable(BenchmarkError):
    pass


_ERROR_MAP = {
    "task_not_found": TaskNotFound,
    "challenge_not_found": ChallengeNotFound,
    "invalid_state": InvalidState,
    "duplicate": DuplicateSubmit,
    "resource_unavailable": ResourceUnavailable,
}


@dataclass
class Challenge:
    unique_code: str
    description: str = ""
    difficulty: str = "medium"
    level: int = 1
    total_score: int = 0
    flag_count: int = 1
    correct_flag_count: int = 0
    is_completed: bool = False
    container_status: str = "stopped"
    container_addr: list[str] = field(default_factory=list)


@dataclass
class SubmitResult:
    correct: bool
    awarded: int = 0
    cumulative_score: int = 0
    correct_flag_count: int = 0
    total_flag_count: int = 0
    matched_flag_index: int | None = None


class TSecBenchClient:
    """TSecBench 评测 API 同步客户端（带速率限制与统一异常）。"""

    def __init__(self, base_url: str, token: str, *, min_interval: float = 0.4, timeout: float = 30.0):
        self.base_url = base_url.rstrip("/")
        self.token = token
        self.timeout = timeout
        self._min_interval = min_interval
        self._lock = threading.Lock()
        self._last_req = 0.0
        self._http = self._make_session()
        self._http_direct = self._make_session(direct=True)

    @staticmethod
    def _make_session(direct: bool = False) -> requests.Session:
        s = requests.Session()
        if direct:
            s.trust_env = False  # 跳过系统代理/环境变量，直连
        from requests.adapters import HTTPAdapter
        adapter = HTTPAdapter(max_retries=2)
        s.mount("https://", adapter)
        s.mount("http://", adapter)
        return s

    def close(self):
        self._http.close()
        self._http_direct.close()

    def __enter__(self) -> "TSecBenchClient":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def _request(self, method: str, path: str, **kwargs):
        with self._lock:
            delta = time.monotonic() - self._last_req
            if delta < self._min_interval:
                time.sleep(self._min_interval - delta)
            self._last_req = time.monotonic()
        url = f"{self.base_url}/openapi/v1/challenges{path}"
        headers = {"BENCHMARK_TOKEN": self.token}
        last_exc: Exception | None = None
        # 先走默认会话（尊重系统代理），网络层失败则直连重试——代理挂时自动降级
        for sess in (self._http, self._http_direct):
            try:
                resp = sess.request(method, url, timeout=self.timeout, headers=headers, **kwargs)
                break
            except (requests.exceptions.SSLError, requests.exceptions.ConnectionError,
                    requests.exceptions.Timeout) as e:
                last_exc = e
                continue
        else:
            raise last_exc or RuntimeError("request failed")
        if resp.status_code >= 400:
            try:
                body = resp.json()
            except ValueError:
                body = {}
            code = body.get("code", f"http_{resp.status_code}")
            message = body.get("message", resp.text[:300])
            exc_cls = _ERROR_MAP.get(code, BenchmarkError)
            raise exc_cls(code=code, message=message, status=resp.status_code,
                          detail=body.get("detail") or {})
        return resp.json()

    def list_challenges(self) -> list[Challenge]:
        data = self._request("GET", "")
        return [Challenge(**{k: v for k, v in item.items() if k in Challenge.__dataclass_fields__})
                for item in data]

    def start_challenge(self, unique_code: str) -> list[str]:
        """启动题目容器，返回 container_addr 列表。"""
        data = self._request("POST", "/start", params={"unique_code": unique_code})
        return list(data.get("container_addr") or [])

    def get_hint(self, unique_code: str) -> str | None:
        data = self._request("GET", "/hint", params={"unique_code": unique_code})
        return data.get("hint")

    def submit_flag(self, unique_code: str, flag: str) -> SubmitResult:
        data = self._request("POST", "/submit", json={"unique_code": unique_code, "flag": flag})
        return SubmitResult(**{k: v for k, v in data.items() if k in SubmitResult.__dataclass_fields__})

    def close_challenge(self, unique_code: str) -> bool:
        data = self._request("POST", "/close", params={"unique_code": unique_code})
        return bool(data.get("closed"))
