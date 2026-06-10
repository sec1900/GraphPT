from __future__ import annotations

import os
from dataclasses import dataclass, replace
from typing import Any, Mapping

DEFAULT_AI_TIMEOUT_S = 300.0
DEFAULT_AI_MAX_RETRIES = 3
DEFAULT_AI_MAX_CONCURRENT = 0
DEFAULT_PARALLEL_WORKERS = 5
DEFAULT_APPROVAL_MODE = "auto_approve"
DEFAULT_APPROVAL_TIMEOUT_S = 10.0
DEFAULT_SCHEDULER_MODE = "event"
DEFAULT_DEBUG_DIR = "debug"
# run_command 工具单条命令执行超时的上限（秒）。慢扫描（全端口 nmap、大字典爆破）
# 可调高此值；模型传入的 timeout_s 会被钳到 [1, 此上限]。
DEFAULT_CMD_TIMEOUT_MAX_S = 86400.0


def _safe_float(raw: str, default: float) -> float:
    """将字符串安全转换为 float，无效值返回 default。"""
    s = raw.strip()
    if not s:
        return default
    try:
        return float(s)
    except (ValueError, TypeError):
        return default


def _safe_int(raw: str, default: int) -> int:
    """将字符串安全转换为 int，无效值返回 default。"""
    s = raw.strip()
    if not s:
        return default
    try:
        return int(s)
    except (ValueError, TypeError):
        return default


def _coerce_float(raw: object, default: float) -> float:
    if isinstance(raw, bool):
        return float(int(raw))
    if isinstance(raw, (int, float)):
        return float(raw)
    return _safe_float(str(raw or ""), default)


def _coerce_int(raw: object, default: int) -> int:
    if isinstance(raw, bool):
        return int(raw)
    if isinstance(raw, int):
        return raw
    if isinstance(raw, float):
        return int(raw)
    return _safe_int(str(raw or ""), default)


def _coerce_bool(raw: object, default: bool) -> bool:
    if isinstance(raw, bool):
        return raw
    text = str(raw or "").strip().lower()
    if not text:
        return default
    if text in {"true", "1", "yes", "on"}:
        return True
    if text in {"false", "0", "no", "off"}:
        return False
    return default


def _normalize_scheduler_mode(raw: str) -> str:
    value = str(raw or "").strip().lower().replace("-", "").replace("_", "")
    aliases = {
        "": DEFAULT_SCHEDULER_MODE,
        "legacy": "legacy",
        "round": "legacy",
        "shadow": "shadow",
        "observe": "shadow",
        "dual": "event",
        "hybrid": "event",
        "event": "event",
        "eventdriven": "event",
        "watchdog": "watchdog",
        "watch": "watchdog",
    }
    return aliases.get(value, DEFAULT_SCHEDULER_MODE)


def normalize_ai_timeout_s(raw: object) -> float:
    return _coerce_float(raw, DEFAULT_AI_TIMEOUT_S)


def normalize_cmd_timeout_max_s(raw: object) -> float:
    return _coerce_float(raw, DEFAULT_CMD_TIMEOUT_MAX_S)


def normalize_ai_max_retries(raw: object) -> int:
    return _coerce_int(raw, DEFAULT_AI_MAX_RETRIES)


def normalize_ai_max_concurrent(raw: object) -> int:
    return _coerce_int(raw, DEFAULT_AI_MAX_CONCURRENT)


def normalize_parallel_workers(raw: object) -> int:
    return _coerce_int(raw, DEFAULT_PARALLEL_WORKERS)


def normalize_approval_timeout_s(raw: object) -> float:
    return _coerce_float(raw, DEFAULT_APPROVAL_TIMEOUT_S)


def normalize_debug_dir(raw: object) -> str:
    text = str(raw or "").strip()
    return text or DEFAULT_DEBUG_DIR


@dataclass(frozen=True)
class AppSettings:
    """
    GraphPT 运行配置（来源：环境变量 / .env）。

    约定：
    - 所有配置项都支持通过 .env 持久化
    - 涉密项（如密码/Key）同样放在 .env，但不要提交到仓库（由 .gitignore 控制）
    """

    db: str = ""
    poc_dir: str = ""
    toolkit_dir: str = ""
    projects_dir: str = ""

    webdav_url: str = ""
    webdav_base_dir: str = ""
    webdav_username: str = ""
    webdav_password: str = ""

    fofa_email: str = ""
    fofa_key: str = ""
    shodan_api_key: str = ""
    hunter_api_key: str = ""
    github_token: str = ""
    tianyancha_token: str = ""

    ai_base_url: str = ""
    ai_model: str = ""
    ai_api_key: str = ""
    ai_wire_api: str = ""
    ai_timeout_s: float = DEFAULT_AI_TIMEOUT_S
    ai_max_tokens: int = 65536  # 输出上限，思考模型需要较大值（默认 64K）
    ai_max_retries: int = DEFAULT_AI_MAX_RETRIES
    ai_max_concurrent: int = DEFAULT_AI_MAX_CONCURRENT  # 0 = 不限制
    parallel_workers: int = DEFAULT_PARALLEL_WORKERS

    approval_mode: str = DEFAULT_APPROVAL_MODE
    approval_timeout_s: float = DEFAULT_APPROVAL_TIMEOUT_S
    cmd_timeout_max_s: float = DEFAULT_CMD_TIMEOUT_MAX_S

    proxy_url: str = ""
    validation_mailbox_url: str = ""
    validation_callback_url: str = ""
    validation_oob_domain: str = ""
    validation_infra_hosts: str = ""
    docker_mode: str = ""  # "true" / "false" / ""
    cache_rotate_mb: float = 5.0
    cache_rotate_lines: int = 50000
    cache_retention_count: int = 40
    cache_compress_after_h: float = 24.0
    scheduler_mode: str = DEFAULT_SCHEDULER_MODE

    @property
    def docker_mode_enabled(self) -> bool:
        """docker_mode 转为布尔值。"""
        return self.docker_mode.lower() in ("true", "1", "yes")
    docker_image: str = ""
    max_token_budget: int = 0
    browser_headless: bool = True
    debug_dir: str = DEFAULT_DEBUG_DIR
    debug: bool = False

    # Reasoning 配置
    reasoning_mode: str = "auto"      # auto / enabled / disabled
    reasoning_effort: str = "high"     # low / medium / high / xhigh，默认 high（16K token 思考预算）
    reasoning_fallback: str = "disable"  # disable / error

    @property
    def effective_ai_timeout_s(self) -> float:
        return normalize_ai_timeout_s(self.ai_timeout_s)

    @property
    def effective_ai_max_retries(self) -> int:
        return normalize_ai_max_retries(self.ai_max_retries)

    @property
    def effective_ai_max_concurrent(self) -> int:
        return normalize_ai_max_concurrent(self.ai_max_concurrent)

    @property
    def effective_parallel_workers(self) -> int:
        return normalize_parallel_workers(self.parallel_workers)

    @property
    def effective_approval_mode(self) -> str:
        from graphpt.core.approval import public_approval_mode

        return public_approval_mode(self.approval_mode, default=DEFAULT_APPROVAL_MODE)

    @property
    def effective_approval_timeout_s(self) -> float:
        return normalize_approval_timeout_s(self.approval_timeout_s)

    @property
    def effective_cmd_timeout_max_s(self) -> float:
        return normalize_cmd_timeout_max_s(self.cmd_timeout_max_s)

    @property
    def effective_scheduler_mode(self) -> str:
        return _normalize_scheduler_mode(self.scheduler_mode)

    @property
    def effective_debug_dir(self) -> str:
        return normalize_debug_dir(self.debug_dir)

    @staticmethod
    def from_env(environ: Mapping[str, str] | None = None) -> "AppSettings":
        env = environ or os.environ

        def get(key: str) -> str:
            return str(env.get(key, "") or "").strip()

        return AppSettings(
            db=get("GRAPHPT_DB"),
            poc_dir=get("GRAPHPT_POC_DIR"),
            toolkit_dir=get("GRAPHPT_TOOLKIT_DIR"),
            projects_dir=get("GRAPHPT_PROJECTS_DIR"),
            webdav_url=get("GRAPHPT_WEBDAV_URL"),
            webdav_base_dir=get("GRAPHPT_WEBDAV_BASE_DIR"),
            webdav_username=get("GRAPHPT_WEBDAV_USERNAME"),
            webdav_password=get("GRAPHPT_WEBDAV_PASSWORD"),
            fofa_email=get("GRAPHPT_FOFA_EMAIL"),
            fofa_key=get("GRAPHPT_FOFA_KEY"),
            shodan_api_key=get("GRAPHPT_SHODAN_API_KEY"),
            hunter_api_key=get("GRAPHPT_HUNTER_API_KEY"),
            github_token=get("GRAPHPT_GITHUB_TOKEN"),
            tianyancha_token=get("GRAPHPT_TIANYANCHA_TOKEN"),
            ai_base_url=get("GRAPHPT_AI_BASE_URL"),
            ai_model=get("GRAPHPT_AI_MODEL"),
            ai_api_key=get("GRAPHPT_AI_API_KEY"),
            ai_wire_api=get("GRAPHPT_AI_WIRE_API"),
            ai_max_tokens=_safe_int(get("GRAPHPT_AI_MAX_TOKENS"), 65536),
            ai_timeout_s=normalize_ai_timeout_s(get("GRAPHPT_AI_TIMEOUT_S")),
            ai_max_retries=normalize_ai_max_retries(get("GRAPHPT_AI_MAX_RETRIES")),
            ai_max_concurrent=normalize_ai_max_concurrent(get("GRAPHPT_AI_MAX_CONCURRENT")),
            approval_mode=get("GRAPHPT_APPROVAL_MODE") or DEFAULT_APPROVAL_MODE,
            approval_timeout_s=normalize_approval_timeout_s(get("GRAPHPT_APPROVAL_TIMEOUT_S")),
            cmd_timeout_max_s=normalize_cmd_timeout_max_s(get("GRAPHPT_CMD_TIMEOUT_MAX_S")),
            parallel_workers=normalize_parallel_workers(get("GRAPHPT_PARALLEL_WORKERS")),
            proxy_url=get("GRAPHPT_PROXY_URL"),
            validation_mailbox_url=get("GRAPHPT_VALIDATION_MAILBOX_URL"),
            validation_callback_url=get("GRAPHPT_VALIDATION_CALLBACK_URL"),
            validation_oob_domain=get("GRAPHPT_VALIDATION_OOB_DOMAIN"),
            validation_infra_hosts=get("GRAPHPT_VALIDATION_INFRA_HOSTS"),
            docker_mode=get("GRAPHPT_DOCKER_MODE"),
            cache_rotate_mb=_safe_float(get("GRAPHPT_CACHE_ROTATE_MB"), 5.0),
            cache_rotate_lines=_safe_int(get("GRAPHPT_CACHE_ROTATE_LINES"), 50000),
            cache_retention_count=_safe_int(get("GRAPHPT_CACHE_RETENTION_COUNT"), 40),
            cache_compress_after_h=_safe_float(get("GRAPHPT_CACHE_COMPRESS_AFTER_H"), 24.0),
            scheduler_mode=_normalize_scheduler_mode(get("GRAPHPT_SCHEDULER_MODE")),
            docker_image=get("GRAPHPT_DOCKER_IMAGE"),
            max_token_budget=_safe_int(get("GRAPHPT_MAX_TOKEN_BUDGET"), 0),
            browser_headless=_coerce_bool(get("GRAPHPT_BROWSER_HEADLESS"), True),
            debug_dir=normalize_debug_dir(get("GRAPHPT_DEBUG_DIR")),
            debug=_coerce_bool(get("GRAPHPT_DEBUG"), False),
            reasoning_mode=get("GRAPHPT_REASONING_MODE") or "auto",
            reasoning_effort=get("GRAPHPT_REASONING_EFFORT") or "high",
            reasoning_fallback=get("GRAPHPT_REASONING_FALLBACK") or "disable",
        )

    def with_overrides(self, **kwargs: Any) -> "AppSettings":
        # 便于把命令行参数合并进来（命令行优先）
        return replace(self, **kwargs)

    def public_dict(self, *, effective_db_file: str = "") -> dict[str, Any]:
        # 注意：不要返回明文的密码/Key
        return {
            "db": self.db,
            "effective_db_file": effective_db_file,
            "poc_dir": self.poc_dir,
            "toolkit_dir": self.toolkit_dir,
            "projects_dir": self.projects_dir,
            "webdav_url": self.webdav_url,
            "webdav_base_dir": self.webdav_base_dir,
            "webdav_username_set": bool(self.webdav_username),
            "webdav_password_set": bool(self.webdav_password),
            "fofa_email": self.fofa_email,
            "fofa_key_set": bool(self.fofa_key),
            "shodan_api_key_set": bool(self.shodan_api_key),
            "hunter_api_key_set": bool(self.hunter_api_key),
            "github_token_set": bool(self.github_token),
            "tianyancha_token_set": bool(self.tianyancha_token),
            "ai_base_url": self.ai_base_url,
            "ai_model": self.ai_model,
            "ai_api_key_set": bool(self.ai_api_key),
            "ai_wire_api": self.ai_wire_api,
            "ai_timeout_s": self.effective_ai_timeout_s,
            "ai_max_retries": self.effective_ai_max_retries,
            "ai_max_concurrent": self.effective_ai_max_concurrent,
            "approval_mode": self.effective_approval_mode,
            "approval_timeout_s": self.effective_approval_timeout_s,
            "cmd_timeout_max_s": self.effective_cmd_timeout_max_s,
            "parallel_workers": self.effective_parallel_workers,
            "proxy_url": self.proxy_url,
            "validation_mailbox_url": self.validation_mailbox_url,
            "validation_callback_url": self.validation_callback_url,
            "validation_oob_domain": self.validation_oob_domain,
            "validation_infra_hosts": self.validation_infra_hosts,
            "docker_mode": self.docker_mode,
            "cache_rotate_mb": self.cache_rotate_mb,
            "cache_rotate_lines": self.cache_rotate_lines,
            "cache_retention_count": self.cache_retention_count,
            "cache_compress_after_h": self.cache_compress_after_h,
            "scheduler_mode": self.effective_scheduler_mode,
            "docker_image": self.docker_image,
            "max_token_budget": self.max_token_budget,
            "browser_headless": self.browser_headless,
            "debug_dir": self.effective_debug_dir,
            "debug": self.debug,
            "reasoning_mode": self.reasoning_mode,
            "reasoning_effort": self.reasoning_effort,
            "reasoning_fallback": self.reasoning_fallback,
        }


ENV_KEY_MAP: dict[str, str] = {
    "db": "GRAPHPT_DB",
    "poc_dir": "GRAPHPT_POC_DIR",
    "toolkit_dir": "GRAPHPT_TOOLKIT_DIR",
    "projects_dir": "GRAPHPT_PROJECTS_DIR",
    "webdav_url": "GRAPHPT_WEBDAV_URL",
    "webdav_base_dir": "GRAPHPT_WEBDAV_BASE_DIR",
    "webdav_username": "GRAPHPT_WEBDAV_USERNAME",
    "webdav_password": "GRAPHPT_WEBDAV_PASSWORD",
    "fofa_email": "GRAPHPT_FOFA_EMAIL",
    "fofa_key": "GRAPHPT_FOFA_KEY",
    "shodan_api_key": "GRAPHPT_SHODAN_API_KEY",
    "hunter_api_key": "GRAPHPT_HUNTER_API_KEY",
    "github_token": "GRAPHPT_GITHUB_TOKEN",
    "tianyancha_token": "GRAPHPT_TIANYANCHA_TOKEN",
    "ai_base_url": "GRAPHPT_AI_BASE_URL",
    "ai_model": "GRAPHPT_AI_MODEL",
    "ai_api_key": "GRAPHPT_AI_API_KEY",
    "ai_wire_api": "GRAPHPT_AI_WIRE_API",
    "ai_timeout_s": "GRAPHPT_AI_TIMEOUT_S",
    "ai_max_retries": "GRAPHPT_AI_MAX_RETRIES",
    "ai_max_concurrent": "GRAPHPT_AI_MAX_CONCURRENT",
    "approval_mode": "GRAPHPT_APPROVAL_MODE",
    "approval_timeout_s": "GRAPHPT_APPROVAL_TIMEOUT_S",
    "cmd_timeout_max_s": "GRAPHPT_CMD_TIMEOUT_MAX_S",
    "parallel_workers": "GRAPHPT_PARALLEL_WORKERS",
    "proxy_url": "GRAPHPT_PROXY_URL",
    "validation_mailbox_url": "GRAPHPT_VALIDATION_MAILBOX_URL",
    "validation_callback_url": "GRAPHPT_VALIDATION_CALLBACK_URL",
    "validation_oob_domain": "GRAPHPT_VALIDATION_OOB_DOMAIN",
    "validation_infra_hosts": "GRAPHPT_VALIDATION_INFRA_HOSTS",
    "docker_mode": "GRAPHPT_DOCKER_MODE",
    "cache_rotate_mb": "GRAPHPT_CACHE_ROTATE_MB",
    "cache_rotate_lines": "GRAPHPT_CACHE_ROTATE_LINES",
    "cache_retention_count": "GRAPHPT_CACHE_RETENTION_COUNT",
    "cache_compress_after_h": "GRAPHPT_CACHE_COMPRESS_AFTER_H",
    "scheduler_mode": "GRAPHPT_SCHEDULER_MODE",
    "docker_image": "GRAPHPT_DOCKER_IMAGE",
    "max_token_budget": "GRAPHPT_MAX_TOKEN_BUDGET",
    "browser_headless": "GRAPHPT_BROWSER_HEADLESS",
    "debug_dir": "GRAPHPT_DEBUG_DIR",
    "debug": "GRAPHPT_DEBUG",
    "reasoning_mode": "GRAPHPT_REASONING_MODE",
    "reasoning_effort": "GRAPHPT_REASONING_EFFORT",
    "reasoning_fallback": "GRAPHPT_REASONING_FALLBACK",
}


def is_debug() -> bool:
    return _coerce_bool(os.environ.get("GRAPHPT_DEBUG", ""), False)


def get_proxy_url() -> str:
    return os.environ.get("GRAPHPT_PROXY_URL", "")


def get_setting_text(*, attr_name: str, env_key: str, default: str = "") -> str:
    return str(os.environ.get(env_key, "") or "").strip() or default


def get_ai_max_concurrent() -> int:
    return normalize_ai_max_concurrent(os.environ.get("GRAPHPT_AI_MAX_CONCURRENT", ""))


def get_parallel_workers() -> int:
    return normalize_parallel_workers(os.environ.get("GRAPHPT_PARALLEL_WORKERS", ""))


def get_approval_timeout() -> float:
    return normalize_approval_timeout_s(os.environ.get("GRAPHPT_APPROVAL_TIMEOUT_S", ""))


def get_approval_mode() -> str:
    from graphpt.core.approval import public_approval_mode
    return public_approval_mode(os.environ.get("GRAPHPT_APPROVAL_MODE", ""), default=DEFAULT_APPROVAL_MODE)


def get_scheduler_mode() -> str:
    return _normalize_scheduler_mode(os.environ.get("GRAPHPT_SCHEDULER_MODE", ""))


def get_debug_dir() -> str:
    return normalize_debug_dir(os.environ.get("GRAPHPT_DEBUG_DIR", ""))


def normalize_update_payload(payload: Any) -> dict[str, str | None]:
    """
    归一化配置更新 payload。

    规则：
    - 字段不存在：不更新
    - 值为 null：清空（删除 .env 中对应 key）
    - 值为字符串：trim 后写入；空字符串会被视为清空
    """
    if not isinstance(payload, dict):
        raise ValueError("payload_must_be_object")

    updates: dict[str, str | None] = {}

    for k in ENV_KEY_MAP.keys():
        if k not in payload:
            continue
        v = payload.get(k)
        if v is None:
            updates[k] = None
            continue
        if not isinstance(v, str):
            raise ValueError(f"field_must_be_string key={k}")
        s = v.strip()
        updates[k] = s if s else None

    return updates
