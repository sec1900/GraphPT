"""扫描配置管理模块 — 管理资产级别的扫描配置和字典选择。

功能：
1. 加载/保存资产的 scan_config.yaml
2. 解析字典 profile（quick/standard/deep）
3. 解析字典路径占位符
4. 提供配置 API 给前端
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

import yaml

_log = logging.getLogger("graphpt.scan_config")

_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
_WORDLISTS_DIR = _PROJECT_ROOT / "res" / "wordlists"
_PROFILES_PATH = _WORDLISTS_DIR / "wordlist_profiles.yaml"
_ASSETS_DIR = _PROJECT_ROOT / "data" / "assets"


class ScanConfig:
    """资产扫描配置"""

    def __init__(self, asset_id: str = "default"):
        self.asset_id = asset_id
        self.config_path = _ASSETS_DIR / asset_id / "scan_config.yaml"
        self.config: dict[str, Any] = {}
        self.profiles: dict[str, Any] = {}
        self._load()

    def _load(self) -> None:
        """加载配置文件"""
        # 加载 wordlist profiles
        if _PROFILES_PATH.exists():
            with open(_PROFILES_PATH, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f) or {}
                self.profiles = data.get("profiles", {})
                self.stats = data.get("stats", {})
        else:
            _log.warning("wordlist_profiles.yaml not found")
            self.profiles = {}
            self.stats = {}

        # 加载资产配置
        if self.config_path.exists():
            with open(self.config_path, "r", encoding="utf-8") as f:
                self.config = yaml.safe_load(f) or {}
                # 确保 config 不是 None
                if not isinstance(self.config, dict):
                    self.config = {}

                # 修复 None 值字段（YAML 中只有键没有值）
                if self.config.get("wordlists") is None:
                    self.config["wordlists"] = {}
                if self.config.get("tools_enabled") is None:
                    self.config["tools_enabled"] = {}
                if self.config.get("tool_params") is None:
                    self.config["tool_params"] = {}
        else:
            _log.info(f"scan_config.yaml not found for asset {self.asset_id}, using defaults")
            self.config = {}

        # 填充默认值
        if not self.config:
            self.config = self._default_config()

    def _default_config(self) -> dict[str, Any]:
        """默认配置"""
        return {
            "scan_strategy": {
                "profile": "standard",
                "force_rescan": False,
                "max_threads": 50,
                "timeout": 30,
            },
            "wordlists": {},
            "tools_enabled": {},
            "tool_params": {},
            "auth": {},  # 认证态扫描: {enabled, type: cookie|header|basic, value, header_name}
        }

    # ---- 认证态扫描配置 ----

    def get_auth(self) -> dict[str, Any]:
        """获取认证配置。返回 {enabled, type, value, header_name}。"""
        auth = self.config.get("auth", {}) or {}
        return {
            "enabled": bool(auth.get("enabled", False)),
            "type": str(auth.get("type", "cookie") or "cookie"),
            "value": str(auth.get("value", "") or ""),
            "header_name": str(auth.get("header_name", "Authorization") or "Authorization"),
        }

    def set_auth(self, *, enabled: bool = True, auth_type: str = "cookie",
                 value: str = "", header_name: str = "Authorization") -> None:
        """保存认证配置到 scan_config.yaml。"""
        if not isinstance(self.config.get("auth"), dict):
            self.config["auth"] = {}
        self.config["auth"] = {
            "enabled": bool(enabled),
            "type": auth_type,
            "value": str(value or ""),
            "header_name": header_name,
        }
        self.save()

    def auth_headers_string(self) -> str:
        """生成工具命令可用的 -H 参数串（供 {auth_headers} 占位符）。

        示例:
          cookie → -H "Cookie: session=abc"
          header → -H "X-API-Key: xyz"
          basic  → -H "Authorization: Basic base64(user:pass)"
        未启用/无值 → 空串（命令里留空，行为与无认证一致）。
        """
        auth = self.get_auth()
        if not auth.get("enabled"):
            return ""
        value = auth.get("value", "")
        if not value:
            return ""
        atype = auth.get("type", "cookie")
        if atype == "cookie":
            return f'-H "Cookie: {value}"'
        if atype == "header":
            name = auth.get("header_name", "Authorization")
            return f'-H "{name}: {value}"'
        if atype == "basic":
            import base64
            enc = base64.b64encode(value.encode("utf-8")).decode("ascii")
            return f'-H "Authorization: Basic {enc}"'
        return ""

    def save(self) -> None:
        """保存配置到文件"""
        self.config_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.config_path, "w", encoding="utf-8") as f:
            yaml.dump(self.config, f, default_flow_style=False, allow_unicode=True)
        _log.info(f"Saved scan config for asset {self.asset_id}")

    def get_profile(self) -> str:
        """获取当前 profile（quick/standard/deep）"""
        return self.config.get("scan_strategy", {}).get("profile", "standard")

    def set_profile(self, profile: str) -> None:
        """设置 profile"""
        if profile not in self.profiles:
            raise ValueError(f"Unknown profile: {profile}. Valid: {list(self.profiles.keys())}")
        self.config.setdefault("scan_strategy", {})["profile"] = profile

    def get_wordlist(self, key: str) -> str:
        """获取字典路径

        Args:
            key: 字典类型（dns_subdomains, web_dirs, passwords 等）

        Returns:
            绝对路径字符串
        """
        # 确保 config 是字典
        if not isinstance(self.config, dict):
            self.config = self._default_config()

        # 1. 优先使用自定义配置
        custom = self.config.get("wordlists", {}).get(key) if self.config else None
        if custom:
            return str(_WORDLISTS_DIR / custom)

        # 2. 使用 profile 中的配置
        profile = self.get_profile()
        profile_config = self.profiles.get(profile, {})
        wordlist = profile_config.get(key)

        if wordlist:
            return str(_WORDLISTS_DIR / wordlist)

        # 3. 降级到默认值
        _log.warning(f"No wordlist configured for {key}, using fallback")
        fallback = {
            "dns_subdomains": "dns_subdomains.txt",
            "web_dirs": "web_dirs.txt",
            "passwords": "top-passwords.txt",
            "usernames": "top-usernames.txt",
        }
        return str(_WORDLISTS_DIR / fallback.get(key, "common.txt"))

    def get_wordlist_stats(self, key: str) -> dict[str, Any]:
        """获取字典统计信息

        Returns:
            {"lines": 5000, "size_kb": 34, "path": "..."}
        """
        path = self.get_wordlist(key)
        relative_path = Path(path).relative_to(_WORDLISTS_DIR).as_posix()

        stats = self.stats.get(relative_path, {})
        if not stats:
            # 动态统计（如果不在预定义列表中）
            try:
                p = Path(path)
                if p.exists():
                    lines = len(p.read_text(encoding="utf-8", errors="ignore").splitlines())
                    size_kb = round(p.stat().st_size / 1024, 1)
                    stats = {"lines": lines, "size_kb": size_kb}
            except Exception as e:
                _log.warning(f"Failed to stat wordlist {path}: {e}")
                stats = {"lines": 0, "size_kb": 0}

        return {**stats, "path": relative_path}

    def get_all_wordlists(self) -> dict[str, dict[str, Any]]:
        """获取所有字典配置和统计

        Returns:
            {
                "dns_subdomains": {"lines": 5000, "size_kb": 34, "path": "..."},
                "web_dirs": {...},
                ...
            }
        """
        keys = ["dns_subdomains", "web_dirs", "web_files", "passwords", "usernames"]
        return {key: self.get_wordlist_stats(key) for key in keys}

    def update_wordlist(self, key: str, wordlist_path: str) -> None:
        """更新字典配置

        Args:
            key: 字典类型
            wordlist_path: 相对于 res/wordlists/ 的路径
        """
        self.config.setdefault("wordlists", {})[key] = wordlist_path

    def is_tool_enabled(self, tool: str) -> bool:
        """检查工具是否启用（默认全部启用）"""
        return self.config.get("tools_enabled", {}).get(tool, True)

    def get_tool_params(self, tool: str) -> dict[str, Any]:
        """获取工具特定参数"""
        return self.config.get("tool_params", {}).get(tool, {})

    def to_dict(self) -> dict[str, Any]:
        """导出完整配置（用于 API）"""
        return {
            "asset_id": self.asset_id,
            "config": self.config,
            "current_profile": self.get_profile(),
            "available_profiles": {
                name: {"desc": prof.get("desc", ""), "wordlists": list(prof.keys())}
                for name, prof in self.profiles.items()
            },
            "wordlists": self.get_all_wordlists(),
        }


def get_scan_config(asset_id: str = "default") -> ScanConfig:
    """获取资产扫描配置（单例）"""
    return ScanConfig(asset_id)


# 工具命令中的字典占位符解析
def resolve_wordlist_placeholder(asset_id: str, placeholder: str) -> str:
    """解析 {wordlist:dns_subdomains} 占位符

    Args:
        asset_id: 资产 ID
        placeholder: 占位符内容，如 "wordlist:dns_subdomains"

    Returns:
        字典绝对路径
    """
    if not placeholder.startswith("wordlist:"):
        return placeholder

    key = placeholder.split(":", 1)[1]
    config = get_scan_config(asset_id)
    return config.get_wordlist(key)
