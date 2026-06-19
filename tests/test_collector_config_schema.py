from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
PIPELINES_YAML = ROOT / "graphpt" / "collector" / "pipelines.yaml"
TOOLS_DIR = ROOT / "tools"


def test_tool_configs_use_tool_yaml_schema_only():
    tool_paths = sorted(TOOLS_DIR.glob("*/tool.yaml"))

    assert tool_paths
    assert (TOOLS_DIR / "subfinder" / "tool.yaml").is_file()
    for tool_path in tool_paths:
        text = tool_path.read_text(encoding="utf-8")
        tool_cfg = yaml.safe_load(text)
        assert isinstance(tool_cfg, dict), tool_path
        assert tool_cfg["command"]
        assert isinstance(tool_cfg.get("use_on", {}), dict), tool_path.parent.name
        assert "category" not in text
        assert "input_query" not in text
        assert "input_mapping" not in text


def _tool_config(name: str) -> dict:
    return yaml.safe_load((TOOLS_DIR / name / "tool.yaml").read_text(encoding="utf-8"))


def _all_commands(tool_cfg: dict) -> list[str]:
    commands = [str(tool_cfg.get("command") or "")]
    for rule in tool_cfg.get("use_on", {}).values():
        if isinstance(rule, dict) and rule.get("command"):
            commands.append(str(rule["command"]))
    return commands


def test_tool_commands_match_adapter_output_contracts():
    contracts = {
        "dnsx": "-json",
        "httpx": "-json",
        "naabu": "-json",
        "nuclei": "-jsonl",
    }
    for tool, flag in contracts.items():
        assert flag in _tool_config(tool)["command"]

    assert "-oX -" in _tool_config("nmap")["command"]

    subfinder = _tool_config("subfinder")["command"]
    assert "-json" in subfinder
    assert "-proxy" not in subfinder
    assert "192.168.166.166" not in subfinder

    katana = _tool_config("katana")["command"]
    assert "-jsonl" in katana
    assert "{urls_file}" in katana  # batch mode

    ffuf = _tool_config("ffuf")
    assert all("-json" in command for command in _all_commands(ffuf))


def test_pipelines_use_explicit_tools_not_categories():
    cfg = yaml.safe_load(PIPELINES_YAML.read_text(encoding="utf-8"))

    assert "pipelines" in cfg
    text = PIPELINES_YAML.read_text(encoding="utf-8")
    assert "category:" not in text
    for pipeline in cfg["pipelines"].values():
        for stage in pipeline["stages"]:
            assert "tools" in stage
            assert stage["tools"]
