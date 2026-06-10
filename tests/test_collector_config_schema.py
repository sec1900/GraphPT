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


def test_pipelines_use_explicit_tools_not_categories():
    cfg = yaml.safe_load(PIPELINES_YAML.read_text(encoding="utf-8"))

    assert "pipelines" in cfg
    text = PIPELINES_YAML.read_text(encoding="utf-8")
    assert "category:" not in text
    for pipeline in cfg["pipelines"].values():
        for stage in pipeline["stages"]:
            assert "tools" in stage
            assert stage["tools"]
