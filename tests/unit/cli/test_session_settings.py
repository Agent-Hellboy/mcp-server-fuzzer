from mcp_fuzzer.cli.config_merge import CliConfig
from mcp_fuzzer.cli.session_settings import SessionSettings


def test_cli_config_to_session_settings():
    args = object()
    cfg = CliConfig(args=args, merged={"a": 1})
    settings = cfg.to_session_settings()
    assert isinstance(settings, SessionSettings)
    assert settings.config == {"a": 1}


def test_session_settings_get_and_attr():
    settings = SessionSettings(
        {"x": 5, "mode": "tools", "protocol": "stdio", "endpoint": "x"}
    )
    assert settings.get("x") == 5
    assert settings.mode == "tools"
