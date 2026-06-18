from graphpt.common.settings import AppSettings


def test_proxy_url_prefers_unified_env_key():
    settings = AppSettings.from_env({
        "GRAPHPT_PROXY_URL": "http://proxy.local:8080",
    })

    assert settings.proxy_url == "http://proxy.local:8080"
