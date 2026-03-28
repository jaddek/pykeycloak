# SPDX-License-Identifier: MIT
import pytest

from pykeycloak.core.settings import ClientSettings, HttpTransportSettings


class TestHttpTransportSettings:
    def test_default_values(self):
        s = HttpTransportSettings()
        assert s.http1 is True
        assert s.http2 is False
        assert s.verify is True
        assert s.trust_env is False
        assert s.retries == 0

    def test_raises_when_both_http_versions_disabled(self):
        with pytest.raises(ValueError, match="http1"):
            HttpTransportSettings(http1=False, http2=False)

    def test_raises_when_retries_negative(self):
        with pytest.raises(ValueError, match="retries"):
            HttpTransportSettings(retries=-1)

    def test_to_dict_contains_required_keys(self):
        s = HttpTransportSettings()
        d = s.to_dict()
        for key in ["verify", "cert", "http1", "http2", "limits", "trust_env", "retries"]:
            assert key in d

    def test_http2_only_is_valid(self):
        s = HttpTransportSettings(http1=False, http2=True)
        assert s.http2 is True
        assert s.http1 is False

    def test_with_env_uses_defaults_when_no_env_set(self, monkeypatch):
        for key in [
            "KEYCLOAK_HTTPX_HTTP_TRANSPORT_HTTP_VERIFY",
            "KEYCLOAK_HTTPX_HTTP_TRANSPORT_HTTP_CERT",
            "KEYCLOAK_HTTPX_HTTP_TRANSPORT_HTTP_TRUST_ENV",
            "KEYCLOAK_HTTPX_HTTP_TRANSPORT_HTTP_HTTP1",
            "KEYCLOAK_HTTPX_HTTP_TRANSPORT_HTTP_HTTP2",
            "KEYCLOAK_HTTPX_HTTP_TRANSPORT_HTTP_RETRIES",
        ]:
            monkeypatch.delenv(key, raising=False)
        s = HttpTransportSettings.with_env()
        assert isinstance(s, HttpTransportSettings)


class TestClientSettings:
    def test_default_values(self):
        s = ClientSettings()
        assert s.http1 is True
        assert s.http2 is False
        assert s.follow_redirects is False
        assert s.trust_env is False
        assert s.max_redirects >= 0

    def test_raises_when_both_http_versions_disabled(self):
        with pytest.raises(ValueError, match="http1"):
            ClientSettings(http1=False, http2=False)

    def test_raises_when_max_redirects_negative(self):
        with pytest.raises(ValueError, match="max_redirects"):
            ClientSettings(max_redirects=-1)

    def test_to_dict_contains_required_keys(self):
        s = ClientSettings()
        d = s.to_dict()
        for key in ["verify", "http1", "http2", "timeout", "follow_redirects", "base_url"]:
            assert key in d

    def test_event_hooks_initialized_to_empty_dict(self):
        s = ClientSettings()
        assert s.event_hooks == {}

    def test_add_event_hook(self):
        s = ClientSettings()
        func = lambda: None  # noqa: E731
        s.add_event_hook("request", func)
        assert func in s.event_hooks["request"]

    def test_extend_event_hooks(self):
        s = ClientSettings()
        f1 = lambda: None  # noqa: E731
        f2 = lambda: None  # noqa: E731
        s.extend_event_hooks("response", [f1, f2])
        assert f1 in s.event_hooks["response"]
        assert f2 in s.event_hooks["response"]

    def test_str_contains_base_url(self):
        s = ClientSettings(base_url="https://example.com")
        assert "https://example.com" in str(s)

    def test_with_env_requires_base_url(self, monkeypatch):
        monkeypatch.delenv("KEYCLOAK_BASE_URL", raising=False)
        with pytest.raises(RuntimeError):
            ClientSettings.with_env()

    def test_with_env_uses_provided_base_url(self, monkeypatch):
        monkeypatch.setenv("KEYCLOAK_BASE_URL", "https://keycloak.example.com")
        s = ClientSettings.with_env()
        assert s.base_url == "https://keycloak.example.com"
