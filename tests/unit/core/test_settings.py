"""
Unit tests for the settings module.
"""

import ssl

from httpx import Limits

from pykeycloak.core.settings import HttpTransportSettings


class TestHttpTransportSettings:
    """Test cases for the HttpTransportSettings class."""

    def test_http_transport_settings_defaults(self):
        """Test HttpTransportSettings with default values."""
        settings = HttpTransportSettings()

        # Check default values
        assert settings.verify is True
        assert settings.cert is None
        assert settings.trust_env is True
        assert settings.http1 is True
        assert settings.http2 is False
        assert isinstance(settings.limits, Limits)
        assert settings.limits.max_connections == 10
        assert settings.limits.max_keepalive_connections == 10
        assert settings.proxy is None
        assert settings.uds is None
        assert settings.local_address is None
        assert settings.retries == 0
        assert settings.socket_options is None

    def test_http_transport_settings_custom_values(self):
        """Test HttpTransportSettings with custom values."""
        custom_limits = Limits(max_connections=20, max_keepalive_connections=15)
        settings = HttpTransportSettings(
            verify=False,
            cert="cert/path",
            trust_env=False,
            http1=False,
            http2=True,
            limits=custom_limits,
            proxy="http://proxy.example.com",
            uds="/path/to/uds",
            local_address="127.0.0.1",
            retries=3,
        )

        assert settings.verify is False
        assert settings.cert == "cert/path"
        assert settings.trust_env is False
        assert settings.http1 is False
        assert settings.http2 is True
        assert settings.limits == custom_limits
        assert settings.proxy == "http://proxy.example.com"
        assert settings.uds == "/path/to/uds"
        assert settings.local_address == "127.0.0.1"
        assert settings.retries == 3

    def test_http_transport_settings_ssl_context(self):
        """Test HttpTransportSettings with SSL context."""
        ssl_context = ssl.create_default_context()
        settings = HttpTransportSettings(verify=ssl_context)

        assert settings.verify == ssl_context

    def test_http_transport_settings_with_minimal_customization(self):
        """Test HttpTransportSettings with minimal customization."""
        settings = HttpTransportSettings(retries=5)

        # Only retries should be different from default
        assert settings.retries == 5
        assert settings.verify is True  # Still default
        assert settings.cert is None  # Still default
        assert settings.trust_env is True  # Still default
