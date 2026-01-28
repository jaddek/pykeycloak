"""
Detailed unit tests for the clients module to increase coverage.
"""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from httpx import HTTPStatusError, RequestError, Response

from pykeycloak.core.clients import (
    HttpMethod,
    KeycloakHttpClientWrapperAsync,
    get_keycloak_client_wrapper,
    get_keycloak_client_wrapper_from_env,
)
from pykeycloak.core.sanitizer import SensitiveDataSanitizer
from pykeycloak.core.settings import ClientSettings, HttpTransportSettings


class TestKeycloakHttpClientWrapperAsyncDetailed:
    """Detailed test cases for the KeycloakHttpClientWrapperAsync class."""

    @pytest.fixture
    def mock_settings(self):
        """Fixture to create mock settings."""
        client_settings = ClientSettings()
        transport_settings = HttpTransportSettings()
        return client_settings, transport_settings

    def test_init_with_defaults(self, mock_settings):
        """Test initialization with default values."""
        wrapper = KeycloakHttpClientWrapperAsync()

        assert wrapper._client is not None

    def test_init_with_custom_values(self, mock_settings):
        """Test initialization with custom values."""
        client_settings, transport_settings = mock_settings
        wrapper = KeycloakHttpClientWrapperAsync(
            client_settings=client_settings,
            transport_settings=transport_settings,
        )

        assert wrapper._client is not None

    @pytest.mark.asyncio
    async def test_request_success(self):
        """Test successful request."""
        wrapper = KeycloakHttpClientWrapperAsync()

        # Mock the client.request method
        mock_response = MagicMock(spec=Response)
        mock_response.json.return_value = {"result": "success"}
        mock_response.headers = {"content-type": "application/json"}
        wrapper._client.request = AsyncMock(return_value=mock_response)

        response = await wrapper.request(HttpMethod.GET, "http://example.com")

        assert response == mock_response
        wrapper._client.request.assert_called_once()

    @pytest.mark.asyncio
    async def test_request_with_request_error(self):
        """Test request with RequestError exception."""
        wrapper = KeycloakHttpClientWrapperAsync()

        # Mock the client.request method to raise RequestError
        wrapper._client.request = AsyncMock(
            side_effect=RequestError(message="Network error", request=None)
        )

        with pytest.raises(RequestError):
            await wrapper.request(HttpMethod.GET, "http://example.com")

    @pytest.mark.asyncio
    async def test_request_with_http_status_error(self):
        """Test request with HTTPStatusError exception."""
        wrapper = KeycloakHttpClientWrapperAsync()

        # Mock the client.request method to raise HTTPStatusError
        wrapper._client.request = AsyncMock(
            side_effect=HTTPStatusError(
                message="Bad Request", request=None, response=MagicMock()
            )
        )

        with pytest.raises(HTTPStatusError):
            await wrapper.request(HttpMethod.GET, "http://example.com")

    @pytest.mark.asyncio
    async def test_request_with_raise_exception_flag(self):
        """Test request with raise_exception flag."""
        wrapper = KeycloakHttpClientWrapperAsync()

        # Mock the client.request method
        mock_response = MagicMock(spec=Response)
        mock_response.json.return_value = {"result": "success"}
        mock_response.headers = {"content-type": "application/json"}
        mock_response.raise_for_status = MagicMock()
        wrapper._client.request = AsyncMock(return_value=mock_response)

        await wrapper.request(
            HttpMethod.GET, "http://example.com", raise_exception=True
        )

        mock_response.raise_for_status.assert_called_once()

    @pytest.mark.asyncio
    async def test_context_manager(self):
        """Test context manager functionality."""
        wrapper = KeycloakHttpClientWrapperAsync()

        # Mock the client context manager methods
        wrapper._client.__aenter__ = AsyncMock()
        wrapper._client.__aexit__ = AsyncMock()

        async with wrapper as w:
            assert w is wrapper

        wrapper._client.__aenter__.assert_called_once()
        wrapper._client.__aexit__.assert_called_once()

    @pytest.mark.asyncio
    async def test_close_method(self):
        """Test close method."""
        wrapper = KeycloakHttpClientWrapperAsync()
        wrapper._client.aclose = AsyncMock()

        await wrapper.close()

        wrapper._client.aclose.assert_called_once()


def test_get_keycloak_client_wrapper():
    """Test get_keycloak_client_wrapper function."""
    client_settings = ClientSettings()
    transport_settings = HttpTransportSettings()
    sanitizer = SensitiveDataSanitizer()

    wrapper = get_keycloak_client_wrapper(
        client_settings=client_settings,
        transport_settings=transport_settings,
        sanitizer=sanitizer,
    )

    assert isinstance(wrapper, KeycloakHttpClientWrapperAsync)
    assert wrapper._sanitizer is sanitizer


@patch("pykeycloak.core.settings.ClientSettings.from_env")
@patch("pykeycloak.core.settings.HttpTransportSettings.from_env")
@patch("pykeycloak.core.sanitizer.SensitiveDataSanitizer.from_env")
def test_get_keycloak_client_wrapper_from_env(
    mock_sanitizer, mock_transport, mock_client
):
    """Test get_keycloak_client_wrapper_from_env function."""
    mock_client.return_value = ClientSettings()
    mock_transport.return_value = HttpTransportSettings()
    mock_sanitizer.return_value = SensitiveDataSanitizer()

    wrapper = get_keycloak_client_wrapper_from_env()

    assert isinstance(wrapper, KeycloakHttpClientWrapperAsync)
    mock_client.assert_called_once()
    mock_transport.assert_called_once()
    mock_sanitizer.assert_called_once()
