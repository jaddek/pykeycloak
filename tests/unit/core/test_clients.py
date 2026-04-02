# SPDX-License-Identifier: MIT
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from pykeycloak.core.clients import HttpMethod, KeycloakHttpClientAsync


class TestHttpMethod:
    def test_get_value(self):
        assert HttpMethod.GET.value == "GET"

    def test_post_value(self):
        assert HttpMethod.POST.value == "POST"

    def test_put_value(self):
        assert HttpMethod.PUT.value == "PUT"

    def test_delete_value(self):
        assert HttpMethod.DELETE.value == "DELETE"

    def test_patch_value(self):
        assert HttpMethod.PATCH.value == "PATCH"

    def test_head_value(self):
        assert HttpMethod.HEAD.value == "HEAD"

    def test_options_value(self):
        assert HttpMethod.OPTIONS.value == "OPTIONS"

    def test_has_seven_members(self):
        assert len(HttpMethod) == 7


class TestKeycloakHttpClientAsyncInit:
    def test_stores_client(self):
        mock_client = MagicMock()
        kc = KeycloakHttpClientAsync(client=mock_client)
        assert kc.client is mock_client

    def test_init_default_client_returns_instance(self):
        mock_client = MagicMock()
        kc = KeycloakHttpClientAsync.init_default_client(mock_client)
        assert isinstance(kc, KeycloakHttpClientAsync)
        assert kc.client is mock_client


class TestBuildFullUrl:
    def test_combines_base_url_path_and_query(self):
        mock_client = MagicMock()
        mock_client.base_url = "https://keycloak.example.com"
        kc = KeycloakHttpClientAsync(client=mock_client)
        result = kc.build_full_url("/realms/myrealm/token", "grant_type=password")
        assert result == "https://keycloak.example.com/realms/myrealm/token?grant_type=password"

    def test_empty_query_produces_trailing_question_mark(self):
        mock_client = MagicMock()
        mock_client.base_url = "https://kc.example.com"
        kc = KeycloakHttpClientAsync(client=mock_client)
        result = kc.build_full_url("/path", "")
        assert result == "https://kc.example.com/path?"


class TestRequestAsync:
    @pytest.mark.asyncio
    async def test_calls_client_request_with_correct_method(self):
        mock_client = AsyncMock()
        mock_response = MagicMock()
        mock_client.request = AsyncMock(return_value=mock_response)

        kc = KeycloakHttpClientAsync(client=mock_client)
        result = await kc.request_async(HttpMethod.GET, "https://kc.example.com/path")

        mock_client.request.assert_awaited_once_with(
            method="GET", url="https://kc.example.com/path"
        )
        assert result is mock_response

    @pytest.mark.asyncio
    async def test_raise_exception_calls_raise_for_status(self):
        mock_client = AsyncMock()
        mock_response = MagicMock()
        mock_client.request = AsyncMock(return_value=mock_response)

        kc = KeycloakHttpClientAsync(client=mock_client)
        await kc.request_async(HttpMethod.POST, "/url", raise_exception=True)

        mock_response.raise_for_status.assert_called_once()

    @pytest.mark.asyncio
    async def test_no_raise_exception_skips_raise_for_status(self):
        mock_client = AsyncMock()
        mock_response = MagicMock()
        mock_client.request = AsyncMock(return_value=mock_response)

        kc = KeycloakHttpClientAsync(client=mock_client)
        await kc.request_async(HttpMethod.GET, "/url", raise_exception=False)

        mock_response.raise_for_status.assert_not_called()

    @pytest.mark.asyncio
    async def test_passes_kwargs_to_client_request(self):
        mock_client = AsyncMock()
        mock_response = MagicMock()
        mock_client.request = AsyncMock(return_value=mock_response)

        kc = KeycloakHttpClientAsync(client=mock_client)
        await kc.request_async(
            HttpMethod.POST, "/url", headers={"X-Custom": "value"}, json={"key": "val"}
        )

        mock_client.request.assert_awaited_once_with(
            method="POST", url="/url", headers={"X-Custom": "value"}, json={"key": "val"}
        )


class TestContextManager:
    @pytest.mark.asyncio
    async def test_aenter_returns_self(self):
        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        kc = KeycloakHttpClientAsync(client=mock_client)
        result = await kc.__aenter__()
        assert result is kc

    @pytest.mark.asyncio
    async def test_aexit_delegates_to_client(self):
        mock_client = AsyncMock()
        mock_client.__aexit__ = AsyncMock(return_value=None)
        kc = KeycloakHttpClientAsync(client=mock_client)
        await kc.__aexit__(None, None, None)
        mock_client.__aexit__.assert_awaited_once_with(None, None, None)

    @pytest.mark.asyncio
    async def test_close_async_calls_aclose(self):
        mock_client = AsyncMock()
        kc = KeycloakHttpClientAsync(client=mock_client)
        await kc.close_async()
        mock_client.aclose.assert_awaited_once()