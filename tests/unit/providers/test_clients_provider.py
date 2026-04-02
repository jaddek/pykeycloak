# SPDX-License-Identifier: MIT
from unittest.mock import AsyncMock, MagicMock

import pytest

from pykeycloak.core.clients import HttpMethod
from pykeycloak.providers._clients import ClientsProvider


@pytest.fixture
def clients_provider(base, mock_access_token):
    return ClientsProvider(base=base, get_access_token=mock_access_token)


class TestGetClientsAsync:
    @pytest.mark.asyncio
    async def test_gets_from_clients_url(self, clients_provider, mock_kc_client):
        mock_kc_client.request_async = AsyncMock(return_value=MagicMock())
        await clients_provider.get_clients_async()

        call_kwargs = mock_kc_client.request_async.call_args.kwargs
        assert call_kwargs["method"] == HttpMethod.GET
        assert "clients" in call_kwargs["url"]

    @pytest.mark.asyncio
    async def test_uses_bearer_auth(self, clients_provider, mock_kc_client):
        mock_kc_client.request_async = AsyncMock(return_value=MagicMock())
        await clients_provider.get_clients_async()

        call_kwargs = mock_kc_client.request_async.call_args.kwargs
        assert call_kwargs["headers"]["Authorization"].startswith("Bearer ")


class TestGetClientAsync:
    @pytest.mark.asyncio
    async def test_gets_specific_client(self, clients_provider, mock_kc_client):
        mock_kc_client.request_async = AsyncMock(return_value=MagicMock())
        await clients_provider.get_client_async()

        call_kwargs = mock_kc_client.request_async.call_args.kwargs
        assert call_kwargs["method"] == HttpMethod.GET
        assert "clients" in call_kwargs["url"]

    @pytest.mark.asyncio
    async def test_url_contains_client_uuid(self, clients_provider, mock_kc_client):
        mock_kc_client.request_async = AsyncMock(return_value=MagicMock())
        await clients_provider.get_client_async()

        call_kwargs = mock_kc_client.request_async.call_args.kwargs
        assert "550e8400-e29b-41d4-a716-446655440000" in call_kwargs["url"]
