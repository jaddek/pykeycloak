# SPDX-License-Identifier: MIT
from unittest.mock import AsyncMock, MagicMock

import pytest

from pykeycloak.core.clients import HttpMethod
from pykeycloak.core.headers import HeadersFactory
from pykeycloak.core.realm import RealmClient
from pykeycloak.providers._base import KeycloakProviderBase

VALID_UUID = "550e8400-e29b-41d4-a716-446655440000"


@pytest.fixture
def realm_client():
    return RealmClient(
        realm_name="myrealm",
        client_uuid=VALID_UUID,
        client_id="my-client",
        client_secret="my-secret",
    )


@pytest.fixture
def mock_kc_client():
    client = MagicMock()
    client.base_url = "https://keycloak.example.com"
    client.request_async = AsyncMock(return_value=MagicMock())
    client.build_full_url = MagicMock(return_value="https://keycloak.example.com/path?q")
    return client


@pytest.fixture
def base(realm_client, mock_kc_client):
    return KeycloakProviderBase(
        realm_client=realm_client,
        kc_headers=HeadersFactory(),
        kc_client=mock_kc_client,
    )


class TestKeycloakProviderBaseInit:
    def test_realm_client_property(self, base, realm_client):
        assert base.realm_client is realm_client

    def test_stores_all_dependencies(self, realm_client, mock_kc_client):
        headers = HeadersFactory()
        b = KeycloakProviderBase(
            realm_client=realm_client,
            kc_headers=headers,
            kc_client=mock_kc_client,
        )
        assert b._realm_client is realm_client
        assert b._kc_headers is headers
        assert b._kc_client is mock_kc_client


class TestBuildUrl:
    def test_inserts_realm_and_client_id(self, base):
        url = base.build_url("/realms/{realm}/clients/{client_id}")
        assert "myrealm" in url
        assert "my-client" in url

    def test_inserts_client_uuid(self, base):
        url = base.build_url("/realms/{realm}/clients/{client_uuid}")
        assert VALID_UUID in url

    def test_extra_kwargs_substituted(self, base):
        url = base.build_url("/users/{user_id}", user_id="user-123")
        assert "user-123" in url

    def test_extra_kwargs_cast_to_str(self, base):
        from uuid import UUID

        url = base.build_url("/sessions/{session_id}", session_id=UUID(VALID_UUID))
        assert VALID_UUID in url


class TestHeaders:
    def test_bearer_headers_returns_authorization(self, base):
        headers = base.bearer_headers("mytoken")
        assert headers["Authorization"] == "Bearer mytoken"
        assert headers["Content-Type"] == "application/json"

    def test_openid_basic_headers(self, base):
        headers = base.openid_basic_headers("basictoken")
        assert headers["Authorization"] == "Basic basictoken"
        assert headers["Content-Type"] == "application/x-www-form-urlencoded"

    def test_openid_bearer_headers(self, base):
        headers = base.openid_bearer_headers("bearertoken")
        assert headers["Authorization"] == "Bearer bearertoken"
        assert headers["Content-Type"] == "application/x-www-form-urlencoded"


class TestRequestAsync:
    @pytest.mark.asyncio
    async def test_delegates_to_kc_client(self, base, mock_kc_client):
        mock_response = MagicMock()
        mock_kc_client.request_async = AsyncMock(return_value=mock_response)

        result = await base.request_async(
            method=HttpMethod.GET,
            url="/test",
            headers={"Authorization": "Bearer tok"},
        )

        mock_kc_client.request_async.assert_awaited_once_with(
            method=HttpMethod.GET,
            url="/test",
            headers={"Authorization": "Bearer tok"},
        )
        assert result is mock_response


class TestBuildFullUrl:
    def test_delegates_to_kc_client(self, base, mock_kc_client):
        mock_kc_client.build_full_url = MagicMock(return_value="https://kc.com/path?q=1")
        result = base.build_full_url(path="/path", query="q=1")
        mock_kc_client.build_full_url.assert_called_once_with(path="/path", query="q=1")
        assert result == "https://kc.com/path?q=1"


class TestCloseConnection:
    @pytest.mark.asyncio
    async def test_calls_aclose_on_client(self, base, mock_kc_client):
        mock_kc_client.client = AsyncMock()
        await base.close_connection()
        mock_kc_client.client.aclose.assert_awaited_once()
