# SPDX-License-Identifier: MIT
from unittest.mock import AsyncMock, MagicMock

import pytest

from pykeycloak.core.clients import HttpMethod
from pykeycloak.providers._users import UsersProvider
from pykeycloak.providers.payloads import (
    CreateUserPayload,
    UpdateUserPayload,
    UserUpdateEnablePayload,
    UserUpdatePasswordPayload,
)
from pykeycloak.providers.queries import GetUsersQuery


@pytest.fixture
def users_provider(base, mock_access_token):
    return UsersProvider(base=base, get_access_token=mock_access_token)


class TestGetUsersCountAsync:
    @pytest.mark.asyncio
    async def test_gets_from_users_count_url(self, users_provider, mock_kc_client):
        mock_kc_client.request_async = AsyncMock(return_value=MagicMock())
        await users_provider.get_users_count_async()

        call_kwargs = mock_kc_client.request_async.call_args.kwargs
        assert call_kwargs["method"] == HttpMethod.GET
        assert "users/count" in call_kwargs["url"]

    @pytest.mark.asyncio
    async def test_passes_query_params(self, users_provider, mock_kc_client):
        mock_kc_client.request_async = AsyncMock(return_value=MagicMock())
        query = GetUsersQuery(max=10)
        await users_provider.get_users_count_async(query=query)

        call_kwargs = mock_kc_client.request_async.call_args.kwargs
        assert call_kwargs["params"] is not None

    @pytest.mark.asyncio
    async def test_no_params_when_no_query(self, users_provider, mock_kc_client):
        mock_kc_client.request_async = AsyncMock(return_value=MagicMock())
        await users_provider.get_users_count_async()

        call_kwargs = mock_kc_client.request_async.call_args.kwargs
        assert call_kwargs["params"] is None


class TestGetUsersAsync:
    @pytest.mark.asyncio
    async def test_gets_from_users_list_url(self, users_provider, mock_kc_client):
        mock_kc_client.request_async = AsyncMock(return_value=MagicMock())
        await users_provider.get_users_async()

        call_kwargs = mock_kc_client.request_async.call_args.kwargs
        assert call_kwargs["method"] == HttpMethod.GET
        assert "users" in call_kwargs["url"]

    @pytest.mark.asyncio
    async def test_uses_default_query_when_none(self, users_provider, mock_kc_client):
        mock_kc_client.request_async = AsyncMock(return_value=MagicMock())
        await users_provider.get_users_async()

        call_kwargs = mock_kc_client.request_async.call_args.kwargs
        assert isinstance(call_kwargs["params"], GetUsersQuery)


class TestGetUserAsync:
    @pytest.mark.asyncio
    async def test_gets_from_user_url_with_id(self, users_provider, mock_kc_client):
        mock_kc_client.request_async = AsyncMock(return_value=MagicMock())
        await users_provider.get_user_async("user-123")

        call_kwargs = mock_kc_client.request_async.call_args.kwargs
        assert call_kwargs["method"] == HttpMethod.GET
        assert "user-123" in call_kwargs["url"]


class TestDeleteUserAsync:
    @pytest.mark.asyncio
    async def test_deletes_user_by_id(self, users_provider, mock_kc_client):
        mock_kc_client.request_async = AsyncMock(return_value=MagicMock())
        await users_provider.delete_user_async("user-123")

        call_kwargs = mock_kc_client.request_async.call_args.kwargs
        assert call_kwargs["method"] == HttpMethod.DELETE
        assert "user-123" in call_kwargs["url"]


class TestCreateUserAsync:
    @pytest.mark.asyncio
    async def test_posts_to_users_url(self, users_provider, mock_kc_client):
        mock_kc_client.request_async = AsyncMock(return_value=MagicMock())
        payload = CreateUserPayload(username="newuser")
        await users_provider.create_user_async(payload)

        call_kwargs = mock_kc_client.request_async.call_args.kwargs
        assert call_kwargs["method"] == HttpMethod.POST
        assert "users" in call_kwargs["url"]

    @pytest.mark.asyncio
    async def test_sends_json_data(self, users_provider, mock_kc_client):
        import json

        mock_kc_client.request_async = AsyncMock(return_value=MagicMock())
        payload = CreateUserPayload(username="newuser")
        await users_provider.create_user_async(payload)

        call_kwargs = mock_kc_client.request_async.call_args.kwargs
        parsed = json.loads(call_kwargs["data"])
        assert parsed["username"] == "newuser"


class TestUpdateUserByIdAsync:
    @pytest.mark.asyncio
    async def test_puts_to_user_url(self, users_provider, mock_kc_client):
        mock_kc_client.request_async = AsyncMock(return_value=MagicMock())
        payload = UpdateUserPayload(email="new@example.com")
        await users_provider.update_user_by_id_async("user-123", payload)

        call_kwargs = mock_kc_client.request_async.call_args.kwargs
        assert call_kwargs["method"] == HttpMethod.PUT
        assert "user-123" in call_kwargs["url"]


class TestUpdateUserEnableByIdAsync:
    @pytest.mark.asyncio
    async def test_puts_to_user_url(self, users_provider, mock_kc_client):
        mock_kc_client.request_async = AsyncMock(return_value=MagicMock())
        payload = UserUpdateEnablePayload(enabled=False)
        await users_provider.update_user_enable_by_id_async("user-123", payload)

        call_kwargs = mock_kc_client.request_async.call_args.kwargs
        assert call_kwargs["method"] == HttpMethod.PUT
        assert "user-123" in call_kwargs["url"]


class TestUpdateUserPasswordByIdAsync:
    @pytest.mark.asyncio
    async def test_puts_to_user_url(self, users_provider, mock_kc_client):
        mock_kc_client.request_async = AsyncMock(return_value=MagicMock())
        payload = UserUpdatePasswordPayload()
        await users_provider.update_user_password_by_id_async("user-123", payload)

        call_kwargs = mock_kc_client.request_async.call_args.kwargs
        assert call_kwargs["method"] == HttpMethod.PUT
        assert "user-123" in call_kwargs["url"]


class TestGetUsersByRoleAsync:
    @pytest.mark.asyncio
    async def test_gets_from_role_members_url(self, users_provider, mock_kc_client):
        mock_kc_client.request_async = AsyncMock(return_value=MagicMock())
        await users_provider.get_users_by_role_async("admin")

        call_kwargs = mock_kc_client.request_async.call_args.kwargs
        assert call_kwargs["method"] == HttpMethod.GET
        assert "admin" in call_kwargs["url"]
