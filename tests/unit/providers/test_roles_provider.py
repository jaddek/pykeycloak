# SPDX-License-Identifier: MIT
from unittest.mock import AsyncMock, MagicMock

import pytest

from pykeycloak.core.clients import HttpMethod
from pykeycloak.core.exceptions import KeycloakUnexpectedBehaviourException
from pykeycloak.providers._roles import RolesProvider
from pykeycloak.providers.payloads import RoleAssignPayload, RolePayload
from pykeycloak.providers.queries import BriefRepresentationQuery


@pytest.fixture
def roles_provider(base, mock_access_token):
    return RolesProvider(base=base, get_access_token=mock_access_token)


class TestGetClientRolesAsync:
    @pytest.mark.asyncio
    async def test_gets_from_roles_url(self, roles_provider, mock_kc_client):
        mock_kc_client.request_async = AsyncMock(return_value=MagicMock())
        await roles_provider.get_client_roles_async()

        call_kwargs = mock_kc_client.request_async.call_args.kwargs
        assert call_kwargs["method"] == HttpMethod.GET
        assert "roles" in call_kwargs["url"]


class TestGetRoleByNameAsync:
    @pytest.mark.asyncio
    async def test_url_contains_role_name(self, roles_provider, mock_kc_client):
        mock_kc_client.request_async = AsyncMock(return_value=MagicMock())
        await roles_provider.get_role_by_name_async("admin")

        call_kwargs = mock_kc_client.request_async.call_args.kwargs
        assert call_kwargs["method"] == HttpMethod.GET
        assert "admin" in call_kwargs["url"]


class TestCreateRoleAsync:
    @pytest.mark.asyncio
    async def test_posts_to_roles_url(self, roles_provider, mock_kc_client):
        mock_kc_client.request_async = AsyncMock(return_value=MagicMock())
        payload = RolePayload(name="new-role")
        await roles_provider.create_role_async(payload)

        call_kwargs = mock_kc_client.request_async.call_args.kwargs
        assert call_kwargs["method"] == HttpMethod.POST
        assert "roles" in call_kwargs["url"]


class TestUpdateRoleByIdAsync:
    @pytest.mark.asyncio
    async def test_raises_unexpected_behaviour_by_default(self, roles_provider):
        with pytest.raises(KeycloakUnexpectedBehaviourException):
            await roles_provider.update_role_by_id_async(
                role_id="some-id", payload=RolePayload(name="role")
            )

    @pytest.mark.asyncio
    async def test_puts_when_flag_skipped(self, roles_provider, mock_kc_client):
        mock_kc_client.request_async = AsyncMock(return_value=MagicMock())
        await roles_provider.update_role_by_id_async(
            role_id="some-id",
            payload=RolePayload(name="role"),
            skip_unexpected_behaviour_exception=True,
        )

        call_kwargs = mock_kc_client.request_async.call_args.kwargs
        assert call_kwargs["method"] == HttpMethod.PUT
        assert "some-id" in call_kwargs["url"]


class TestUpdateRoleByNameAsync:
    @pytest.mark.asyncio
    async def test_puts_to_role_url(self, roles_provider, mock_kc_client):
        mock_kc_client.request_async = AsyncMock(return_value=MagicMock())
        await roles_provider.update_role_by_name_async("admin", RolePayload(name="admin"))

        call_kwargs = mock_kc_client.request_async.call_args.kwargs
        assert call_kwargs["method"] == HttpMethod.PUT
        assert "admin" in call_kwargs["url"]


class TestDeleteRoleByIdAsync:
    @pytest.mark.asyncio
    async def test_deletes_by_role_id(self, roles_provider, mock_kc_client):
        mock_kc_client.request_async = AsyncMock(return_value=MagicMock())
        await roles_provider.delete_role_by_id_async("role-uuid")

        call_kwargs = mock_kc_client.request_async.call_args.kwargs
        assert call_kwargs["method"] == HttpMethod.DELETE
        assert "role-uuid" in call_kwargs["url"]


class TestDeleteRoleByNameAsync:
    @pytest.mark.asyncio
    async def test_deletes_by_role_name(self, roles_provider, mock_kc_client):
        mock_kc_client.request_async = AsyncMock(return_value=MagicMock())
        await roles_provider.delete_role_by_name_async("admin")

        call_kwargs = mock_kc_client.request_async.call_args.kwargs
        assert call_kwargs["method"] == HttpMethod.DELETE
        assert "admin" in call_kwargs["url"]


class TestAssignRoleAsync:
    @pytest.mark.asyncio
    async def test_posts_roles_for_user(self, roles_provider, mock_kc_client):
        mock_kc_client.request_async = AsyncMock(return_value=MagicMock())
        roles = [RoleAssignPayload(id="r1", name="admin")]
        await roles_provider.assign_role_async("user-123", roles)

        call_kwargs = mock_kc_client.request_async.call_args.kwargs
        assert call_kwargs["method"] == HttpMethod.POST
        assert "user-123" in call_kwargs["url"]
        assert call_kwargs["json"] == [{"id": "r1", "name": "admin"}]


class TestUnassignRoleAsync:
    @pytest.mark.asyncio
    async def test_deletes_roles_for_user(self, roles_provider, mock_kc_client):
        mock_kc_client.request_async = AsyncMock(return_value=MagicMock())
        roles = [RoleAssignPayload(id="r1", name="admin")]
        await roles_provider.unassign_role_async("user-123", roles)

        call_kwargs = mock_kc_client.request_async.call_args.kwargs
        assert call_kwargs["method"] == HttpMethod.DELETE
        assert "user-123" in call_kwargs["url"]
        assert call_kwargs["json"] == [{"id": "r1", "name": "admin"}]


class TestGetClientRolesOfUserAsync:
    @pytest.mark.asyncio
    async def test_gets_roles_for_user(self, roles_provider, mock_kc_client):
        mock_kc_client.request_async = AsyncMock(return_value=MagicMock())
        await roles_provider.get_client_roles_of_user_async("user-123")

        call_kwargs = mock_kc_client.request_async.call_args.kwargs
        assert call_kwargs["method"] == HttpMethod.GET
        assert "user-123" in call_kwargs["url"]


class TestGetCompositeClientRolesOfUserAsync:
    @pytest.mark.asyncio
    async def test_gets_composite_roles(self, roles_provider, mock_kc_client):
        mock_kc_client.request_async = AsyncMock(return_value=MagicMock())
        await roles_provider.get_composite_client_roles_of_user_async("user-123")

        call_kwargs = mock_kc_client.request_async.call_args.kwargs
        assert call_kwargs["method"] == HttpMethod.GET
        assert "user-123" in call_kwargs["url"]
        assert "composite" in call_kwargs["url"]

    @pytest.mark.asyncio
    async def test_passes_brief_representation_query(self, roles_provider, mock_kc_client):
        mock_kc_client.request_async = AsyncMock(return_value=MagicMock())
        query = BriefRepresentationQuery(brief_representation=True)
        await roles_provider.get_composite_client_roles_of_user_async("user-123", query)

        call_kwargs = mock_kc_client.request_async.call_args.kwargs
        assert call_kwargs["params"] is query


class TestGetAvailableClientRolesOfUserAsync:
    @pytest.mark.asyncio
    async def test_url_contains_available(self, roles_provider, mock_kc_client):
        mock_kc_client.request_async = AsyncMock(return_value=MagicMock())
        await roles_provider.get_available_client_roles_of_user_async("user-123")

        call_kwargs = mock_kc_client.request_async.call_args.kwargs
        assert "available" in call_kwargs["url"]
        assert "user-123" in call_kwargs["url"]


class TestGetUserRolesAsync:
    @pytest.mark.asyncio
    async def test_gets_user_roles(self, roles_provider, mock_kc_client):
        mock_kc_client.request_async = AsyncMock(return_value=MagicMock())
        await roles_provider.get_user_roles_async("user-123")

        call_kwargs = mock_kc_client.request_async.call_args.kwargs
        assert call_kwargs["method"] == HttpMethod.GET
        assert "user-123" in call_kwargs["url"]
