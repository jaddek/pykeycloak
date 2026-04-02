# SPDX-License-Identifier: MIT
from unittest.mock import AsyncMock, MagicMock

import pytest

from pykeycloak.core.clients import HttpMethod
from pykeycloak.providers._authz import (
    AuthzPermissionProvider,
    AuthzPolicyProvider,
    AuthzResourceProvider,
    AuthzScopeProvider,
    AuthzSettingsProvider,
)
from pykeycloak.providers.payloads import (
    PermissionPayload,
    PermissionScopesPayload,
    ResourcePayload,
    RolePolicyPayload,
)
from pykeycloak.providers.queries import FilterFindPolicyParams, FindPermissionQuery, ResourcesListQuery


@pytest.fixture
def authz_settings_provider(base, mock_access_token):
    return AuthzSettingsProvider(base=base, get_access_token=mock_access_token)


@pytest.fixture
def authz_scope_provider(base, mock_access_token):
    return AuthzScopeProvider(base=base, get_access_token=mock_access_token)


@pytest.fixture
def authz_resource_provider(base, mock_access_token):
    return AuthzResourceProvider(base=base, get_access_token=mock_access_token)


@pytest.fixture
def authz_policy_provider(base, mock_access_token):
    return AuthzPolicyProvider(base=base, get_access_token=mock_access_token)


@pytest.fixture
def authz_permission_provider(base, mock_access_token):
    return AuthzPermissionProvider(base=base, get_access_token=mock_access_token)


class TestAuthzSettingsProvider:
    @pytest.mark.asyncio
    async def test_gets_authz_settings(self, authz_settings_provider, mock_kc_client):
        mock_kc_client.request_async = AsyncMock(return_value=MagicMock())
        await authz_settings_provider.get_client_authz_settings()

        call_kwargs = mock_kc_client.request_async.call_args.kwargs
        assert call_kwargs["method"] == HttpMethod.GET
        assert "settings" in call_kwargs["url"]


class TestAuthzScopeProvider:
    @pytest.mark.asyncio
    async def test_gets_authz_scopes(self, authz_scope_provider, mock_kc_client):
        mock_kc_client.request_async = AsyncMock(return_value=MagicMock())
        await authz_scope_provider.get_client_authz_scopes_async()

        call_kwargs = mock_kc_client.request_async.call_args.kwargs
        assert call_kwargs["method"] == HttpMethod.GET
        assert "scope" in call_kwargs["url"]


class TestAuthzResourceProvider:
    @pytest.mark.asyncio
    async def test_gets_resources(self, authz_resource_provider, mock_kc_client):
        mock_kc_client.request_async = AsyncMock(return_value=MagicMock())
        await authz_resource_provider.get_resources_async()

        call_kwargs = mock_kc_client.request_async.call_args.kwargs
        assert call_kwargs["method"] == HttpMethod.GET
        assert "resource" in call_kwargs["url"]

    @pytest.mark.asyncio
    async def test_gets_resources_with_query(self, authz_resource_provider, mock_kc_client):
        mock_kc_client.request_async = AsyncMock(return_value=MagicMock())
        query = ResourcesListQuery(max=5)
        await authz_resource_provider.get_resources_async(query=query)

        call_kwargs = mock_kc_client.request_async.call_args.kwargs
        assert call_kwargs["params"] is not None

    @pytest.mark.asyncio
    async def test_creates_resource(self, authz_resource_provider, mock_kc_client):
        mock_kc_client.request_async = AsyncMock(return_value=MagicMock())
        payload = ResourcePayload(id="res-id", name="my-resource")
        await authz_resource_provider.create_resource_async(payload)

        call_kwargs = mock_kc_client.request_async.call_args.kwargs
        assert call_kwargs["method"] == HttpMethod.POST
        assert "resource" in call_kwargs["url"]

    @pytest.mark.asyncio
    async def test_gets_resource_by_id(self, authz_resource_provider, mock_kc_client):
        mock_kc_client.request_async = AsyncMock(return_value=MagicMock())
        await authz_resource_provider.get_resource_by_id_async("res-123")

        call_kwargs = mock_kc_client.request_async.call_args.kwargs
        assert call_kwargs["method"] == HttpMethod.GET
        assert "res-123" in call_kwargs["url"]

    @pytest.mark.asyncio
    async def test_deletes_resource_by_id(self, authz_resource_provider, mock_kc_client):
        mock_kc_client.request_async = AsyncMock(return_value=MagicMock())
        await authz_resource_provider.delete_resource_by_id_async("res-123")

        call_kwargs = mock_kc_client.request_async.call_args.kwargs
        assert call_kwargs["method"] == HttpMethod.DELETE
        assert "res-123" in call_kwargs["url"]

    @pytest.mark.asyncio
    async def test_gets_resource_permissions(self, authz_resource_provider, mock_kc_client):
        mock_kc_client.request_async = AsyncMock(return_value=MagicMock())
        await authz_resource_provider.get_resource_permissions_async("res-123")

        call_kwargs = mock_kc_client.request_async.call_args.kwargs
        assert call_kwargs["method"] == HttpMethod.GET
        assert "res-123" in call_kwargs["url"]
        assert "permissions" in call_kwargs["url"]


class TestAuthzPolicyProvider:
    @pytest.mark.asyncio
    async def test_creates_role_policy(self, authz_policy_provider, mock_kc_client):
        mock_kc_client.request_async = AsyncMock(return_value=MagicMock())
        payload = RolePolicyPayload(name="my-policy")
        await authz_policy_provider.create_policy_role_async(payload)

        call_kwargs = mock_kc_client.request_async.call_args.kwargs
        assert call_kwargs["method"] == HttpMethod.POST
        assert "role" in call_kwargs["url"]

    @pytest.mark.asyncio
    async def test_deletes_policy(self, authz_policy_provider, mock_kc_client):
        mock_kc_client.request_async = AsyncMock(return_value=MagicMock())
        await authz_policy_provider.delete_policy_async("policy-123")

        call_kwargs = mock_kc_client.request_async.call_args.kwargs
        assert call_kwargs["method"] == HttpMethod.DELETE
        assert "policy-123" in call_kwargs["url"]

    @pytest.mark.asyncio
    async def test_creates_policy(self, authz_policy_provider, mock_kc_client):
        mock_kc_client.request_async = AsyncMock(return_value=MagicMock())
        payload = PermissionPayload(name="my-perm")
        await authz_policy_provider.create_policy_async(payload)

        call_kwargs = mock_kc_client.request_async.call_args.kwargs
        assert call_kwargs["method"] == HttpMethod.POST

    @pytest.mark.asyncio
    async def test_gets_policy_by_name(self, authz_policy_provider, mock_kc_client):
        mock_kc_client.request_async = AsyncMock(return_value=MagicMock())
        query = FilterFindPolicyParams(name="my-policy")
        await authz_policy_provider.get_policy_by_name_async(query)

        call_kwargs = mock_kc_client.request_async.call_args.kwargs
        assert call_kwargs["method"] == HttpMethod.GET
        assert "search" in call_kwargs["url"]

    @pytest.mark.asyncio
    async def test_gets_associated_roles(self, authz_policy_provider, mock_kc_client):
        mock_kc_client.request_async = AsyncMock(return_value=MagicMock())
        await authz_policy_provider.get_associated_roles_async("policy-123")

        call_kwargs = mock_kc_client.request_async.call_args.kwargs
        assert call_kwargs["method"] == HttpMethod.GET
        assert "policy-123" in call_kwargs["url"]

    @pytest.mark.asyncio
    async def test_gets_policy_authorisation_scopes(self, authz_policy_provider, mock_kc_client):
        mock_kc_client.request_async = AsyncMock(return_value=MagicMock())
        await authz_policy_provider.get_policy_authorisation_scopes_async("policy-123")

        call_kwargs = mock_kc_client.request_async.call_args.kwargs
        assert call_kwargs["method"] == HttpMethod.GET
        assert "policy-123" in call_kwargs["url"]
        assert "scopes" in call_kwargs["url"]

    @pytest.mark.asyncio
    async def test_gets_all_policies(self, authz_policy_provider, mock_kc_client):
        mock_kc_client.request_async = AsyncMock(return_value=MagicMock())
        await authz_policy_provider.get_policies_async()

        call_kwargs = mock_kc_client.request_async.call_args.kwargs
        assert call_kwargs["method"] == HttpMethod.GET
        assert "policy" in call_kwargs["url"]


class TestAuthzPermissionProvider:
    @pytest.mark.asyncio
    async def test_creates_permission_based_on_resource(
        self, authz_permission_provider, mock_kc_client
    ):
        mock_kc_client.request_async = AsyncMock(return_value=MagicMock())
        payload = PermissionPayload(name="perm")
        await authz_permission_provider.create_client_authz_permission_based_on_resource_async(
            payload
        )

        call_kwargs = mock_kc_client.request_async.call_args.kwargs
        assert call_kwargs["method"] == HttpMethod.POST
        assert "resource" in call_kwargs["url"]

    @pytest.mark.asyncio
    async def test_creates_permission_based_on_scope(
        self, authz_permission_provider, mock_kc_client
    ):
        mock_kc_client.request_async = AsyncMock(return_value=MagicMock())
        payload = PermissionPayload(name="perm")
        await authz_permission_provider.create_client_authz_permission_based_on_scope_async(
            payload
        )

        call_kwargs = mock_kc_client.request_async.call_args.kwargs
        assert call_kwargs["method"] == HttpMethod.POST
        assert "scope" in call_kwargs["url"]

    @pytest.mark.asyncio
    async def test_gets_permissions(self, authz_permission_provider, mock_kc_client):
        mock_kc_client.request_async = AsyncMock(return_value=MagicMock())
        await authz_permission_provider.get_permissions_async()

        call_kwargs = mock_kc_client.request_async.call_args.kwargs
        assert call_kwargs["method"] == HttpMethod.GET
        assert "permission" in call_kwargs["url"]

    @pytest.mark.asyncio
    async def test_gets_permission_with_query(self, authz_permission_provider, mock_kc_client):
        mock_kc_client.request_async = AsyncMock(return_value=MagicMock())
        query = FindPermissionQuery(name="my-perm")
        await authz_permission_provider.get_permissions_async(query=query)

        call_kwargs = mock_kc_client.request_async.call_args.kwargs
        assert call_kwargs["params"] is not None

    @pytest.mark.asyncio
    async def test_gets_permission_by_scope_id(self, authz_permission_provider, mock_kc_client):
        mock_kc_client.request_async = AsyncMock(return_value=MagicMock())
        await authz_permission_provider.get_permission_based_on_scope_by_id_async("perm-123")

        call_kwargs = mock_kc_client.request_async.call_args.kwargs
        assert call_kwargs["method"] == HttpMethod.GET
        assert "perm-123" in call_kwargs["url"]
        assert "scope" in call_kwargs["url"]

    @pytest.mark.asyncio
    async def test_gets_permission_by_resource_id(self, authz_permission_provider, mock_kc_client):
        mock_kc_client.request_async = AsyncMock(return_value=MagicMock())
        await authz_permission_provider.get_permission_based_on_resource_by_id_async("perm-123")

        call_kwargs = mock_kc_client.request_async.call_args.kwargs
        assert call_kwargs["method"] == HttpMethod.GET
        assert "perm-123" in call_kwargs["url"]
        assert "resource" in call_kwargs["url"]

    @pytest.mark.asyncio
    async def test_deletes_permission(self, authz_permission_provider, mock_kc_client):
        mock_kc_client.request_async = AsyncMock(return_value=MagicMock())
        await authz_permission_provider.delete_permission_async("perm-123")

        call_kwargs = mock_kc_client.request_async.call_args.kwargs
        assert call_kwargs["method"] == HttpMethod.DELETE
        assert "perm-123" in call_kwargs["url"]

    @pytest.mark.asyncio
    async def test_updates_permission_scopes(self, authz_permission_provider, mock_kc_client):
        mock_kc_client.request_async = AsyncMock(return_value=MagicMock())
        payload = PermissionScopesPayload(name="perm", policies=["p1"])
        await authz_permission_provider.update_permission_scopes_async("perm-123", payload)

        call_kwargs = mock_kc_client.request_async.call_args.kwargs
        assert call_kwargs["method"] == HttpMethod.PUT
        assert "perm-123" in call_kwargs["url"]
        assert "scope" in call_kwargs["url"]
