"""
Detailed unit tests for the providers module to increase coverage.
"""

import uuid
from unittest.mock import AsyncMock, MagicMock

import pytest
from httpx import Response

from pykeycloak.core.clients import HttpMethod
from pykeycloak.core.realm import RealmClient
from pykeycloak.providers.payloads import (
    ConfidentialClientRevokePayload,
    CreateUserPayload,
    PublicClientRevokePayload,
    RefreshTokenPayload,
    RTPExchangeTokenPayload,
    RTPIntrospectionPayload,
    TokenIntrospectionPayload,
    UMAAuthorizationPayload,
    UserUpdateEnablePayload,
    UserUpdatePasswordPayload,
)
from pykeycloak.providers.providers import (
    KeycloakProviderAsync,
)
from pykeycloak.providers.queries import (
    BriefRepresentationQuery,
    GetUsersQuery,
    PaginationQuery,
    RoleMembersListQuery,
)


class TestKeycloakProviderAsyncDetailed:
    """Detailed test cases for the KeycloakProviderAsync class."""

    @pytest.fixture
    def mock_realm_client(self):
        """Fixture to create a mock realm client."""
        mock = MagicMock(spec=RealmClient)
        mock.is_confidential = True
        mock.client_id = "test_client"  # noqa: S106 S105
        mock.client_secret = "test_secret"  # noqa: S106 S105
        mock.base64_auth.return_value = "test_auth"  # noqa: S106 S105
        return mock

    @pytest.fixture
    def mock_wrapper(self):
        """Fixture to create a mock HTTP wrapper."""
        mock = AsyncMock()
        mock.request = AsyncMock(return_value=Response(status_code=200))
        return mock

    @pytest.fixture
    def provider(self, mock_realm_client, mock_wrapper):
        """Fixture to create a KeycloakProviderAsync instance."""
        return KeycloakProviderAsync(
            realm="test_realm", realm_client=mock_realm_client, wrapper=mock_wrapper
        )

    @pytest.mark.asyncio
    async def test_refresh_token_with_refresh_payload(self, provider, mock_wrapper):
        """Test refresh_token_async with RefreshTokenPayload."""
        payload = RefreshTokenPayload(refresh_token="test_refresh_token")  # noqa: S106
        await provider.refresh_token_async(payload)

        mock_wrapper.request.assert_called_once()
        args, kwargs = mock_wrapper.request.call_args
        assert kwargs["method"] == HttpMethod.POST
        assert "/protocol/openid-connect/token" in kwargs["url"]
        assert kwargs["data"] == payload.to_dict()

    @pytest.mark.asyncio
    async def test_refresh_token_with_rtp_exchange_payload(
        self, provider, mock_wrapper
    ):
        """Test refresh_token_async with RTPExchangeTokenPayload."""
        payload = RTPExchangeTokenPayload(
            refresh_token="test_refresh_token"  # noqa: S106 S105
        )
        await provider.refresh_token_async(payload)

        mock_wrapper.request.assert_called_once()
        args, kwargs = mock_wrapper.request.call_args
        assert kwargs["method"] == HttpMethod.POST
        assert "/protocol/openid-connect/token" in kwargs["url"]
        assert kwargs["data"] == payload.to_dict()

    @pytest.mark.asyncio
    async def test_refresh_token_with_invalid_payload_type(self, provider):
        """Test refresh_token_async with invalid payload type raises TypeError."""
        with pytest.raises(TypeError, match="Unsupported payload type"):
            await provider.refresh_token_async(
                payload=RefreshTokenPayload(
                    refresh_token="test_refresh_token"  # noqa: S106 S105
                )
            )

    @pytest.mark.asyncio
    async def test_refresh_token_non_confidential_client_raises_error(
        self, mock_realm_client, mock_wrapper
    ):
        """Test refresh_token_async raises ValueError for non-confidential clients."""
        mock_realm_client.is_confidential = False

        provider = KeycloakProviderAsync(
            realm="test_realm", realm_client=mock_realm_client, wrapper=mock_wrapper
        )

        payload = RefreshTokenPayload(refresh_token="test_refresh_token")  # noqa: S106
        with pytest.raises(
            ValueError,
            match="Introspection could be invoked only by confidential clients",
        ):
            await provider.refresh_token_async(payload)

    @pytest.mark.asyncio
    async def test_obtain_token_async(self, provider, mock_wrapper):
        """Test obtain_token_async method."""
        from pykeycloak.providers.payloads import ClientCredentialsLoginPayload

        payload = ClientCredentialsLoginPayload()
        await provider.obtain_token_async(payload=payload)

        mock_wrapper.request.assert_called_once()
        args, kwargs = mock_wrapper.request.call_args
        assert kwargs["method"] == HttpMethod.POST
        assert "/protocol/openid-connect/token" in kwargs["url"]
        assert kwargs["data"] == payload.to_dict()

    @pytest.mark.asyncio
    async def test_introspect_token_with_rtp_payload(self, provider, mock_wrapper):
        """Test introspect_token_async with RTPIntrospectionPayload."""
        payload = RTPIntrospectionPayload(token="test_token")  # noqa: S106
        await provider.introspect_token_async(payload)

        mock_wrapper.request.assert_called_once()
        args, kwargs = mock_wrapper.request.call_args
        assert kwargs["method"] == HttpMethod.POST
        assert "/protocol/openid-connect/token/introspect" in kwargs["url"]
        assert kwargs["data"] == payload

    @pytest.mark.asyncio
    async def test_introspect_token_with_regular_payload(self, provider, mock_wrapper):
        """Test introspect_token_async with TokenIntrospectionPayload."""
        payload = TokenIntrospectionPayload(token="test_token")  # noqa: S106
        await provider.introspect_token_async(payload)

        mock_wrapper.request.assert_called_once()
        args, kwargs = mock_wrapper.request.call_args
        assert kwargs["method"] == HttpMethod.POST
        assert "/protocol/openid-connect/token/introspect" in kwargs["url"]
        assert kwargs["data"] == payload

    @pytest.mark.asyncio
    async def test_introspect_token_with_invalid_payload_type(self, provider):
        """Test introspect_token_async with invalid payload type raises TypeError."""
        with pytest.raises(TypeError, match="Unsupported payload type"):
            await provider.introspect_token_async(
                payload=TokenIntrospectionPayload(token="test_token")  # noqa: S106 S105
            )

    @pytest.mark.asyncio
    async def test_introspect_token_non_confidential_client_raises_error(
        self, mock_realm_client, mock_wrapper
    ):
        """Test introspect_token_async raises ValueError for non-confidential clients."""
        mock_realm_client.is_confidential = False

        provider = KeycloakProviderAsync(
            realm="test_realm", realm_client=mock_realm_client, wrapper=mock_wrapper
        )

        payload = TokenIntrospectionPayload(token="test_token")  # noqa: S106
        with pytest.raises(
            ValueError,
            match="Introspection could be invoked only by confidential clients",
        ):
            await provider.introspect_token_async(payload)

    @pytest.mark.asyncio
    async def test_get_certs_async(self, provider, mock_wrapper):
        """Test get_certs_async method."""
        await provider.get_certs_async(access_token="test_token")  # noqa: S106

        mock_wrapper.request.assert_called_once()
        args, kwargs = mock_wrapper.request.call_args
        assert kwargs["method"] == HttpMethod.GET
        assert "/protocol/openid-connect/certs" in kwargs["url"]

    @pytest.mark.asyncio
    async def test_logout_async_confidential_client(
        self, provider, mock_wrapper, mock_realm_client
    ):
        """Test logout_async method for confidential client."""
        mock_realm_client.is_confidential = True

        await provider.logout_async(refresh_token="test_refresh_token")  # noqa: S106

        mock_wrapper.request.assert_called_once()
        args, kwargs = mock_wrapper.request.call_args
        assert kwargs["method"] == HttpMethod.POST
        assert "/protocol/openid-connect/logout" in kwargs["url"]
        assert (
            kwargs["data"]["refresh_token"] == "test_refresh_token"  # noqa: S106 S105
        )
        assert kwargs["data"]["client_secret"] == "test_secret"  # noqa: S106 S105

    @pytest.mark.asyncio
    async def test_logout_async_public_client(self, mock_realm_client, mock_wrapper):
        """Test logout_async method for public client."""
        mock_realm_client.is_confidential = False

        provider = KeycloakProviderAsync(
            realm="test_realm", realm_client=mock_realm_client, wrapper=mock_wrapper
        )

        await provider.logout_async(refresh_token="test_refresh_token")  # noqa: S106

        mock_wrapper.request.assert_called_once()
        args, kwargs = mock_wrapper.request.call_args
        assert kwargs["method"] == HttpMethod.POST
        assert "/protocol/openid-connect/logout" in kwargs["url"]
        assert (
            kwargs["data"]["refresh_token"] == "test_refresh_token"  # noqa: S106 S105
        )
        assert "client_secret" not in kwargs["data"]

    @pytest.mark.asyncio
    async def test_revoke_async_confidential_client(
        self, provider, mock_wrapper, mock_realm_client
    ):
        """Test revoke_async method for confidential client."""
        mock_realm_client.is_confidential = True

        await provider.revoke_async(refresh_token="test_refresh_token")  # noqa: S106

        mock_wrapper.request.assert_called_once()
        args, kwargs = mock_wrapper.request.call_args
        assert kwargs["method"] == HttpMethod.POST
        assert "/protocol/openid-connect/revoke" in kwargs["url"]
        assert isinstance(kwargs["data"], ConfidentialClientRevokePayload)

    @pytest.mark.asyncio
    async def test_revoke_async_public_client(self, mock_realm_client, mock_wrapper):
        """Test revoke_async method for public client."""
        mock_realm_client.is_confidential = False

        provider = KeycloakProviderAsync(
            realm="test_realm", realm_client=mock_realm_client, wrapper=mock_wrapper
        )

        await provider.revoke_async(refresh_token="test_refresh_token")  # noqa: S106

        mock_wrapper.request.assert_called_once()
        args, kwargs = mock_wrapper.request.call_args
        assert kwargs["method"] == HttpMethod.POST
        assert "/protocol/openid-connect/revoke" in kwargs["url"]
        assert isinstance(kwargs["data"], PublicClientRevokePayload)

    @pytest.mark.asyncio
    async def test_get_user_info_async(self, provider, mock_wrapper):
        """Test get_user_info_async method."""
        await provider.get_user_info_async(access_token="test_token")  # noqa: S106

        mock_wrapper.request.assert_called_once()
        args, kwargs = mock_wrapper.request.call_args
        assert kwargs["method"] == HttpMethod.GET
        assert "/protocol/openid-connect/userinfo" in kwargs["url"]

    @pytest.mark.asyncio
    async def test_get_uma_permission_async(self, provider, mock_wrapper):
        """Test get_uma_permission_async method."""
        payload = UMAAuthorizationPayload(
            audience="test_audience",
            permissions={"resource_id": ["permission1", "permission2"]},
            subject_token="test_subject_token",  # noqa: S106
        )
        await provider.get_uma_permission_async(payload)

        mock_wrapper.request.assert_called_once()
        args, kwargs = mock_wrapper.request.call_args
        assert kwargs["method"] == HttpMethod.POST
        assert "/protocol/openid-connect/token" in kwargs["url"]
        assert kwargs["data"] == payload.to_dict()

    @pytest.mark.asyncio
    async def test_get_users_count_async(self, provider, mock_wrapper):
        """Test get_users_count_async method."""
        query = GetUsersQuery(first=0, max=10)
        await provider.get_users_count_async(
            query=query, access_token="test_token"  # noqa: S106
        )

        mock_wrapper.request.assert_called_once()
        args, kwargs = mock_wrapper.request.call_args
        assert kwargs["method"] == HttpMethod.GET
        assert "/admin/realms/test_realm/users/count" in kwargs["url"]

    @pytest.mark.asyncio
    async def test_get_users_async(self, provider, mock_wrapper):
        """Test get_users_async method."""
        query = GetUsersQuery(first=0, max=10)
        await provider.get_users_async(
            query=query, access_token="test_token"  # noqa: S106
        )

        mock_wrapper.request.assert_called_once()
        args, kwargs = mock_wrapper.request.call_args
        assert kwargs["method"] == HttpMethod.GET
        assert "/admin/realms/test_realm/users" in kwargs["url"]

    @pytest.mark.asyncio
    async def test_get_user_async(self, provider, mock_wrapper):
        """Test get_user_async method."""
        await provider.get_user_async(
            user_id=uuid.uuid4(), access_token="test_token"  # noqa: S106
        )

        mock_wrapper.request.assert_called_once()
        args, kwargs = mock_wrapper.request.call_args
        assert kwargs["method"] == HttpMethod.GET
        assert "/admin/realms/test_realm/users/test_user_id" in kwargs["url"]

    @pytest.mark.asyncio
    async def test_create_user_async(self, provider, mock_wrapper):
        """Test create_user_async method."""
        payload = CreateUserPayload(
            username="test_user", email="test@example.com", enabled=True
        )
        await provider.create_user_async(
            payload=payload, access_token="test_token"  # noqa: S106
        )

        mock_wrapper.request.assert_called_once()
        args, kwargs = mock_wrapper.request.call_args
        assert kwargs["method"] == HttpMethod.POST
        assert "/admin/realms/test_realm/users" in kwargs["url"]
        assert kwargs["data"] == payload

    @pytest.mark.asyncio
    async def test_update_user_by_id_async(self, provider, mock_wrapper):
        """Test update_user_by_id_async method."""
        payload = CreateUserPayload(
            username="updated_user", email="updated@example.com", enabled=True
        )
        await provider.update_user_by_id_async(
            user_id=uuid.uuid4(),
            payload=payload,
            access_token="test_token",  # noqa: S106
        )

        mock_wrapper.request.assert_called_once()
        args, kwargs = mock_wrapper.request.call_args
        assert kwargs["method"] == HttpMethod.PUT
        assert "/admin/realms/test_realm/users/test_user_id" in kwargs["url"]
        assert kwargs["data"] == payload

    @pytest.mark.asyncio
    async def test_update_user_enable_by_id_async(self, provider, mock_wrapper):
        """Test update_user_enable_by_id_async method."""
        payload = UserUpdateEnablePayload(enabled=True)
        await provider.update_user_enable_by_id_async(
            user_id=uuid.uuid4(),
            payload=payload,
            access_token="test_token",  # noqa: S106
        )

        mock_wrapper.request.assert_called_once()
        args, kwargs = mock_wrapper.request.call_args
        assert kwargs["method"] == HttpMethod.PUT
        assert "/admin/realms/test_realm/users/test_user_id" in kwargs["url"]
        assert kwargs["data"] == payload

    @pytest.mark.asyncio
    async def test_update_user_password_by_id_async(self, provider, mock_wrapper):
        """Test update_user_password_by_id_async method."""
        payload = UserUpdatePasswordPayload(
            credentials=[
                {"type": "password", "temporary": False, "value": "new_password"}
            ]
        )
        await provider.update_user_password_by_id_async(
            user_id=uuid.uuid4(),
            payload=payload,
            access_token="test_token",  # noqa: S106
        )

        mock_wrapper.request.assert_called_once()
        args, kwargs = mock_wrapper.request.call_args
        assert kwargs["method"] == HttpMethod.PUT
        assert "/admin/realms/test_realm/users/test_user_id" in kwargs["url"]
        assert kwargs["data"] == payload

    @pytest.mark.asyncio
    async def test_get_users_by_role_async(self, provider, mock_wrapper):
        """Test get_users_by_role_async method."""
        query = RoleMembersListQuery(first=0, max=10)
        await provider.get_users_by_role_async(
            role_name="test_role",
            request_query=query,
            access_token="test_token",  # noqa: S106
        )

        mock_wrapper.request.assert_called_once()
        args, kwargs = mock_wrapper.request.call_args
        assert kwargs["method"] == HttpMethod.GET
        assert (
            "/admin/realms/test_realm/clients/test_client/roles/test_role/users"
            in kwargs["url"]
        )

    @pytest.mark.asyncio
    async def test_close_method(self, provider, mock_wrapper):
        """Test close method."""
        await provider.close()
        mock_wrapper.client.aclose.assert_called_once()

    @pytest.mark.asyncio
    async def test_get_client_roles_async(
        self, provider, mock_wrapper, mock_realm_client
    ):
        """Test get_client_roles_async method."""
        # Mock the client_uuid property
        mock_realm_client.client_uuid = "test-client-uuid"

        provider = KeycloakProviderAsync(
            realm="test_realm", realm_client=mock_realm_client, wrapper=mock_wrapper
        )

        await provider.get_client_roles_async(access_token="test_token")  # noqa: S106

        mock_wrapper.request.assert_called_once()
        args, kwargs = mock_wrapper.request.call_args
        assert kwargs["method"] == HttpMethod.GET
        assert (
            "/admin/realms/test_realm/clients/test-client-uuid/roles" in kwargs["url"]
        )

    @pytest.mark.asyncio
    async def test_get_client_roles_of_user_async(self, provider, mock_wrapper):
        """Test get_client_roles_of_user_async method."""
        await provider.get_client_roles_of_user_async(
            user_id=uuid.uuid4(), access_token="test_token"  # noqa: S106
        )

        mock_wrapper.request.assert_called_once()
        args, kwargs = mock_wrapper.request.call_args
        assert kwargs["method"] == HttpMethod.GET
        assert (
            "/admin/realms/test_realm/users/test_user_id/role-mappings/clients/test_client"
            in kwargs["url"]
        )

    @pytest.mark.asyncio
    async def test_get_composite_client_roles_of_user_async(
        self, provider, mock_wrapper
    ):
        """Test get_composite_client_roles_of_user_async method."""
        query = BriefRepresentationQuery(brief_representation=True)
        await provider.get_composite_client_roles_of_user_async(
            user_id=uuid.uuid4(),
            request_query=query,
            access_token="test_token",  # noqa: S106
        )

        mock_wrapper.request.assert_called_once()
        args, kwargs = mock_wrapper.request.call_args
        assert kwargs["method"] == HttpMethod.GET
        assert (
            "/admin/realms/test_realm/users/test_user_id/role-mappings/clients/test_client/composite"
            in kwargs["url"]
        )

    @pytest.mark.asyncio
    async def test_get_available_client_roles_of_user_async(
        self, provider, mock_wrapper
    ):
        """Test get_available_client_roles_of_user_async method."""
        await provider.get_available_client_roles_of_user_async(
            user_id=uuid.uuid4(), access_token="test_token"  # noqa: S106
        )

        mock_wrapper.request.assert_called_once()
        args, kwargs = mock_wrapper.request.call_args
        assert kwargs["method"] == HttpMethod.GET
        assert (
            "/admin/realms/test_realm/users/test_user_id/role-mappings/clients/test_client/available"
            in kwargs["url"]
        )

    @pytest.mark.asyncio
    async def test_delete_user_async(self, provider, mock_wrapper):
        """Test delete_user_async method."""
        await provider.delete_user_async(
            user_id=uuid.uuid4(), access_token="test_token"  # noqa: S106
        )

        mock_wrapper.request.assert_called_once()
        args, kwargs = mock_wrapper.request.call_args
        assert kwargs["method"] == HttpMethod.DELETE
        assert "/admin/realms/test_realm/users/test_user_id" in kwargs["url"]

    @pytest.mark.asyncio
    async def test_delete_session_by_id_async(self, provider, mock_wrapper):
        """Test delete_session_by_id_async method."""
        await provider.delete_session_by_id_async(
            session_id="test_session_id",
            is_offline=False,
            access_token="test_token",  # noqa: S106
        )

        mock_wrapper.request.assert_called_once()
        args, kwargs = mock_wrapper.request.call_args
        assert kwargs["method"] == HttpMethod.DELETE
        assert "/admin/realms/test_realm/sessions/test_session_id" in kwargs["url"]
        assert kwargs["params"]["isOffline"] == "false"

    @pytest.mark.asyncio
    async def test_get_client_user_sessions_async(self, provider, mock_wrapper):
        """Test get_client_user_sessions_async method."""
        query = PaginationQuery(first=0, max=10)
        await provider.get_client_user_sessions_async(
            request_query=query, access_token="test_token"  # noqa: S106
        )

        mock_wrapper.request.assert_called_once()
        args, kwargs = mock_wrapper.request.call_args
        assert kwargs["method"] == HttpMethod.GET
        assert (
            "/admin/realms/test_realm/clients/test_client/user-sessions"
            in kwargs["url"]
        )

    @pytest.mark.asyncio
    async def test_get_client_sessions_count_async(self, provider, mock_wrapper):
        """Test get_client_sessions_count_async method."""
        await provider.get_client_sessions_count_async(
            access_token="test_token"  # noqa: S106
        )

        mock_wrapper.request.assert_called_once()
        args, kwargs = mock_wrapper.request.call_args
        assert kwargs["method"] == HttpMethod.GET
        assert (
            "/admin/realms/test_realm/clients/test_client/session-count"
            in kwargs["url"]
        )

    @pytest.mark.asyncio
    async def test_get_offline_sessions_async(self, provider, mock_wrapper):
        """Test get_offline_sessions_async method."""
        query = PaginationQuery(first=0, max=10)
        await provider.get_offline_sessions_async(
            request_query=query, access_token="test_token"  # noqa: S106
        )

        mock_wrapper.request.assert_called_once()
        args, kwargs = mock_wrapper.request.call_args
        assert kwargs["method"] == HttpMethod.GET
        assert (
            "/admin/realms/test_realm/clients/test_client/offline-sessions"
            in kwargs["url"]
        )

    @pytest.mark.asyncio
    async def test_get_offline_sessions_count_async(self, provider, mock_wrapper):
        """Test get_offline_sessions_count_async method."""
        await provider.get_offline_sessions_count_async(
            access_token="test_token"  # noqa: S106
        )

        mock_wrapper.request.assert_called_once()
        args, kwargs = mock_wrapper.request.call_args
        assert kwargs["method"] == HttpMethod.GET
        assert (
            "/admin/realms/test_realm/clients/test_client/offline-session-count"
            in kwargs["url"]
        )

    @pytest.mark.asyncio
    async def test_remove_user_sessions_async(self, provider, mock_wrapper):
        """Test remove_user_sessions_async method."""
        await provider.remove_user_sessions_async(
            user_id=uuid.uuid4(), access_token="test_token"  # noqa: S106
        )

        mock_wrapper.request.assert_called_once()
        args, kwargs = mock_wrapper.request.call_args
        assert kwargs["method"] == HttpMethod.POST
        assert "/admin/realms/test_realm/users/test_user_id/logout" in kwargs["url"]

    @pytest.mark.asyncio
    async def test_logout_all_users_async(self, provider, mock_wrapper):
        """Test logout_all_users_async method."""
        await provider.logout_all_users_async(access_token="test_token")  # noqa: S106

        mock_wrapper.request.assert_called_once()
        args, kwargs = mock_wrapper.request.call_args
        assert kwargs["method"] == HttpMethod.POST
        assert "/admin/realms/test_realm/logout-all" in kwargs["url"]

    @pytest.mark.asyncio
    async def test_get_client_session_stats_async(self, provider, mock_wrapper):
        """Test get_client_session_stats_async method."""
        await provider.get_client_session_stats_async(
            access_token="test_token"  # noqa: S106
        )

        mock_wrapper.request.assert_called_once()
        args, kwargs = mock_wrapper.request.call_args
        assert kwargs["method"] == HttpMethod.GET
        assert "/admin/realms/test_realm/client-session-stats" in kwargs["url"]

    @pytest.mark.asyncio
    async def test_get_client_user_offline_sessions_async(self, provider, mock_wrapper):
        """Test get_client_user_offline_sessions_async method."""
        await provider.get_client_user_offline_sessions_async(
            user_id=uuid.uuid4(), access_token="test_token"  # noqa: S106
        )

        mock_wrapper.request.assert_called_once()
        args, kwargs = mock_wrapper.request.call_args
        assert kwargs["method"] == HttpMethod.GET
        assert (
            "/admin/realms/test_realm/users/test_user_id/offline-sessions"
            in kwargs["url"]
        )

    @pytest.mark.asyncio
    async def test_get_client_role_id_async(self, provider, mock_wrapper):
        """Test get_client_role_id_async method."""
        await provider.get_client_role_id_async(
            role_name="test_role", access_token="test_token"  # noqa: S106
        )

        mock_wrapper.request.assert_called_once()
        args, kwargs = mock_wrapper.request.call_args
        assert kwargs["method"] == HttpMethod.GET
        assert (
            "/admin/realms/test_realm/clients/test_client/roles/test_role"
            in kwargs["url"]
        )

    @pytest.mark.asyncio
    async def test_create_role(self, provider, mock_wrapper):
        """Test create_role method."""
        payload = {"name": "test_role", "description": "Test role"}
        await provider.create_role(
            payload=payload, access_token="test_token"  # noqa: S106
        )

        mock_wrapper.request.assert_called_once()
        args, kwargs = mock_wrapper.request.call_args
        assert kwargs["method"] == HttpMethod.POST
        assert "/admin/realms/test_realm/clients/test_client/roles" in kwargs["url"]
        assert kwargs["data"] == payload

    @pytest.mark.asyncio
    async def test_update_role_by_id_async(self, provider, mock_wrapper):
        """Test update_role_by_id_async method."""
        from uuid import UUID

        role_id = UUID("12345678-1234-5678-1234-567812345678")
        payload = {"name": "updated_role", "description": "Updated role"}
        await provider.update_role_by_id_async(
            role_id=role_id, payload=payload, access_token="test_token"  # noqa: S106
        )

        mock_wrapper.request.assert_called_once()
        args, kwargs = mock_wrapper.request.call_args
        assert kwargs["method"] == HttpMethod.PUT
        assert f"/admin/realms/test_realm/roles-by-id/{role_id}" in kwargs["url"]
        assert kwargs["data"] == payload

    @pytest.mark.asyncio
    async def test_update_role_by_name_async(self, provider, mock_wrapper):
        """Test update_role_by_name_async method."""
        payload = {"name": "updated_role", "description": "Updated role"}
        await provider.update_role_by_name_async(
            role_name="test_role",
            payload=payload,
            access_token="test_token",  # noqa: S106
        )

        mock_wrapper.request.assert_called_once()
        args, kwargs = mock_wrapper.request.call_args
        assert kwargs["method"] == HttpMethod.PUT
        assert "/admin/realms/test_realm/roles/test_role" in kwargs["url"]
        assert kwargs["data"] == payload

    @pytest.mark.asyncio
    async def test_delete_role_by_id_async(self, provider, mock_wrapper):
        """Test delete_role_by_id_async method."""
        from uuid import UUID

        role_id = UUID("12345678-1234-5678-1234-567812345678")
        await provider.delete_role_by_id_async(
            role_id=role_id, access_token="test_token"  # noqa: S106
        )

        mock_wrapper.request.assert_called_once()
        args, kwargs = mock_wrapper.request.call_args
        assert kwargs["method"] == HttpMethod.DELETE
        assert f"/admin/realms/test_realm/roles-by-id/{role_id}" in kwargs["url"]

    @pytest.mark.asyncio
    async def test_delete_role_by_name_async(self, provider, mock_wrapper):
        """Test delete_role_by_name_async method."""
        await provider.delete_role_by_name_async(
            role_name="test_role", access_token="test_token"  # noqa: S106
        )

        mock_wrapper.request.assert_called_once()
        args, kwargs = mock_wrapper.request.call_args
        assert kwargs["method"] == HttpMethod.DELETE
        assert "/admin/realms/test_realm/roles/test_role" in kwargs["url"]

    @pytest.mark.asyncio
    async def test_assign_client_role_async(self, provider, mock_wrapper):
        """Test assign_client_role_async method."""
        from uuid import UUID

        user_id = UUID("12345678-1234-5678-1234-567812345678")
        roles = ["role1", "role2"]
        await provider.assign_client_role_async(
            user_id=user_id, roles=roles, access_token="test_token"  # noqa: S106
        )

        mock_wrapper.request.assert_called_once()
        args, kwargs = mock_wrapper.request.call_args
        assert kwargs["method"] == HttpMethod.POST
        assert (
            f"/admin/realms/test_realm/users/{user_id}/role-mappings/clients/test_client"
            in kwargs["url"]
        )

    @pytest.mark.asyncio
    async def test_delete_client_roles_of_user_async(self, provider, mock_wrapper):
        """Test delete_client_roles_of_user_async method."""
        roles = ["role1", "role2"]
        await provider.delete_client_roles_of_user_async(
            user_id=uuid.uuid4(), roles=roles, access_token="test_token"  # noqa: S106
        )

        mock_wrapper.request.assert_called_once()
        args, kwargs = mock_wrapper.request.call_args
        assert kwargs["method"] == HttpMethod.DELETE
        assert (
            "/admin/realms/test_realm/users/test_user_id/role-mappings/clients/test_client"
            in kwargs["url"]
        )
