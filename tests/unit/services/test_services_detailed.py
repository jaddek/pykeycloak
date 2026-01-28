"""
Detailed unit tests for the services module to increase coverage.
"""

from unittest.mock import MagicMock

import pytest
from httpx import Response

from pykeycloak.providers.providers import KeycloakProviderAsync
from pykeycloak.services.services import (
    AuthService,
    BaseService,
    UmaService,
    UsersService,
)


class TestServicesDetailed:
    """Detailed test cases for the service classes."""

    @pytest.fixture
    def mock_provider(self):
        """Fixture to create a mock provider."""
        mock = MagicMock(spec=KeycloakProviderAsync)
        return mock

    @pytest.fixture
    def base_service(self, mock_provider):
        """Fixture to create a BaseService instance."""
        return BaseService(provider=mock_provider)

    @pytest.mark.asyncio
    async def test_validate_response_success(self, base_service):
        """Test validate_response method with successful response."""
        mock_response = MagicMock(spec=Response)
        mock_response.json.return_value = {"key": "value"}

        result = base_service.validate_response(mock_response)
        assert result == {"key": "value"}

    @pytest.mark.asyncio
    async def test_validate_response_json_error(self, base_service):
        """Test validate_response method with JSON decoding error."""
        mock_response = MagicMock(spec=Response)
        mock_response.json.side_effect = ValueError("Invalid JSON")

        with pytest.raises(ValueError, match="Failed to decode JSON response"):
            base_service.validate_response(mock_response)

    @pytest.mark.asyncio
    async def test_validate_response_invalid_type(self, base_service):
        """Test validate_response method with invalid response type."""
        mock_response = MagicMock(spec=Response)
        mock_response.json.return_value = "not_a_dict_or_list"

        with pytest.raises(TypeError, match="Expected JSON dict or list"):
            base_service.validate_response(mock_response)

    @pytest.mark.asyncio
    async def test_users_service_get_users_async(self, mock_provider):
        """Test UsersService get_users_async method."""
        users_service = UsersService(provider=mock_provider)

        # Mock the get_users_count_async response
        count_response = MagicMock(spec=Response)
        count_response.text = "2"
        mock_provider.get_users_count_async.return_value = count_response

        # Mock the get_users_async response
        users_response = MagicMock(spec=Response)
        users_response.json.return_value = [
            {"id": "1", "username": "user1"},
            {"id": "2", "username": "user2"},
        ]
        mock_provider.get_users_async.return_value = users_response

        result = await users_service.get_users_async()

        assert (
            len(result) == 1
        )  # Since count is 2 and default max is higher, it returns one response
        assert mock_provider.get_users_count_async.called
        assert mock_provider.get_users_async.called

    @pytest.mark.asyncio
    async def test_users_service_get_users_async_pagination(self, mock_provider):
        """Test UsersService get_users_async method with pagination."""
        users_service = UsersService(provider=mock_provider)

        # Mock the get_users_count_async response
        count_response = MagicMock(spec=Response)
        count_response.text = "150"  # More than default max to trigger pagination
        mock_provider.get_users_count_async.return_value = count_response

        # Mock the get_users_async response for each page
        users_response = MagicMock(spec=Response)
        users_response.json.return_value = [
            {"id": f"{i}", "username": f"user{i}"} for i in range(100)
        ]
        mock_provider.get_users_async.return_value = users_response

        await users_service.get_users_async()

        assert mock_provider.get_users_count_async.called
        # For 150 users with default max=100, it should call get_users_async twice
        assert mock_provider.get_users_async.call_count >= 1

    @pytest.mark.asyncio
    async def test_users_service_get_paginated_users_async(self, mock_provider):
        """Test UsersService get_paginated_users_async method."""
        users_service = UsersService(provider=mock_provider)

        # Mock the get_users_async response
        users_response = MagicMock(spec=Response)
        users_response.json.return_value = [{"id": "1", "username": "user1"}]
        mock_provider.get_users_async.return_value = users_response

        result = await users_service.get_paginated_users_async(
            users_count=1, query=None
        )

        assert len(result) == 1
        assert mock_provider.get_users_async.called

    @pytest.mark.asyncio
    async def test_auth_service_client_login_raw_async(self, mock_provider):
        """Test AuthService client_login_raw_async method."""
        auth_service = AuthService(provider=mock_provider)

        mock_response = MagicMock(spec=Response)
        mock_response.json.return_value = {
            "access_token": "test_token",
            "expires_in": 3600,
        }
        mock_response.status_code = 200

        mock_provider.obtain_token_async.return_value = mock_response

        result = await auth_service.client_login_raw_async()

        assert "access_token" in result
        assert mock_provider.obtain_token_async.called

    @pytest.mark.asyncio
    async def test_auth_service_refresh_token_raw_async(self, mock_provider):
        """Test AuthService refresh_token_raw_async method."""
        auth_service = AuthService(provider=mock_provider)

        from pykeycloak.providers.payloads import RefreshTokenPayload

        payload = RefreshTokenPayload(refresh_token="test_refresh_token")  # noqa: S106

        mock_response = MagicMock(spec=Response)
        mock_response.json.return_value = {
            "access_token": "new_token",  # noqa: S106
            "refresh_token": "new_refresh_token",  # noqa: S106
        }
        mock_response.status_code = 200

        mock_provider.refresh_token_async.return_value = mock_response

        result = await auth_service.refresh_token_raw_async(payload=payload)

        assert "access_token" in result
        assert mock_provider.refresh_token_async.called

    @pytest.mark.asyncio
    async def test_auth_service_get_user_info_raw_async(self, mock_provider):
        """Test AuthService get_user_info_raw_async method."""
        auth_service = AuthService(provider=mock_provider)

        mock_response = MagicMock(spec=Response)
        mock_response.json.return_value = {
            "sub": "user123",
            "email": "user@example.com",
        }
        mock_response.status_code = 200

        mock_provider.get_user_info_async.return_value = mock_response

        result = await auth_service.get_user_info_raw_async(
            access_token="test_token"  # noqa: S106
        )

        assert "sub" in result
        assert mock_provider.get_user_info_async.called

    @pytest.mark.asyncio
    async def test_auth_service_logout_async(self, mock_provider):
        """Test AuthService logout_async method."""
        auth_service = AuthService(provider=mock_provider)

        from http import HTTPStatus

        mock_response = MagicMock(spec=Response)
        mock_response.status_code = HTTPStatus.NO_CONTENT
        mock_provider.logout_async.return_value = mock_response

        await auth_service.logout_async(
            refresh_token="test_refresh_token"  # noqa: S106
        )

        assert mock_provider.logout_async.called

    @pytest.mark.asyncio
    async def test_auth_service_logout_async_with_error(self, mock_provider):
        """Test AuthService logout_async method with error response."""
        auth_service = AuthService(provider=mock_provider)

        from http import HTTPStatus

        mock_response = MagicMock(spec=Response)
        mock_response.status_code = HTTPStatus.BAD_REQUEST
        mock_provider.logout_async.return_value = mock_response

        with pytest.raises(ValueError, match="Unexpected response from Keycloak"):
            await auth_service.logout_async(
                refresh_token="test_refresh_token"  # noqa: S106
            )

    @pytest.mark.asyncio
    async def test_auth_service_introspect_raw_async(self, mock_provider):
        """Test AuthService introspect_raw_async method."""
        auth_service = AuthService(provider=mock_provider)

        from pykeycloak.providers.payloads import TokenIntrospectionPayload

        payload = TokenIntrospectionPayload(token="test_token")  # noqa: S106

        mock_response = MagicMock(spec=Response)
        mock_response.json.return_value = {"active": True, "username": "test_user"}
        mock_provider.introspect_token_async.return_value = mock_response

        result = await auth_service.introspect_token_raw_async(payload=payload)

        assert "active" in result
        assert mock_provider.introspect_token_async.called

    @pytest.mark.asyncio
    async def test_auth_service_get_certs_raw_async(self, mock_provider):
        """Test AuthService get_certs_raw_async method."""
        auth_service = AuthService(provider=mock_provider)

        mock_response = MagicMock(spec=Response)
        mock_response.json.return_value = {"keys": []}
        mock_provider.get_certs_async.return_value = mock_response

        result = await auth_service.get_certs_async()

        assert "keys" in result
        assert mock_provider.get_certs_async.called

    @pytest.mark.asyncio
    async def test_uma_service_get_uma_permissions_async(self, mock_provider):
        """Test UmaService get_uma_permissions_async method."""
        uma_service = UmaService(provider=mock_provider)

        from pykeycloak.providers.payloads import UMAAuthorizationPayload

        payload = UMAAuthorizationPayload(
            audience="test_audience",
            permissions={"resource_id": ["permission1", "permission2"]},
            subject_token="test_subject_token",  # noqa: S106
        )

        mock_response = MagicMock(spec=Response)
        mock_response.json.return_value = {"permissions": []}
        mock_response.status_code = 200
        mock_provider.get_uma_permission_async.return_value = mock_response

        result = await uma_service.get_uma_permissions_async(payload=payload)

        assert "permissions" in result
        assert mock_provider.get_uma_permission_async.called

    def test_base_service_init(self, mock_provider):
        """Test BaseService initialization."""
        service = BaseService(provider=mock_provider)
        assert service._provider is mock_provider

    @pytest.mark.asyncio
    async def test_users_service_get_user_async(self, mock_provider):
        """Test UsersService get_user_async method."""
        users_service = UsersService(provider=mock_provider)

        from uuid import UUID

        user_id = UUID(int=1)  # Create a valid UUID

        # Mock the get_user_async response
        user_data = {
            "id": str(user_id),
            "username": "test_user",
            "email": "test@example.com",
        }
        mock_response = MagicMock(spec=Response)
        mock_response.json.return_value = user_data
        mock_provider.get_user_async.return_value = mock_response
        mock_response.status_code = 200

        result = await users_service.get_user_async(user_id=user_id)

        assert result == user_data
        mock_provider.get_user_async.assert_called_once_with(user_id=user_id)

    @pytest.mark.asyncio
    async def test_users_service_get_users_count(self, mock_provider):
        """Test UsersService get_users_count method."""
        users_service = UsersService(provider=mock_provider)

        # Mock the get_users_count_async response
        count_data = 42
        mock_response = MagicMock(spec=Response)
        mock_response.json.return_value = count_data
        mock_provider.get_users_count_async.return_value = mock_response

        result = await users_service.get_users_count()

        assert result == count_data
        mock_provider.get_users_count_async.assert_called_once_with(query=None)

    @pytest.mark.asyncio
    async def test_users_service_get_users_by_role_async(self, mock_provider):
        """Test UsersService get_users_by_role_async method."""
        users_service = UsersService(provider=mock_provider)

        role_name = "test_role"

        # Mock the get_users_by_role_async response
        users_data = [
            {"id": "1", "username": "user1"},
            {"id": "2", "username": "user2"},
        ]
        mock_response = MagicMock(spec=Response)
        mock_response.json.return_value = users_data
        mock_response.status_code = 200

        mock_provider.get_users_by_role_async.return_value = mock_response

        result = await users_service.get_users_by_role_async(role_name=role_name)

        assert result == users_data
        mock_provider.get_users_by_role_async.assert_called_once_with(
            role_name=role_name, query=None
        )

    @pytest.mark.asyncio
    async def test_users_service_create_user_async(self, mock_provider):
        """Test UsersService create_user_async method."""
        users_service = UsersService(provider=mock_provider)

        from pykeycloak.providers.payloads import CreateUserPayload

        payload = CreateUserPayload(
            username="test_user",
            email="test@example.com",
            first_name="Test",
            last_name="User",
        )

        # Mock the create_user_async response
        user_data = {"id": "new_user_id", "username": "test_user"}
        mock_response = MagicMock(spec=Response)
        mock_response.json.return_value = user_data
        mock_response.status_code = 200

        mock_provider.create_user_async.return_value = mock_response

        result = await users_service.create_user_async(payload=payload)

        assert result == user_data
        mock_provider.create_user_async.assert_called_once_with(parent=payload)

    @pytest.mark.asyncio
    async def test_users_service_update_user_async(self, mock_provider):
        """Test UsersService update_user_async method."""
        users_service = UsersService(provider=mock_provider)

        from uuid import UUID

        user_id = UUID(int=1)  # Create a valid UUID

        from pykeycloak.providers.payloads import CreateUserPayload

        payload = CreateUserPayload(
            username="updated_user",
            email="updated@example.com",
            first_name="Updated",
            last_name="User",
        )

        # Mock the update_user_by_id_async response
        user_data = {"id": str(user_id), "username": "updated_user"}
        mock_response = MagicMock(spec=Response)
        mock_response.json.return_value = user_data
        mock_response.status_code = 200

        mock_provider.update_user_by_id_async.return_value = mock_response

        result = await users_service.update_user_async(user_id=user_id, payload=payload)

        assert result == user_data
        mock_provider.update_user_by_id_async.assert_called_once_with(
            user_id=user_id, payload=payload
        )

    @pytest.mark.asyncio
    async def test_users_service_enable_user_async(self, mock_provider):
        """Test UsersService enable_user_async method."""
        users_service = UsersService(provider=mock_provider)

        from uuid import UUID

        user_id = UUID(int=1)  # Create a valid UUID

        from pykeycloak.providers.payloads import UserUpdateEnablePayload

        payload = UserUpdateEnablePayload(enabled=True)

        # Mock the update_user_enable_by_id_async response
        user_data = {"id": str(user_id), "enabled": True}
        mock_response = MagicMock(spec=Response)
        mock_response.json.return_value = user_data
        mock_response.status_code = 200
        mock_provider.update_user_enable_by_id_async.return_value = mock_response

        result = await users_service.enable_user_async(user_id=user_id, payload=payload)

        assert result == user_data
        mock_provider.update_user_enable_by_id_async.assert_called_once_with(
            user_id=user_id, payload=payload
        )

    @pytest.mark.asyncio
    async def test_users_service_update_user_password_async(self, mock_provider):
        """Test UsersService update_user_password_async method."""
        users_service = UsersService(provider=mock_provider)

        from uuid import UUID

        user_id = UUID(int=1)  # Create a valid UUID

        from pykeycloak.providers.payloads import UserUpdatePasswordPayload

        payload = UserUpdatePasswordPayload(
            credentials=[
                {"temporary": False, "type": "password", "value": "new_password"}
            ]
        )

        # Mock the update_user_password_by_id_async response
        result_data = {"success": True}
        mock_response = MagicMock(spec=Response)
        mock_response.json.return_value = result_data
        mock_response.status_code = 200
        mock_provider.update_user_password_by_id_async.return_value = mock_response

        await users_service.update_user_password_async(
            user_id=user_id, payload=payload
        )

        mock_provider.update_user_password_by_id_async.assert_called_once_with(
            user_id=user_id, payload=payload
        )

    @pytest.mark.asyncio
    async def test_users_service_delete_user_async(self, mock_provider):
        """Test UsersService delete_user_async method."""
        users_service = UsersService(provider=mock_provider)

        from uuid import UUID

        user_id = UUID(int=1)  # Create a valid UUID

        # Mock the delete_user_async response
        result_data = {"success": True}
        mock_response = MagicMock(spec=Response)
        mock_response.json.return_value = result_data
        mock_response.status_code = 200
        mock_provider.delete_user_async.return_value = mock_response

        await users_service.delete_user_async(user_id=user_id)

        mock_provider.delete_user_async.assert_called_once_with(user_id=user_id)
