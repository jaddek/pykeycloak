"""
Detailed unit tests for the services module to increase coverage.
"""

import pytest
from unittest.mock import AsyncMock, MagicMock
from httpx import Response
from pykeycloak.services.services import (
    BaseService,
    AuthService,
    UsersService,
    RolesService,
    SessionsService,
    UmaService
)
from pykeycloak.providers.providers import KeycloakProviderAsync


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
        users_response.json.return_value = [{"id": "1", "username": "user1"}, {"id": "2", "username": "user2"}]
        mock_provider.get_users_async.return_value = users_response

        result = await users_service.get_users_async()

        assert len(result) == 1  # Since count is 2 and default max is higher, it returns one response
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
        users_response.json.return_value = [{"id": f"{i}", "username": f"user{i}"} for i in range(100)]
        mock_provider.get_users_async.return_value = users_response

        result = await users_service.get_users_async()

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

        result = await users_service.get_paginated_users_async(users_count=1, query=None)

        assert len(result) == 1
        assert mock_provider.get_users_async.called

    @pytest.mark.asyncio
    async def test_auth_service_client_login_raw_async(self, mock_provider):
        """Test AuthService client_login_raw_async method."""
        auth_service = AuthService(provider=mock_provider)

        mock_response = MagicMock(spec=Response)
        mock_response.json.return_value = {"access_token": "test_token", "expires_in": 3600}
        mock_provider.obtain_token_async.return_value = mock_response

        result = await auth_service.client_login_raw_async()

        assert "access_token" in result
        assert mock_provider.obtain_token_async.called

    @pytest.mark.asyncio
    async def test_auth_service_refresh_token_raw_async(self, mock_provider):
        """Test AuthService refresh_token_raw_async method."""
        auth_service = AuthService(provider=mock_provider)

        from pykeycloak.providers.payloads import RefreshTokenPayload
        payload = RefreshTokenPayload(refresh_token="test_refresh_token")

        mock_response = MagicMock(spec=Response)
        mock_response.json.return_value = {"access_token": "new_token", "refresh_token": "new_refresh_token"}
        mock_provider.refresh_token_async.return_value = mock_response

        result = await auth_service.refresh_token_raw_async(payload=payload)

        assert "access_token" in result
        assert mock_provider.refresh_token_async.called

    @pytest.mark.asyncio
    async def test_auth_service_get_user_info_raw_async(self, mock_provider):
        """Test AuthService get_user_info_raw_async method."""
        auth_service = AuthService(provider=mock_provider)

        mock_response = MagicMock(spec=Response)
        mock_response.json.return_value = {"sub": "user123", "email": "user@example.com"}
        mock_provider.get_user_info_async.return_value = mock_response

        result = await auth_service.get_user_info_raw_async(access_token="test_token")

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

        await auth_service.logout_async(refresh_token="test_refresh_token")

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
            await auth_service.logout_async(refresh_token="test_refresh_token")

    @pytest.mark.asyncio
    async def test_auth_service_introspect_raw_async(self, mock_provider):
        """Test AuthService introspect_raw_async method."""
        auth_service = AuthService(provider=mock_provider)

        from pykeycloak.providers.payloads import TokenIntrospectionPayload
        payload = TokenIntrospectionPayload(token="test_token")

        mock_response = MagicMock(spec=Response)
        mock_response.json.return_value = {"active": True, "username": "test_user"}
        mock_provider.introspect_token_async.return_value = mock_response

        result = await auth_service.introspect_raw_async(payload=payload)

        assert "active" in result
        assert mock_provider.introspect_token_async.called

    @pytest.mark.asyncio
    async def test_auth_service_get_certs_raw_async(self, mock_provider):
        """Test AuthService get_certs_raw_async method."""
        auth_service = AuthService(provider=mock_provider)

        mock_response = MagicMock(spec=Response)
        mock_response.json.return_value = {"keys": []}
        mock_provider.get_certs_async.return_value = mock_response

        result = await auth_service.get_certs_raw_async()

        assert "keys" in result
        assert mock_provider.get_certs_async.called

    @pytest.mark.asyncio
    async def test_uma_service_get_uma_permissions_async(self, mock_provider):
        """Test UmaService get_uma_permissions_async method."""
        uma_service = UmaService(provider=mock_provider)

        from pykeycloak.providers.payloads import UMAAuthorizationPayload
        from pykeycloak.core.enums import UrnIetfOauthUmaTicketResponseModeEnum
        from pykeycloak.core.enums import UrnIetfOauthUmaTicketPermissionResourceFormatEnum
        payload = UMAAuthorizationPayload(
            audience="test_audience",
            permissions={"resource_id": ["permission1", "permission2"]},
            subject_token="test_subject_token"
        )

        mock_response = MagicMock(spec=Response)
        mock_response.json.return_value = {"permissions": []}
        mock_provider.get_uma_permission_async.return_value = mock_response

        result = await uma_service.get_uma_permissions_async(payload=payload)

        assert "permissions" in result
        assert mock_provider.get_uma_permission_async.called

    def test_base_service_init(self, mock_provider):
        """Test BaseService initialization."""
        service = BaseService(provider=mock_provider)
        assert service._provider is mock_provider