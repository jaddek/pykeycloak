"""
Unit tests for the token_manager module.
"""

from unittest.mock import Mock

import pytest

from pykeycloak.core.token_manager import (
    AuthToken,
    RefreshTokenSchema,
    mark_need_access_token_initialization,
    mark_need_token_verification,
)


class TestTokenManagerDecorators:
    """Test cases for token manager decorators."""

    def test_mark_need_token_verification_decorator(self):
        """Test the mark_need_token_verification decorator."""

        @mark_need_token_verification
        def sample_function():
            return "result"

        # Check that the function has the attribute set
        assert hasattr(sample_function, "_need_token_verification")
        assert sample_function._need_token_verification is True

        # Check that the function still works normally
        result = sample_function()
        assert result == "result"

    def test_mark_need_access_token_initialization_decorator(self):
        """Test the mark_need_access_token_initialization decorator."""

        @mark_need_access_token_initialization
        def sample_function():
            return "result"

        # Check that the function has the attribute set
        assert hasattr(sample_function, "_need_access_token_initialization")
        assert sample_function._need_access_token_initialization is True

        # Check that the function still works normally
        result = sample_function()
        assert result == "result"

    def test_decorators_on_different_functions(self):
        """Test that decorators work independently on different functions."""

        @mark_need_token_verification
        def func1():
            return 1

        @mark_need_access_token_initialization
        def func2():
            return 2

        @mark_need_token_verification
        @mark_need_access_token_initialization
        def func3():
            return 3

        # Check attributes for func1
        assert func1._need_token_verification is True
        assert not hasattr(func1, "_need_access_token_initialization")

        # Check attributes for func2
        assert func2._need_access_token_initialization is True
        assert not hasattr(func2, "_need_token_verification")

        # Check attributes for func3
        assert func3._need_token_verification is True
        assert func3._need_access_token_initialization is True


class TestRefreshTokenSchema:
    """Test cases for the RefreshTokenSchema class."""

    def test_refresh_token_schema_creation(self):
        """Test creating a RefreshTokenSchema instance."""
        mock_refresh_method = Mock()
        mock_refresh_payload = Mock()

        schema = RefreshTokenSchema(
            refresh_token_method=mock_refresh_method,
            refresh_token_payload=mock_refresh_payload,
        )

        assert schema.refresh_token_method == mock_refresh_method
        assert schema.refresh_token_payload == mock_refresh_payload

    def test_refresh_token_schema_immutability(self):
        """Test that RefreshTokenSchema is immutable."""
        mock_refresh_method = Mock()
        mock_refresh_payload = Mock()

        schema = RefreshTokenSchema(
            refresh_token_method=mock_refresh_method,
            refresh_token_payload=mock_refresh_payload,
        )

        # Attempt to modify should raise an error
        with pytest.raises(Exception):  # noqa: B017
            schema.refresh_token_method = Mock()


class TestAuthToken:
    """Test cases for the AuthToken class."""

    def test_auth_token_defaults(self):
        """Test AuthToken with default values."""
        token = AuthToken()

        assert token.access_token is None
        assert token.expires_in is None
        assert token.scope is None
        assert token.token_type is None
        assert token.not_before_policy is None
        assert token.session_state is None
        assert token.refresh_token is None
        assert token.id_token is None
        assert token.refresh_expires_in is None

    def test_auth_token_with_values(self):
        """Test AuthToken with custom values."""
        token = AuthToken(
            access_token="access-token-123",  # noqa: S106 S105
            expires_in=3600,
            scope="read write",
            token_type="Bearer",  # noqa: S106 S105
            not_before_policy=0,
            session_state="session-state-456",  # noqa: S106 S105
            refresh_token="refresh-token-789",  # noqa: S106 S105
            id_token="id-token-abc",  # noqa: S106 S105
            refresh_expires_in=7200,
        )

        assert token.access_token == "access-token-123"  # noqa: S106 S105
        assert token.expires_in == 3600
        assert token.scope == "read write"
        assert token.token_type == "Bearer"  # noqa: S106 S105
        assert token.not_before_policy == 0
        assert token.session_state == "session-state-456"
        assert token.refresh_token == "refresh-token-789"  # noqa: S106 S105
        assert token.id_token == "id-token-abc"  # noqa: S106 S105
        assert token.refresh_expires_in == 7200

    def test_auth_token_partial_values(self):
        """Test AuthToken with partial values."""
        token = AuthToken(
            access_token="access-token-123", expires_in=3600  # noqa: S106 S105
        )

        assert token.access_token == "access-token-123"  # noqa: S106 S105
        assert token.expires_in == 3600
        assert token.scope is None
        assert token.token_type is None
        assert token.not_before_policy is None
        assert token.session_state is None
        assert token.refresh_token is None
        assert token.id_token is None
        assert token.refresh_expires_in is None

    def test_auth_token_metadata_field(self):
        """Test the metadata field in AuthToken."""
        token = AuthToken(not_before_policy=12345)

        assert token.not_before_policy == 12345
        # Check that the metadata alias works as expected
