# SPDX-License-Identifier: MIT
from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock, MagicMock

import pytest

from pykeycloak.core.token_manager import AuthToken, AuthTokenValidator, TokenManager


def make_token(
    access_token="tok",
    expires_in=3600,
    refresh_token="ref",
    refresh_expires_in=7200,
    issued_at=None,
):
    return AuthToken(
        access_token=access_token,
        expires_in=expires_in,
        refresh_token=refresh_token,
        refresh_expires_in=refresh_expires_in,
        issued_at=issued_at or datetime.now(UTC),
    )


class TestAuthTokenValidator:
    def test_valid_access_token(self):
        token = make_token(expires_in=3600)
        assert AuthTokenValidator.is_access_token_valid(token) is True

    def test_expired_access_token(self):
        token = make_token(
            expires_in=10,
            issued_at=datetime.now(UTC) - timedelta(seconds=100),
        )
        assert AuthTokenValidator.is_access_token_valid(token) is False

    def test_access_token_within_buffer_is_invalid(self):
        # expires in 20s but buffer is 30s -> invalid
        token = make_token(
            expires_in=20,
            issued_at=datetime.now(UTC),
        )
        assert AuthTokenValidator.is_access_token_valid(token) is False

    def test_no_access_token_is_invalid(self):
        token = AuthToken(access_token=None, expires_in=3600)
        assert AuthTokenValidator.is_access_token_valid(token) is False

    def test_no_expires_in_is_invalid(self):
        token = AuthToken(access_token="tok", expires_in=None)
        assert AuthTokenValidator.is_access_token_valid(token) is False

    def test_valid_refresh_token(self):
        token = make_token(refresh_expires_in=7200)
        assert AuthTokenValidator.is_refresh_token_valid(token) is True

    def test_expired_refresh_token(self):
        token = make_token(
            refresh_expires_in=10,
            issued_at=datetime.now(UTC) - timedelta(seconds=100),
        )
        assert AuthTokenValidator.is_refresh_token_valid(token) is False

    def test_no_refresh_token_is_invalid(self):
        token = AuthToken(refresh_token=None, refresh_expires_in=7200)
        assert AuthTokenValidator.is_refresh_token_valid(token) is False

    def test_no_refresh_expires_in_is_invalid(self):
        token = AuthToken(refresh_token="ref", refresh_expires_in=None)
        assert AuthTokenValidator.is_refresh_token_valid(token) is False


class TestTokenManager:
    def test_initial_state(self):
        tm = TokenManager()
        assert tm.auth_tokens is not None
        assert tm.auth_tokens.access_token is None
        assert tm.is_access_token_exists() is False
        assert tm.is_access_token_valid() is False

    def test_update_auth_tokens(self):
        tm = TokenManager()
        token = make_token()
        tm.update_auth_tokens(token)
        assert tm.auth_tokens is token
        assert tm.is_access_token_exists() is True

    def test_is_access_token_valid_after_update(self):
        tm = TokenManager()
        token = make_token(expires_in=3600)
        tm.update_auth_tokens(token)
        assert tm.is_access_token_valid() is True

    async def test_get_valid_token_returns_existing_valid_token(self):
        tm = TokenManager()
        token = make_token(expires_in=3600)
        tm.update_auth_tokens(token)
        result = await tm.get_valid_token()
        assert result is token

    async def test_get_valid_token_refreshes_when_expired(self):
        tm = TokenManager()
        expired = make_token(
            expires_in=10, issued_at=datetime.now(UTC) - timedelta(seconds=100)
        )
        tm.update_auth_tokens(expired)

        new_token = make_token(expires_in=3600)
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "access_token": new_token.access_token,
            "expires_in": new_token.expires_in,
            "refresh_token": new_token.refresh_token,
            "refresh_expires_in": new_token.refresh_expires_in,
        }
        updater = AsyncMock(return_value=mock_response)
        tm.init_update_access_token_api(updater)

        result = await tm.get_valid_token()
        assert result.access_token == "tok"
        updater.assert_awaited_once()

    async def test_fetch_access_token_raises_without_updater(self):
        tm = TokenManager()
        with pytest.raises(TypeError, match="init_update_access_token_api"):
            await tm.fetch_access_token_using_refresh_token()
