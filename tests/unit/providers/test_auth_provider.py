# SPDX-License-Identifier: MIT
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from pykeycloak.core.clients import HttpMethod
from pykeycloak.core.exceptions import AccessTokenIsRequiredError
from pykeycloak.core.token_manager import TokenManager
from pykeycloak.providers._auth import AuthProvider
from pykeycloak.providers.payloads import (
    ClientCredentialsLoginPayload,
    ConfidentialClientRevokePayload,
    RefreshTokenPayload,
    RTPExchangeTokenPayload,
    RTPIntrospectionPayload,
    SSOLoginPayload,
    TokenIntrospectionPayload,
    UMAAuthorizationPayload,
)


def make_token_response(access_token="tok", expires_in=3600, refresh_token="ref", refresh_expires_in=7200):
    resp = MagicMock()
    resp.json.return_value = {
        "access_token": access_token,
        "expires_in": expires_in,
        "refresh_token": refresh_token,
        "refresh_expires_in": refresh_expires_in,
    }
    return resp


@pytest.fixture
def token_manager():
    return TokenManager()


@pytest.fixture
def auth_provider(base, token_manager):
    return AuthProvider(base=base, token_manager=token_manager)


@pytest.fixture
def auth_provider_with_valid_token(base, token_manager):
    from datetime import UTC, datetime

    from pykeycloak.core.token_manager import AuthToken

    token = AuthToken(
        access_token="valid-token",
        expires_in=3600,
        refresh_token="ref",
        refresh_expires_in=7200,
        issued_at=datetime.now(UTC),
    )
    token_manager.update_auth_tokens(token)
    return AuthProvider(base=base, token_manager=token_manager)


class TestObtainTokenAsync:
    @pytest.mark.asyncio
    async def test_posts_to_token_url(self, auth_provider, mock_kc_client):
        mock_kc_client.request_async = AsyncMock(return_value=make_token_response())
        payload = ClientCredentialsLoginPayload()
        await auth_provider.obtain_token_async(payload)

        mock_kc_client.request_async.assert_awaited_once()
        call_kwargs = mock_kc_client.request_async.call_args
        assert call_kwargs.kwargs["method"] == HttpMethod.POST
        assert "token" in call_kwargs.kwargs["url"]

    @pytest.mark.asyncio
    async def test_uses_basic_auth_header(self, auth_provider, mock_kc_client):
        mock_kc_client.request_async = AsyncMock(return_value=make_token_response())
        payload = ClientCredentialsLoginPayload()
        await auth_provider.obtain_token_async(payload)

        call_kwargs = mock_kc_client.request_async.call_args.kwargs
        assert call_kwargs["headers"]["Authorization"].startswith("Basic ")

    @pytest.mark.asyncio
    async def test_updates_token_manager(self, auth_provider, mock_kc_client, token_manager):
        mock_kc_client.request_async = AsyncMock(return_value=make_token_response("new-token"))
        payload = ClientCredentialsLoginPayload()
        await auth_provider.obtain_token_async(payload)

        assert token_manager.auth_tokens.access_token == "new-token"


class TestGetClientAccessToken:
    @pytest.mark.asyncio
    async def test_returns_access_token(self, auth_provider_with_valid_token):
        token = await auth_provider_with_valid_token.get_client_access_token()
        assert token == "valid-token"

    @pytest.mark.asyncio
    async def test_raises_when_no_access_token(self, auth_provider):
        from pykeycloak.core.token_manager import AuthToken

        empty_token = AuthToken(access_token=None, expires_in=None)
        with patch.object(
            auth_provider._token_manager, "get_valid_token", AsyncMock(return_value=empty_token)
        ):
            with pytest.raises(AccessTokenIsRequiredError):
                await auth_provider.get_client_access_token()


class TestRefreshTokenAsync:
    @pytest.mark.asyncio
    async def test_raises_for_public_client(self, base, token_manager):
        from pykeycloak.core.headers import HeadersFactory
        from pykeycloak.core.realm import RealmClient
        from pykeycloak.providers._base import KeycloakProviderBase

        public_rc = RealmClient(
            realm_name="r",
            client_uuid="550e8400-e29b-41d4-a716-446655440000",
            client_id="pub-client",
        )
        pub_base = KeycloakProviderBase(
            realm_client=public_rc,
            kc_headers=HeadersFactory(),
            kc_client=base._kc_client,
        )
        provider = AuthProvider(base=pub_base, token_manager=token_manager)
        with pytest.raises(ValueError, match="confidential"):
            await provider.refresh_token_async(RefreshTokenPayload(refresh_token="ref"))

    @pytest.mark.asyncio
    async def test_refresh_uses_basic_header(self, auth_provider, mock_kc_client):
        mock_kc_client.request_async = AsyncMock(return_value=MagicMock())
        payload = RefreshTokenPayload(refresh_token="ref123")
        await auth_provider.refresh_token_async(payload)

        call_kwargs = mock_kc_client.request_async.call_args.kwargs
        assert call_kwargs["headers"]["Authorization"].startswith("Basic ")

    @pytest.mark.asyncio
    async def test_rtp_exchange_uses_bearer_header(self, auth_provider, mock_kc_client):
        mock_kc_client.request_async = AsyncMock(return_value=MagicMock())
        payload = RTPExchangeTokenPayload(refresh_token="rtp-tok")
        await auth_provider.refresh_token_async(payload)

        call_kwargs = mock_kc_client.request_async.call_args.kwargs
        assert call_kwargs["headers"]["Authorization"].startswith("Bearer ")


class TestIntrospectTokenAsync:
    @pytest.mark.asyncio
    async def test_raises_for_public_client(self, base, token_manager):
        from pykeycloak.core.headers import HeadersFactory
        from pykeycloak.core.realm import RealmClient
        from pykeycloak.providers._base import KeycloakProviderBase

        public_rc = RealmClient(
            realm_name="r",
            client_uuid="550e8400-e29b-41d4-a716-446655440000",
            client_id="pub",
        )
        pub_base = KeycloakProviderBase(
            realm_client=public_rc,
            kc_headers=HeadersFactory(),
            kc_client=base._kc_client,
        )
        provider = AuthProvider(base=pub_base, token_manager=token_manager)
        with pytest.raises(ValueError, match="confidential"):
            await provider.introspect_token_async(TokenIntrospectionPayload(token="t"))

    @pytest.mark.asyncio
    async def test_rtp_uses_bearer_header(self, auth_provider, mock_kc_client):
        mock_kc_client.request_async = AsyncMock(return_value=MagicMock())
        payload = RTPIntrospectionPayload(token="rtp-tok")
        await auth_provider.introspect_token_async(payload)

        call_kwargs = mock_kc_client.request_async.call_args.kwargs
        assert call_kwargs["headers"]["Authorization"].startswith("Bearer ")

    @pytest.mark.asyncio
    async def test_token_introspection_uses_basic_header(self, auth_provider, mock_kc_client):
        mock_kc_client.request_async = AsyncMock(return_value=MagicMock())
        payload = TokenIntrospectionPayload(token="tok")
        await auth_provider.introspect_token_async(payload)

        call_kwargs = mock_kc_client.request_async.call_args.kwargs
        assert call_kwargs["headers"]["Authorization"].startswith("Basic ")

    @pytest.mark.asyncio
    async def test_posts_to_introspect_url(self, auth_provider, mock_kc_client):
        mock_kc_client.request_async = AsyncMock(return_value=MagicMock())
        payload = TokenIntrospectionPayload(token="tok")
        await auth_provider.introspect_token_async(payload)

        call_kwargs = mock_kc_client.request_async.call_args.kwargs
        assert "introspect" in call_kwargs["url"]


class TestGetSSORedirectUrl:
    def test_returns_url_with_query(self, auth_provider, mock_kc_client):
        mock_kc_client.build_full_url = MagicMock(
            return_value="https://kc.example.com/realms/myrealm/protocol/openid-connect/auth?client_id=my-client&redirect_uri=https%3A%2F%2Fr.com&state=st&response_type=code&scope=openid+profile+email"
        )
        payload = SSOLoginPayload(
            client_id="my-client",
            redirect_uri="https://r.com",
            state="st",
        )
        url = auth_provider.get_sso_redirect_url(payload)
        assert "client_id" in url
        assert "redirect_uri" in url


class TestAuthDeviceAsync:
    @pytest.mark.asyncio
    async def test_posts_to_auth_device_url(self, auth_provider, mock_kc_client):
        mock_kc_client.request_async = AsyncMock(return_value=MagicMock())
        await auth_provider.auth_device_async()

        call_kwargs = mock_kc_client.request_async.call_args.kwargs
        assert call_kwargs["method"] == HttpMethod.POST
        assert "device" in call_kwargs["url"]

    @pytest.mark.asyncio
    async def test_confidential_client_uses_basic_header(self, auth_provider, mock_kc_client):
        mock_kc_client.request_async = AsyncMock(return_value=MagicMock())
        await auth_provider.auth_device_async()

        call_kwargs = mock_kc_client.request_async.call_args.kwargs
        assert call_kwargs["headers"]["Authorization"].startswith("Basic ")

    @pytest.mark.asyncio
    async def test_data_contains_client_id(self, auth_provider, mock_kc_client):
        mock_kc_client.request_async = AsyncMock(return_value=MagicMock())
        await auth_provider.auth_device_async()

        call_kwargs = mock_kc_client.request_async.call_args.kwargs
        assert call_kwargs["data"]["client_id"] == "my-client"


class TestWellKnownAsync:
    @pytest.mark.asyncio
    async def test_get_issuer_uses_bearer_header(self, auth_provider_with_valid_token, mock_kc_client):
        mock_kc_client.request_async = AsyncMock(return_value=MagicMock())
        await auth_provider_with_valid_token.get_issuer_async()

        call_kwargs = mock_kc_client.request_async.call_args.kwargs
        assert call_kwargs["headers"]["Authorization"].startswith("Bearer ")

    @pytest.mark.asyncio
    async def test_get_openid_configuration_uses_well_known_url(
        self, auth_provider_with_valid_token, mock_kc_client
    ):
        mock_kc_client.request_async = AsyncMock(return_value=MagicMock())
        await auth_provider_with_valid_token.get_openid_configuration_async()

        call_kwargs = mock_kc_client.request_async.call_args.kwargs
        assert "openid-configuration" in call_kwargs["url"]

    @pytest.mark.asyncio
    async def test_get_uma2_configuration_uses_well_known_url(
        self, auth_provider_with_valid_token, mock_kc_client
    ):
        mock_kc_client.request_async = AsyncMock(return_value=MagicMock())
        await auth_provider_with_valid_token.get_uma2_configuration_async()

        call_kwargs = mock_kc_client.request_async.call_args.kwargs
        assert "uma2-configuration" in call_kwargs["url"]

    @pytest.mark.asyncio
    async def test_get_certs_uses_certs_url(self, auth_provider_with_valid_token, mock_kc_client):
        mock_kc_client.request_async = AsyncMock(return_value=MagicMock())
        await auth_provider_with_valid_token.get_certs_async()

        call_kwargs = mock_kc_client.request_async.call_args.kwargs
        assert "certs" in call_kwargs["url"]


class TestLogoutAsync:
    @pytest.mark.asyncio
    async def test_posts_to_logout_url(self, auth_provider, mock_kc_client):
        mock_kc_client.request_async = AsyncMock(return_value=MagicMock())
        await auth_provider.logout_async("ref-token")

        call_kwargs = mock_kc_client.request_async.call_args.kwargs
        assert call_kwargs["method"] == HttpMethod.POST
        assert "logout" in call_kwargs["url"]

    @pytest.mark.asyncio
    async def test_payload_contains_refresh_token(self, auth_provider, mock_kc_client):
        mock_kc_client.request_async = AsyncMock(return_value=MagicMock())
        await auth_provider.logout_async("my-refresh-token")

        call_kwargs = mock_kc_client.request_async.call_args.kwargs
        assert call_kwargs["data"]["refresh_token"] == "my-refresh-token"

    @pytest.mark.asyncio
    async def test_confidential_includes_client_secret_in_payload(self, auth_provider, mock_kc_client):
        mock_kc_client.request_async = AsyncMock(return_value=MagicMock())
        await auth_provider.logout_async("ref")

        call_kwargs = mock_kc_client.request_async.call_args.kwargs
        assert "client_secret" in call_kwargs["data"]


class TestRevokeAsync:
    @pytest.mark.asyncio
    async def test_confidential_uses_basic_auth(self, auth_provider, mock_kc_client):
        mock_kc_client.request_async = AsyncMock(return_value=MagicMock())
        await auth_provider.revoke_async("ref-token")

        call_kwargs = mock_kc_client.request_async.call_args.kwargs
        assert call_kwargs["headers"]["Authorization"].startswith("Basic ")

    @pytest.mark.asyncio
    async def test_public_client_uses_bearer_auth(self, base, token_manager, mock_kc_client):
        from pykeycloak.core.headers import HeadersFactory
        from pykeycloak.core.realm import RealmClient
        from pykeycloak.providers._base import KeycloakProviderBase

        public_rc = RealmClient(
            realm_name="r",
            client_uuid="550e8400-e29b-41d4-a716-446655440000",
            client_id="pub",
        )
        pub_base = KeycloakProviderBase(
            realm_client=public_rc,
            kc_headers=HeadersFactory(),
            kc_client=mock_kc_client,
        )
        mock_kc_client.request_async = AsyncMock(return_value=MagicMock())
        provider = AuthProvider(base=pub_base, token_manager=token_manager)
        await provider.revoke_async("ref-token")

        call_kwargs = mock_kc_client.request_async.call_args.kwargs
        assert call_kwargs["headers"]["Authorization"].startswith("Bearer ")

    @pytest.mark.asyncio
    async def test_posts_to_revoke_url(self, auth_provider, mock_kc_client):
        mock_kc_client.request_async = AsyncMock(return_value=MagicMock())
        await auth_provider.revoke_async("ref")

        call_kwargs = mock_kc_client.request_async.call_args.kwargs
        assert "revoke" in call_kwargs["url"]


class TestGetUserInfoAsync:
    @pytest.mark.asyncio
    async def test_uses_bearer_header(self, auth_provider, mock_kc_client):
        mock_kc_client.request_async = AsyncMock(return_value=MagicMock())
        await auth_provider.get_user_info_async(access_token="user-access-token")

        call_kwargs = mock_kc_client.request_async.call_args.kwargs
        assert call_kwargs["headers"]["Authorization"] == "Bearer user-access-token"

    @pytest.mark.asyncio
    async def test_gets_from_userinfo_url(self, auth_provider, mock_kc_client):
        mock_kc_client.request_async = AsyncMock(return_value=MagicMock())
        await auth_provider.get_user_info_async(access_token="tok")

        call_kwargs = mock_kc_client.request_async.call_args.kwargs
        assert call_kwargs["method"] == HttpMethod.GET
        assert "userinfo" in call_kwargs["url"]


class TestGetUmaPermissionAsync:
    @pytest.mark.asyncio
    async def test_posts_to_token_url(self, auth_provider, mock_kc_client):
        mock_kc_client.request_async = AsyncMock(return_value=MagicMock())
        payload = UMAAuthorizationPayload(permissions=["res1"], subject_token="sub-tok")
        await auth_provider.get_uma_permission_async(payload)

        call_kwargs = mock_kc_client.request_async.call_args.kwargs
        assert call_kwargs["method"] == HttpMethod.POST
        assert "token" in call_kwargs["url"]

    @pytest.mark.asyncio
    async def test_sets_audience_to_client_id_when_none(self, auth_provider, mock_kc_client):
        mock_kc_client.request_async = AsyncMock(return_value=MagicMock())
        payload = UMAAuthorizationPayload(permissions=["res1"], subject_token="sub-tok")
        await auth_provider.get_uma_permission_async(payload)

        call_kwargs = mock_kc_client.request_async.call_args.kwargs
        assert call_kwargs["data"]["audience"] == "my-client"

    @pytest.mark.asyncio
    async def test_does_not_override_explicit_audience(self, auth_provider, mock_kc_client):
        mock_kc_client.request_async = AsyncMock(return_value=MagicMock())
        payload = UMAAuthorizationPayload(
            permissions=["res1"], subject_token="sub-tok", audience="explicit-audience"
        )
        await auth_provider.get_uma_permission_async(payload)

        call_kwargs = mock_kc_client.request_async.call_args.kwargs
        assert call_kwargs["data"]["audience"] == "explicit-audience"
