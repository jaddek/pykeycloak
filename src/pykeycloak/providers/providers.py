import logging
from typing import Any

from httpx import Response

from pykeycloak.core.clients import (
    KeycloakHttpClientWrapperAsync,
    get_keycloak_client_wrapper_from_env,
)
from pykeycloak.core.headers import Headers, get_headers
from pykeycloak.core.urls import (
    REALM_CLIENT_OPENID_URL_AUTH_DEVICE,
    REALM_CLIENT_OPENID_URL_CERTS,
    REALM_CLIENT_OPENID_URL_INTROSPECT,
    REALM_CLIENT_OPENID_URL_LOGOUT,
    REALM_CLIENT_OPENID_URL_TOKEN,
    REALM_CLIENT_OPENID_URL_USERINFO,
)

from ..core.entities import RealmClient
from .payloads import (
    ObtainTokenPayload,
    RefreshTokenPayload,
    RTPIntrospectionPayload,
    TokenIntrospectionPayload,
    UMAAuthorizationPayload,
)

logger = logging.getLogger(__name__)


class KeycloakProviderAsync:
    def __init__(
        self,
        *,
        realm: str,
        realm_client: RealmClient,
        wrapper: KeycloakHttpClientWrapperAsync | None = None,
        headers: Headers | None = None,
    ) -> None:
        self._realm: str = realm
        self._realm_client: RealmClient = realm_client

        self._wrapper = wrapper or get_keycloak_client_wrapper_from_env()
        self._headers = headers or get_headers(
            access_token=self._realm_client.client_secret,
        )

    async def auth_device_async(self) -> Response:
        payload = {
            "client_id": self._realm_client.client_id,
            "client_secret": self._realm_client.client_secret,
        }

        with self._headers.override_with_form_urlencoded_headers():
            response = await self._wrapper.request(
                method="POST",
                url=self._get_path(path=REALM_CLIENT_OPENID_URL_AUTH_DEVICE),
                data=payload,
                headers=self._headers,
            )

        return response

    async def get_certs_async(self) -> Response:
        with self._headers.override_with_form_urlencoded_headers():
            response = await self._wrapper.request(
                method="GET",
                url=self._get_path(path=REALM_CLIENT_OPENID_URL_CERTS),
                headers=self._headers,
            )

        return response

    async def logout_async(self, refresh_token: str) -> Response:
        payload = {
            "client_id": self._realm_client.client_id,
            "refresh_token": refresh_token,
        }

        if self._realm_client.client_secret:
            payload |= {
                "client_secret": self._realm_client.client_secret,
            }

        with self._headers.override_with_form_urlencoded_headers():
            response = await self._wrapper.request(
                method="POST",
                url=self._get_path(path=REALM_CLIENT_OPENID_URL_LOGOUT),
                data=payload,
                headers=self._headers,
            )

        return response

    async def refresh_token_async(
        self,
        payload: RefreshTokenPayload,
    ) -> Response:
        _payload = payload.to_dict()
        _payload |= {
            "client_id": self._realm_client.client_id,
        }

        if self._realm_client.client_secret:
            _payload |= {
                "client_secret": self._realm_client.client_secret,
            }

        with self._headers.override_with_form_urlencoded_headers():
            response = await self._wrapper.request(
                method="POST",
                url=self._get_path(path=REALM_CLIENT_OPENID_URL_TOKEN),
                data=_payload,
                headers=self._headers,
            )

        return response

    async def get_user_info_async(
        self,
        access_token: str,
    ) -> Response:
        #  error="insufficient_scope", error_description="Missing openid scope" in headers
        with self._headers.override_with_form_urlencoded_headers(
            access_token=access_token
        ):
            response = await self._wrapper.request(
                method="GET",
                url=self._get_path(path=REALM_CLIENT_OPENID_URL_USERINFO),
                headers=self._headers,
            )

        return response

    async def obtain_token_async(
        self,
        payload: ObtainTokenPayload,
    ) -> Response:
        _payload = payload.to_dict()
        _payload |= {
            "client_id": self._realm_client.client_id,
            "client_secret": self._realm_client.client_secret,
        }

        with self._headers.override_with_form_urlencoded_headers():
            response = await self._wrapper.request(
                method="POST",
                url=self._get_path(path=REALM_CLIENT_OPENID_URL_TOKEN),
                data=_payload,
                headers=self._headers,
            )

        return response

    async def introspect_token_async(
        self, payload: RTPIntrospectionPayload | TokenIntrospectionPayload
    ) -> Response:

        if not self._realm_client.is_confidential:
            raise ValueError(
                "Introspection could be invoked only by confidential clients"
            )

        _payload = payload.to_dict()
        _payload |= {
            "client_id": self._realm_client.client_id,
            "client_secret": self._realm_client.client_secret,
        }

        access_token: str = str(self._realm_client.client_secret)

        if isinstance(_payload, RTPIntrospectionPayload):
            access_token = payload.token

        with self._headers.override_with_form_urlencoded_headers(
            access_token=access_token
        ):
            response = await self._wrapper.request(
                method="POST",
                url=self._get_path(path=REALM_CLIENT_OPENID_URL_INTROSPECT),
                data=_payload,
                headers=self._headers,
            )

        return response

    async def get_uma_permission_async(
        self,
        payload: UMAAuthorizationPayload,
        access_token: str,
    ) -> Response:
        with self._headers.override_with_form_urlencoded_headers(access_token):
            response = await self._wrapper.request(
                method="POST",
                url=self._get_path(path=REALM_CLIENT_OPENID_URL_TOKEN),
                data=payload.to_dict(),
                headers=self._headers,
            )

        return response

    async def close(self) -> None:
        await self._wrapper.client.aclose()

    def _get_path(self, path: str, **kwargs: Any) -> str:
        params = {"realm": self._realm, **kwargs}
        return path.format(**params)
