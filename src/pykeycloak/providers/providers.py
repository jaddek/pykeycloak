import json
import logging
from abc import ABC
from typing import Any, Callable, Awaitable
from uuid import UUID

from httpx import Response

from pykeycloak.core.clients import (
    KeycloakHttpClientWrapperAsync,
    get_keycloak_client_wrapper_from_env, HttpMethod,
)
from pykeycloak.core.headers import HeadersProtocol, HeaderFactory
from .payloads import (
    ObtainTokenPayload,
    RefreshTokenPayload,
    RTPIntrospectionPayload,
    TokenIntrospectionPayload,
    UMAAuthorizationPayload, CreateUserPayload, UserUpdateEnablePayload, UserUpdatePasswordPayload,
    RTPExchangeTokenPayload, ConfidentialClientRevokePayload, PublicClientRevokePayload,
)
from .queries import GetUsersQuery, RoleMembersListQuery, PaginationQuery, BriefRepresentationQuery
from ..core.realm import RealmClient
from ..core.token_manager import TokenManager, mark_need_token_verification, TokenAutoRefresher, \
    mark_need_access_token_initialization
from ..core.urls import (
    REALM_LOGOUT_ALL,
    REALM_CLIENT_OPENID_URL_TOKEN,
    REALM_CLIENT_OPENID_URL_LOGOUT, REALM_CLIENT_OPENID_URL_USERINFO,
    REALM_CLIENT_OPENID_URL_INTROSPECT, REALM_CLIENT_OPENID_URL_AUTH_DEVICE,
    REALM_CLIENT_OPENID_URL_CERTS, REALM_USERS_LIST, REALM_USERS_COUNT, REALM_USER,
    REALM_USER_LOGOUT, REALM_CLIENT_ROLES, REALM_CLIENT_ROLE_MEMBERS, REALM_USER_SESSIONS, REALM_DELETE_SESSION,
    REALM_CLIENT_USER_SESSIONS, REALM_CLIENT_ACTIVE_SESSION_COUNT, REALM_CLIENT_OFFLINE_SESSION_COUNT,
    REALM_CLIENT_OFFLINE_SESSIONS, REALM_CLIENT_USER_OFFLINE_SESSIONS, REALM_ROLES_ROLE_BY_ID, REALM_CLIENT_ROLE,
    REALM_ROLES_ROLE_BY_NAME, REALM_CLIENT_USER_ROLE_MAPPING, REALM_CLIENT_USER_ROLE_MAPPING_AVAILABLE,
    REALM_CLIENT_USER_ROLE_MAPPING_COMPOSITE, REALM_CLIENT_SESSION_STATS, REALM_CLIENT_OPENID_URL_REVOKE
)

logger = logging.getLogger(__name__)

class KeycloakProviderAsync(ABC):
    def __init__(
            self,
            *,
            realm: str,
            realm_client: RealmClient,
            headers: HeadersProtocol | None = None,
            wrapper: KeycloakHttpClientWrapperAsync | None = None,
    ) -> None:
        self._realm: str = realm
        self._realm_client: RealmClient = realm_client

        self._headers = headers or HeaderFactory()
        self._wrapper = wrapper or get_keycloak_client_wrapper_from_env()

    ##############################################################
    #  Auth/OpenID endpoints
    ##############################################################

    async def refresh_token_async(
            self,
            payload: RefreshTokenPayload | RTPExchangeTokenPayload,
    ) -> Response:
        if not self._realm_client.is_confidential:
            raise ValueError(
                "Introspection could be invoked only by confidential clients"
            )

        headers: dict | None = None

        match payload:
            case payload if isinstance(payload, RTPExchangeTokenPayload):
                headers = self._headers.openid_bearer(bearer_token=str(payload.refresh_token))

            case payload if isinstance(payload, RefreshTokenPayload):
                headers = self._headers.openid_basic(basic_token=self._realm_client.base64_auth())

            case _:
                raise TypeError(
                    f"Unsupported payload type: {type(payload).__name__}. "
                    "Expected RTPExchangeTokenPayload or RefreshTokenPayload"
                )

        response = await self._wrapper.request(
            method=HttpMethod.POST,
            url=self._get_path(path=REALM_CLIENT_OPENID_URL_TOKEN),
            data=payload.to_dict(),
            headers=headers
        )

        return response

    @mark_need_access_token_initialization
    async def obtain_token_async(
            self,
            *,
            payload: ObtainTokenPayload,
    ) -> Response:
        headers = self._headers.openid_basic(self._realm_client.base64_auth())

        response = await self._wrapper.request(
            method=HttpMethod.POST,
            url=self._get_path(path=REALM_CLIENT_OPENID_URL_TOKEN),
            data=payload.to_dict(),
            headers=headers,
        )

        return response

    @mark_need_token_verification
    async def introspect_token_async(
            self, payload: RTPIntrospectionPayload | TokenIntrospectionPayload
    ) -> Response:

        if not self._realm_client.is_confidential:
            raise ValueError(
                "Introspection could be invoked only by confidential clients"
            )

        headers: dict | None = None

        match payload:
            case payload if isinstance(payload, RTPIntrospectionPayload):
                headers = self._headers.openid_bearer(bearer_token=str(payload.token))
            case payload if isinstance(payload, TokenIntrospectionPayload):
                headers = self._headers.openid_basic(basic_token=self._realm_client.base64_auth())

            case _:
                raise TypeError(
                    f"Unsupported payload type: {type(payload).__name__}. "
                    "Expected RTPIntrospectionPayload or TokenIntrospectionPayload"
                )

        response = await self._wrapper.request(
            method=HttpMethod.POST,
            url=self._get_path(path=REALM_CLIENT_OPENID_URL_INTROSPECT),
            data=payload,
            headers=headers,
        )

        return response

    @mark_need_token_verification
    async def auth_device_async(
            self,
            access_token: str | None = None,
    ) -> Response:

        headers: dict = self._headers.openid_basic(basic_token=access_token)

        response = await self._wrapper.request(
            method=HttpMethod.POST,
            url=self._get_path(path=REALM_CLIENT_OPENID_URL_AUTH_DEVICE),
            data={},
            headers=headers,
        )

        return response

    @mark_need_token_verification
    async def get_certs_async(
            self,
            access_token: str | None = None,
    ) -> Response:

        headers: dict = self._headers.openid_bearer(bearer_token=access_token)

        response = await self._wrapper.request(
            method=HttpMethod.GET,
            url=self._get_path(path=REALM_CLIENT_OPENID_URL_CERTS),
            headers=headers,
        )

        return response

    async def logout_async(self, refresh_token: str) -> Response:
        payload = {
            "client_id": self._realm_client.client_id,
            "refresh_token": refresh_token,
        }

        if self._realm_client.is_confidential:
            payload |= {
                "client_secret": self._realm_client.client_secret,
            }

        headers: dict = self._headers.openid_bearer(bearer_token=self._realm_client.base64_auth())

        response = await self._wrapper.request(
            method=HttpMethod.POST,
            url=self._get_path(path=REALM_CLIENT_OPENID_URL_LOGOUT),
            data=payload,
            headers=headers,
        )

        return response

    async def revoke_async(self, refresh_token: str) -> Response:
        payload: ConfidentialClientRevokePayload | PublicClientRevokePayload | None = None
        headers: dict | None = None

        match self._realm_client.is_confidential:
            case True:
                payload = ConfidentialClientRevokePayload(token=refresh_token)

                headers = self._headers.openid_basic(basic_token=self._realm_client.base64_auth())

            case False:
                payload = PublicClientRevokePayload(
                    client_id=self._realm_client.client_id,
                    token=refresh_token
                )

                headers = self._headers.openid_bearer(bearer_token=str(payload.token))

        response = await self._wrapper.request(
            method=HttpMethod.POST,
            url=self._get_path(path=REALM_CLIENT_OPENID_URL_REVOKE),
            data=payload,
            headers=headers,
        )

        return response

    @mark_need_token_verification
    async def get_user_info_async(
            self,
            access_token: str,
    ) -> Response:
        headers = self._headers.openid_bearer(bearer_token=str(access_token))

        response = await self._wrapper.request(
            method=HttpMethod.GET,
            url=self._get_path(path=REALM_CLIENT_OPENID_URL_USERINFO),
            headers=headers,
        )

        return response

    ##############################################################
    #  Uma endpoints
    ##############################################################

    async def get_uma_permission_async(
            self,
            payload: UMAAuthorizationPayload,
    ) -> Response:
        headers = self._headers.openid_basic(basic_token=self._realm_client.base64_auth())

        response = await self._wrapper.request(
            method=HttpMethod.POST,
            url=self._get_path(path=REALM_CLIENT_OPENID_URL_TOKEN),
            data=payload.to_dict(),
            headers=headers,
        )

        return response

    ##############################################################
    #  Users
    ##############################################################

    @mark_need_token_verification
    async def get_users_count_async(
            self,
            query: GetUsersQuery | None = None,
            access_token: str | None = None,
    ) -> Response:

        headers = self._headers.keycloak_bearer(bearer_token=access_token)

        return await self._wrapper.request(
            method=HttpMethod.GET,
            url=self._get_path(path=REALM_USERS_COUNT),
            headers=headers,
            params=query,
        )

    @mark_need_token_verification
    async def get_users_async(
            self,
            query: GetUsersQuery | None = None,
            access_token: str | None = None,
    ) -> Response:
        headers = self._headers.keycloak_bearer(bearer_token=access_token)

        _query = query or GetUsersQuery()

        return await self._wrapper.request(
            method=HttpMethod.GET,
            url=self._get_path(path=REALM_USERS_LIST),
            headers=headers,
            params=_query,
        )

    @mark_need_token_verification
    async def get_user_async(
            self,
            user_id: str,
            access_token: str | None = None,
    ):
        headers = self._headers.keycloak_bearer(bearer_token=access_token)

        response = await self._wrapper.request(
            method=HttpMethod.GET,
            url=self._get_path(path=REALM_USER, user_id=user_id),
            headers=headers,
        )

        return response

    @mark_need_token_verification
    async def delete_user_async(
            self,
            user_id: str,
            access_token: str | None = None,
    ):
        headers = self._headers.keycloak_bearer(bearer_token=access_token)

        response = await self._wrapper.request(
            method=HttpMethod.DELETE,
            url=self._get_path(path=REALM_USER, user_id=user_id),
            headers=headers,
        )

        return response

    @mark_need_token_verification
    async def create_user_async(
            self,
            payload: CreateUserPayload,
            access_token: str | None = None,
    ) -> Response:
        headers = self._headers.keycloak_bearer(bearer_token=access_token)

        response = await self._wrapper.request(
            method=HttpMethod.POST,
            url=self._get_path(path=REALM_USERS_LIST),
            headers=headers,
            data=payload
        )

        return response

    @mark_need_token_verification
    async def update_user_by_id_async(
            self,
            user_id: str,
            payload: CreateUserPayload,
            access_token: str | None = None,
    ) -> Response:
        headers = self._headers.keycloak_bearer(bearer_token=access_token)

        response = await self._wrapper.request(
            method=HttpMethod.PUT,
            url=self._get_path(path=REALM_USER, user_id=user_id),
            headers=headers,
            data=payload,
        )

        return response

    @mark_need_token_verification
    async def update_user_enable_by_id_async(
            self,
            user_id: str,
            payload: UserUpdateEnablePayload,
            access_token: str | None = None,
    ) -> Response:
        headers = self._headers.keycloak_bearer(bearer_token=access_token)

        response = await self._wrapper.request(
            method=HttpMethod.PUT,
            url=self._get_path(path=REALM_USER, user_id=user_id),
            headers=headers,
            data=payload,
        )

        return response

    @mark_need_token_verification
    async def update_user_password_by_id_async(
            self,
            user_id: str,
            payload: UserUpdatePasswordPayload,
            access_token: str | None = None,
    ) -> Response:
        headers = self._headers.keycloak_bearer(bearer_token=access_token)

        response = await self._wrapper.request(
            method=HttpMethod.PUT,
            url=self._get_path(
                path=REALM_USER,
                user_id=user_id
            ),
            headers=headers,
            data=payload,
        )

        return response

    @mark_need_token_verification
    async def get_users_by_role_async(
            self,
            role_name: str,
            request_query: RoleMembersListQuery | None = None,
            access_token: str | None = None,
    ) -> Response:
        headers = self._headers.keycloak_bearer(bearer_token=access_token)

        response = await self._wrapper.request(
            method=HttpMethod.GET,
            url=self._get_path(
                path=REALM_CLIENT_ROLE_MEMBERS,
                role_name=role_name,
            ),
            headers=headers,
            params=request_query if request_query else {},
        )

        return response

    ##############################################################
    #  Sessions
    ##############################################################

    @mark_need_token_verification
    async def get_user_sessions_async(
            self,
            user_id: str,
            access_token: str | None = None,
    ) -> Response:
        headers = self._headers.keycloak_bearer(bearer_token=access_token)

        response = await self._wrapper.request(
            method=HttpMethod.GET,
            url=self._get_path(path=REALM_USER_SESSIONS, user_id=user_id),
            headers=headers,
        )

        return response

    @mark_need_token_verification
    async def delete_session_by_id_async(
            self,
            session_id: str,
            is_offline: bool,
            access_token: str | None = None,
    ) -> Response:
        headers = self._headers.keycloak_bearer(bearer_token=access_token)

        offline_status = "true" if is_offline else "false"

        response = await self._wrapper.request(
            method=HttpMethod.DELETE,
            url=self._get_path(path=REALM_DELETE_SESSION, session_id=session_id),
            headers=headers,
            params={"isOffline": offline_status},
        )

        return response

    @mark_need_token_verification
    async def get_client_user_sessions_async(
            self,
            request_query: PaginationQuery | None = None,
            access_token: str | None = None,
    ) -> Response:
        headers = self._headers.keycloak_bearer(bearer_token=access_token)

        response = await self._wrapper.request(
            method=HttpMethod.GET,
            url=self._get_path(path=REALM_CLIENT_USER_SESSIONS),
            headers=headers,
            params=request_query
        )

        return response

    @mark_need_token_verification
    async def get_client_sessions_count_async(
            self,
            access_token: str | None = None,
    ) -> Response:
        headers = self._headers.keycloak_bearer(bearer_token=access_token)

        response = await self._wrapper.request(
            method=HttpMethod.GET,
            url=self._get_path(path=REALM_CLIENT_ACTIVE_SESSION_COUNT),
            headers=headers,
        )

        return response

    @mark_need_token_verification
    async def get_offline_sessions_async(
            self,
            request_query: PaginationQuery | None = None,
            access_token: str | None = None,
    ) -> Response:
        headers = self._headers.keycloak_bearer(bearer_token=access_token)

        response = await self._wrapper.request(
            method=HttpMethod.GET,
            url=self._get_path(path=REALM_CLIENT_OFFLINE_SESSIONS),
            headers=headers,
            params=request_query
        )

        return response

    @mark_need_token_verification
    async def get_offline_sessions_count_async(
            self,
            access_token: str | None = None,
    ) -> Response:
        headers = self._headers.keycloak_bearer(bearer_token=access_token)

        response = await self._wrapper.request(
            method=HttpMethod.GET,
            url=self._get_path(path=REALM_CLIENT_OFFLINE_SESSION_COUNT),
            headers=headers,
        )

        return response

    @mark_need_token_verification
    async def remove_user_sessions_async(
            self,
            user_id: str,
            access_token: str | None = None,
    ) -> Response:
        headers = self._headers.keycloak_bearer(bearer_token=access_token)

        response = await self._wrapper.request(
            method=HttpMethod.POST,
            url=self._get_path(path=REALM_USER_LOGOUT, user_id=user_id),
            headers=headers,
        )

        return response

    @mark_need_token_verification
    async def logout_all_users_async(
            self,
            access_token: str | None = None,
    ):
        headers = self._headers.keycloak_bearer(bearer_token=access_token)

        response = await self._wrapper.request(
            method=HttpMethod.POST,
            url=self._get_path(path=REALM_LOGOUT_ALL),
            headers=headers,
        )

        return response

    @mark_need_token_verification
    async def get_client_session_stats_async(
            self,
            access_token: str | None = None,
    ) -> Response:
        headers = self._headers.keycloak_bearer(bearer_token=access_token)

        response = await self._wrapper.request(
            method=HttpMethod.GET,
            url=self._get_path(path=REALM_CLIENT_SESSION_STATS),
            headers=headers,
        )

        return response

    @mark_need_token_verification
    async def get_client_user_offline_sessions_async(
            self,
            user_id: str,
            access_token: str | None = None,
    ) -> Response:
        headers = self._headers.keycloak_bearer(bearer_token=access_token)

        response = await self._wrapper.request(
            method=HttpMethod.GET,
            url=self._get_path(path=REALM_CLIENT_USER_OFFLINE_SESSIONS, user_id=user_id),
            headers=headers,
        )

        return response

    ##############################################################
    #  Roles
    ##############################################################

    @mark_need_token_verification
    async def get_client_roles_async(
            self,
            access_token: str | None = None,
    ) -> Response:
        headers = self._headers.keycloak_bearer(bearer_token=access_token)

        response = await self._wrapper.request(
            method=HttpMethod.GET,
            url=self._get_path(path=REALM_CLIENT_ROLES, client_id=self._realm_client.client_uuid),
            headers=headers,
        )

        return response

    @mark_need_token_verification
    async def get_client_role_id_async(
            self,
            role_name: str,
            access_token: str | None = None,
    ) -> Response:
        headers = self._headers.keycloak_bearer(bearer_token=access_token)

        response = await self._wrapper.request(
            method=HttpMethod.GET,
            url=self._get_path(path=REALM_CLIENT_ROLE, role_name=role_name),
            headers=headers,
        )

        return response

    @mark_need_token_verification
    async def get_role_by_name_async(
            self,
            role_name: str,
            access_token: str | None = None,
    ) -> Response:
        headers = self._headers.keycloak_bearer(bearer_token=access_token)

        response = await self._wrapper.request(
            method=HttpMethod.GET,
            url=self._get_path(path=REALM_CLIENT_ROLE, role_name=role_name),
            headers=headers,
        )

        return response

    @mark_need_token_verification
    async def create_role(
            self,
            payload: dict,
            access_token: str | None = None,
    ) -> Response:
        headers = self._headers.keycloak_bearer(bearer_token=access_token)

        response = await self._wrapper.request(
            method=HttpMethod.POST,
            url=self._get_path(path=REALM_CLIENT_ROLES),
            headers=headers,
            data=payload,
        )

        return response

    @mark_need_token_verification
    async def update_role_by_id_async(
            self,
            role_id: UUID,
            payload: dict,
            access_token: str | None = None,
    ) -> Response:
        headers = self._headers.keycloak_bearer(bearer_token=access_token)

        response = await self._wrapper.request(
            method=HttpMethod.PUT,
            url=self._get_path(path=REALM_ROLES_ROLE_BY_ID, role_id=role_id),
            headers=headers,
            data=payload,
        )

        return response

    @mark_need_token_verification
    async def update_role_by_name_async(
            self,
            role_name: str,
            payload: dict,
            access_token: str | None = None,
    ) -> Response:
        headers = self._headers.keycloak_bearer(bearer_token=access_token)

        response = await self._wrapper.request(
            method=HttpMethod.PUT,
            url=self._get_path(path=REALM_ROLES_ROLE_BY_NAME, role_name=role_name),
            headers=headers,
            data=payload,
        )

        return response

    @mark_need_token_verification
    async def delete_role_by_id_async(
            self,
            role_id: UUID,
            access_token: str | None = None,
    ) -> Response:
        headers = self._headers.keycloak_bearer(bearer_token=access_token)

        response = await self._wrapper.request(
            method=HttpMethod.DELETE,
            url=self._get_path(path=REALM_ROLES_ROLE_BY_ID, role_id=role_id),
            headers=headers,
        )

        return response

    @mark_need_token_verification
    async def delete_role_by_name_async(
            self,
            role_name: str,
            access_token: str | None = None,
    ) -> Response:
        headers = self._headers.keycloak_bearer(bearer_token=access_token)

        response = await self._wrapper.request(
            method=HttpMethod.DELETE,
            url=self._get_path(path=REALM_ROLES_ROLE_BY_NAME, role_name=role_name),
            headers=headers,
        )

        return response

    @mark_need_token_verification
    async def assign_client_role_async(
            self,
            user_id: UUID,
            roles: list[str],
            access_token: str | None = None,
    ) -> Response:
        headers = self._headers.keycloak_bearer(bearer_token=access_token)

        response = await self._wrapper.request(
            method=HttpMethod.POST,
            url=self._get_path(path=REALM_CLIENT_USER_ROLE_MAPPING, user_id=user_id),
            headers=headers,
            data=json.dumps(roles),
        )

        return response

    @mark_need_token_verification
    async def get_client_roles_of_user_async(
            self,
            user_id: str,
            access_token: str | None = None,
    ) -> Response:
        headers = self._headers.keycloak_bearer(bearer_token=access_token)

        response = await self._wrapper.request(
            method=HttpMethod.GET,
            url=self._get_path(path=REALM_CLIENT_USER_ROLE_MAPPING, user_id=user_id),
            headers=headers,
        )

        return response

    @mark_need_token_verification
    async def get_composite_client_roles_of_user_async(
            self,
            user_id: str,
            request_query: BriefRepresentationQuery | None = None,
            access_token: str | None = None,
    ) -> Response:
        headers = self._headers.keycloak_bearer(bearer_token=access_token)

        response = await self._wrapper.request(
            method=HttpMethod.GET,
            url=self._get_path(path=REALM_CLIENT_USER_ROLE_MAPPING_COMPOSITE, user_id=user_id),
            headers=headers,
            params=request_query
        )

        return response

    @mark_need_token_verification
    async def get_available_client_roles_of_user_async(
            self,
            user_id: str,
            access_token: str | None = None,
    ) -> Response:
        headers = self._headers.keycloak_bearer(bearer_token=access_token)

        response = await self._wrapper.request(
            method=HttpMethod.GET,
            url=self._get_path(path=REALM_CLIENT_USER_ROLE_MAPPING_AVAILABLE, user_id=user_id),
            headers=headers,
        )

        return response

    @mark_need_token_verification
    async def delete_client_roles_of_user_async(
            self,
            user_id: str,
            roles: list[str],
            access_token: str | None = None,
    ) -> Response:
        headers = self._headers.keycloak_bearer(bearer_token=access_token)

        response = await self._wrapper.request(
            method=HttpMethod.DELETE,
            url=self._get_path(path=REALM_CLIENT_USER_ROLE_MAPPING, user_id=user_id),
            headers=headers,
            data=json.dumps(roles),
        )

        return response

    @mark_need_token_verification
    async def get_user_roles_async(
            self,
            user_id: str,
            access_token: str | None = None,
    ) -> Response:
        headers = self._headers.keycloak_bearer(bearer_token=access_token)

        response = await self._wrapper.request(
            method=HttpMethod.GET,
            url=self._get_path(path=REALM_CLIENT_USER_ROLE_MAPPING, user_id=user_id),
            headers=headers,
        )

        return response

    ##############################################################
    #  ...
    ##############################################################

    async def close(self) -> None:
        await self._wrapper.client.aclose()

    def _get_path(self, path: str, **kwargs: Any) -> str:
        params = {"realm": self._realm, "client_id": self._realm_client.client_id, **kwargs}
        return path.format(**params)

    ##############################################################
    #  Token manager
    ##############################################################

    def token_manager_update_access_token(self) -> Callable[[str], Awaitable[Response]]:
        async def _refresh(refresh_token: str) -> Response:
            return await self.refresh_token_async(
                payload=RefreshTokenPayload(refresh_token=refresh_token)
            )

        return _refresh


token_manager = TokenManager()


@TokenAutoRefresher(token_manager=token_manager)
class KeycloakInMemoryProviderAsync(KeycloakProviderAsync):
    ...
