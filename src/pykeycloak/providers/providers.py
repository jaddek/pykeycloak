# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Anton "Tony" Nazarov <tonynazarov+dev@gmail.com>

import json
import logging
from collections.abc import Awaitable, Callable
from typing import Any, Protocol
from uuid import UUID

from httpx import Response

from pykeycloak.core.clients import (
    HttpMethod,
    KeycloakHttpClientWrapperAsync,
    get_keycloak_client_wrapper_from_env,
)
from pykeycloak.core.headers import HeaderFactory, HeadersProtocol
from pykeycloak.providers.payloads import RolePayload

from ..core.exceptions import PyKeycloakUnexpectedBehaviourException
from ..core.realm import RealmClient
from ..core.token_manager import (
    TokenAutoRefresher,
    TokenManager,
    mark_need_access_token_initialization,
    mark_need_token_verification,
)
from ..core.urls import (
    REALM_CLIENT,
    REALM_CLIENT_ACTIVE_SESSION_COUNT,
    REALM_CLIENT_AUTHZ_SCOPES,
    REALM_CLIENT_AUTHZ_SETTINGS,
    REALM_CLIENT_OFFLINE_SESSION_COUNT,
    REALM_CLIENT_OFFLINE_SESSIONS,
    REALM_CLIENT_OPENID_URL_AUTH_DEVICE,
    REALM_CLIENT_OPENID_URL_CERTS,
    REALM_CLIENT_OPENID_URL_INTROSPECT,
    REALM_CLIENT_OPENID_URL_LOGOUT,
    REALM_CLIENT_OPENID_URL_REVOKE,
    REALM_CLIENT_OPENID_URL_TOKEN,
    REALM_CLIENT_OPENID_URL_USERINFO,
    REALM_CLIENT_ROLE,
    REALM_CLIENT_ROLE_MEMBERS,
    REALM_CLIENT_ROLES,
    REALM_CLIENT_SESSION_STATS,
    REALM_CLIENT_USER_OFFLINE_SESSIONS,
    REALM_CLIENT_USER_ROLE_MAPPING,
    REALM_CLIENT_USER_ROLE_MAPPING_AVAILABLE,
    REALM_CLIENT_USER_ROLE_MAPPING_COMPOSITE,
    REALM_CLIENT_USER_SESSIONS,
    REALM_CLIENTS,
    REALM_DELETE_SESSION,
    REALM_LOGOUT_ALL,
    REALM_ROLES_DELETE_ROLE_BY_NAME,
    REALM_ROLES_ROLE_BY_ID,
    REALM_USER,
    REALM_USER_LOGOUT,
    REALM_USER_SESSIONS,
    REALM_USERS_COUNT,
    REALM_USERS_LIST,
)
from .payloads import (
    ConfidentialClientRevokePayload,
    CreateUserPayload,
    ObtainTokenPayload,
    PublicClientRevokePayload,
    RefreshTokenPayload,
    RTPExchangeTokenPayload,
    RTPIntrospectionPayload,
    TokenIntrospectionPayload,
    UMAAuthorizationPayload,
    UserUpdateEnablePayload,
    UserUpdatePasswordPayload,
)
from .queries import (
    BriefRepresentationQuery,
    GetUsersQuery,
    PaginationQuery,
    RoleMembersListQuery,
)

logger = logging.getLogger(__name__)


class KeycloakProviderProtocol(Protocol):
    async def refresh_token_async(
        self,
        payload: RefreshTokenPayload | RTPExchangeTokenPayload,
    ) -> Response: ...

    async def obtain_token_async(
        self,
        *,
        payload: ObtainTokenPayload,
    ) -> Response: ...

    async def introspect_token_async(
        self, payload: RTPIntrospectionPayload | TokenIntrospectionPayload
    ) -> Response: ...

    async def auth_device_async(self, access_token: str = ...) -> Response: ...

    async def get_certs_async(self, access_token: str = ...) -> Response: ...

    async def logout_async(self, refresh_token: str) -> Response: ...

    async def revoke_async(self, refresh_token: str) -> Response: ...

    async def get_user_info_async(
        self,
        access_token: str = ...,
    ) -> Response: ...

    async def get_uma_permission_async(
        self,
        payload: UMAAuthorizationPayload,
    ) -> Response: ...

    async def get_users_count_async(
        self,
        access_token: str = ...,
        query: GetUsersQuery | None = None,
    ) -> Response: ...

    async def get_users_async(
        self,
        access_token: str = ...,
        query: GetUsersQuery | None = None,
    ) -> Response: ...

    async def get_user_async(
        self, user_id: UUID | str, access_token: str = ...
    ) -> Response: ...

    async def delete_user_async(
        self, user_id: UUID | str, access_token: str = ...
    ) -> Response: ...

    async def create_user_async(
        self, payload: CreateUserPayload, access_token: str = ...
    ) -> Response: ...

    async def update_user_by_id_async(
        self, user_id: UUID | str, payload: CreateUserPayload, access_token: str = ...
    ) -> Response: ...

    async def update_user_enable_by_id_async(
        self,
        user_id: UUID | str,
        payload: UserUpdateEnablePayload,
        access_token: str = ...,
    ) -> Response: ...

    async def update_user_password_by_id_async(
        self,
        user_id: UUID | str,
        payload: UserUpdatePasswordPayload,
        access_token: str = ...,
    ) -> Response: ...

    async def get_users_by_role_async(
        self,
        role_name: str,
        access_token: str = ...,
        request_query: RoleMembersListQuery | None = None,
    ) -> Response: ...

    async def get_user_sessions_async(
        self, user_id: UUID | str, access_token: str = ...
    ) -> Response: ...

    async def delete_session_by_id_async(
        self, session_id: UUID, is_offline: bool, access_token: str = ...
    ) -> Response: ...

    async def get_client_user_sessions_async(
        self,
        access_token: str = ...,
        request_query: PaginationQuery | None = None,
    ) -> Response: ...

    async def get_client_sessions_count_async(
        self, access_token: str = ...
    ) -> Response: ...

    async def get_offline_sessions_async(
        self,
        access_token: str = ...,
        query: PaginationQuery | None = None,
    ) -> Response: ...

    async def get_offline_sessions_count_async(
        self, access_token: str = ...
    ) -> Response: ...

    async def remove_user_sessions_async(
        self, user_id: UUID | str, access_token: str = ...
    ) -> Response: ...

    async def logout_all_users_async(self, access_token: str = ...) -> Response: ...

    async def get_client_session_stats_async(
        self,
        access_token: str = ...,
    ) -> Response: ...

    async def get_client_sessions_async(
        self, access_token: str = ..., query: PaginationQuery | None = None
    ) -> Response: ...

    async def get_client_user_offline_sessions_async(
        self, user_id: UUID | str, access_token: str = ...
    ) -> Response: ...

    async def get_client_roles_async(self, access_token: str = ...) -> Response: ...

    async def get_client_role_id_async(
        self, role_name: str, access_token: str = ...
    ) -> Response: ...

    async def get_role_by_name_async(
        self, role_name: str, access_token: str = ...
    ) -> Response: ...

    async def create_role_async(
        self, payload: RolePayload, access_token: str = ...
    ) -> Response: ...

    async def update_role_by_id_async(
        self,
        role_id: UUID | str,
        payload: RolePayload,
        access_token: str = ...,
        skip_unexpected_behaviour_exception: bool = False,
    ) -> Response: ...

    async def update_role_by_name_async(
        self, role_name: str, payload: RolePayload, access_token: str = ...
    ) -> Response: ...

    async def delete_role_by_id_async(
        self, role_id: UUID | str, access_token: str = ...
    ) -> Response: ...

    async def delete_role_by_name_async(
        self, role_name: str, access_token: str = ...
    ) -> Response: ...

    async def assign_client_role_async(
        self, user_id: UUID | str, roles: list[str], access_token: str = ...
    ) -> Response: ...

    async def get_client_roles_of_user_async(
        self, user_id: UUID | str, access_token: str = ...
    ) -> Response: ...

    async def get_composite_client_roles_of_user_async(
        self,
        user_id: UUID | str,
        access_token: str = ...,
        request_query: BriefRepresentationQuery | None = None,
    ) -> Response: ...

    async def get_available_client_roles_of_user_async(
        self, user_id: UUID | str, access_token: str = ...
    ) -> Response: ...

    async def delete_client_roles_of_user_async(
        self, user_id: UUID | str, roles: list[str], access_token: str = ...
    ) -> Response: ...

    async def get_user_roles_async(
        self, user_id: UUID | str, access_token: str = ...
    ) -> Response: ...

    async def get_clients_async(self, access_token: str = ...) -> Response: ...

    async def get_client_async(self, access_token: str = ...) -> Response: ...

    async def get_client_authz_settings(self, access_token: str = ...) -> Response: ...

    async def get_client_authz_scopes_async(
        self, access_token: str = ...
    ) -> Response: ...


class KeycloakProviderAsync:
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
    #  Clint endpoints
    ##############################################################

    @mark_need_token_verification
    async def get_clients_async(self, access_token: str) -> Response:
        headers = self._headers.keycloak_bearer(bearer_token=access_token)

        response = await self._wrapper.request(
            method=HttpMethod.GET,
            url=self._get_path(path=REALM_CLIENTS),
            headers=headers,
        )

        return response

    @mark_need_token_verification
    async def get_client_async(self, access_token: str) -> Response:
        headers = self._headers.keycloak_bearer(bearer_token=access_token)

        response = await self._wrapper.request(
            method=HttpMethod.GET,
            url=self._get_path(path=REALM_CLIENT),
            headers=headers,
        )

        return response

    ##############################################################
    #  Authz endpoints
    ##############################################################

    @mark_need_token_verification
    async def get_client_authz_settings(self, access_token: str) -> Response:
        headers = self._headers.keycloak_bearer(bearer_token=access_token)

        response = await self._wrapper.request(
            method=HttpMethod.GET,
            url=self._get_path(path=REALM_CLIENT_AUTHZ_SETTINGS),
            headers=headers,
        )

        return response

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

        headers: dict[str, str] | None = None

        match payload:
            case payload if isinstance(payload, RTPExchangeTokenPayload):
                headers = self._headers.openid_bearer(
                    bearer_token=str(payload.refresh_token)
                )

            case payload if isinstance(payload, RefreshTokenPayload):
                headers = self._headers.openid_basic(
                    basic_token=self._realm_client.base64_auth()
                )

            case _:
                raise TypeError(
                    f"Unsupported payload type: {type(payload).__name__}. "
                    "Expected RTPExchangeTokenPayload or RefreshTokenPayload"
                )

        response = await self._wrapper.request(
            method=HttpMethod.POST,
            url=self._get_path(path=REALM_CLIENT_OPENID_URL_TOKEN),
            data=payload.to_dict(),
            headers=headers,
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

        headers: dict[str, str] | None = None

        match payload:
            case payload if isinstance(payload, RTPIntrospectionPayload):
                headers = self._headers.openid_bearer(bearer_token=str(payload.token))
            case payload if isinstance(payload, TokenIntrospectionPayload):
                headers = self._headers.openid_basic(
                    basic_token=self._realm_client.base64_auth()
                )

            case _:
                raise TypeError(
                    f"Unsupported payload type: {type(payload).__name__}. "
                    "Expected RTPIntrospectionPayload or TokenIntrospectionPayload"
                )

        response = await self._wrapper.request(
            method=HttpMethod.POST,
            url=self._get_path(path=REALM_CLIENT_OPENID_URL_INTROSPECT),
            data=payload.to_dict(),
            headers=headers,
        )

        return response

    @mark_need_token_verification
    async def auth_device_async(self, access_token: str) -> Response:
        headers: dict[str, str] = self._headers.openid_basic(basic_token=access_token)

        response = await self._wrapper.request(
            method=HttpMethod.POST,
            url=self._get_path(path=REALM_CLIENT_OPENID_URL_AUTH_DEVICE),
            data={},
            headers=headers,
        )

        return response

    @mark_need_token_verification
    async def get_certs_async(self, access_token: str) -> Response:
        headers: dict[str, str] = self._headers.openid_bearer(bearer_token=access_token)

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

        if self._realm_client.client_secret:
            payload |= {
                "client_secret": self._realm_client.client_secret,
            }

        headers: dict[str, str] = self._headers.openid_bearer(
            bearer_token=self._realm_client.base64_auth()
        )

        response = await self._wrapper.request(
            method=HttpMethod.POST,
            url=self._get_path(path=REALM_CLIENT_OPENID_URL_LOGOUT),
            data=payload,
            headers=headers,
        )

        return response

    async def revoke_async(self, refresh_token: str) -> Response:
        payload: ConfidentialClientRevokePayload | PublicClientRevokePayload | None = (
            None
        )
        headers: dict[str, str] | None = None

        match self._realm_client.is_confidential:
            case True:
                payload = ConfidentialClientRevokePayload(token=refresh_token)

                headers = self._headers.openid_basic(
                    basic_token=self._realm_client.base64_auth()
                )

            case False:
                payload = PublicClientRevokePayload(
                    client_id=self._realm_client.client_id, token=refresh_token
                )

                headers = self._headers.openid_bearer(bearer_token=str(payload.token))

        response = await self._wrapper.request(
            method=HttpMethod.POST,
            url=self._get_path(path=REALM_CLIENT_OPENID_URL_REVOKE),
            data=payload.to_dict(),
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
        headers = self._headers.openid_basic(
            basic_token=self._realm_client.base64_auth()
        )

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
        access_token: str,
        query: GetUsersQuery | None = None,
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
        access_token: str,
        query: GetUsersQuery | None = None,
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
    async def get_user_async(self, user_id: UUID | str, access_token: str) -> Response:
        headers = self._headers.keycloak_bearer(bearer_token=access_token)

        response = await self._wrapper.request(
            method=HttpMethod.GET,
            url=self._get_path(path=REALM_USER, user_id=user_id),
            headers=headers,
        )

        return response

    @mark_need_token_verification
    async def delete_user_async(
        self, user_id: UUID | str, access_token: str
    ) -> Response:
        headers = self._headers.keycloak_bearer(bearer_token=access_token)

        response = await self._wrapper.request(
            method=HttpMethod.DELETE,
            url=self._get_path(path=REALM_USER, user_id=user_id),
            headers=headers,
        )

        return response

    @mark_need_token_verification
    async def create_user_async(
        self, payload: CreateUserPayload, access_token: str
    ) -> Response:
        headers = self._headers.keycloak_bearer(bearer_token=access_token)

        response = await self._wrapper.request(
            method=HttpMethod.POST,
            url=self._get_path(path=REALM_USERS_LIST),
            headers=headers,
            data=payload.to_dict(),
        )

        return response

    @mark_need_token_verification
    async def update_user_by_id_async(
        self, user_id: UUID | str, payload: CreateUserPayload, access_token: str
    ) -> Response:
        headers = self._headers.keycloak_bearer(bearer_token=access_token)

        response = await self._wrapper.request(
            method=HttpMethod.PUT,
            url=self._get_path(path=REALM_USER, user_id=user_id),
            headers=headers,
            data=payload.to_dict(),
        )

        return response

    @mark_need_token_verification
    async def update_user_enable_by_id_async(
        self, user_id: UUID | str, payload: UserUpdateEnablePayload, access_token: str
    ) -> Response:
        headers = self._headers.keycloak_bearer(bearer_token=access_token)

        response = await self._wrapper.request(
            method=HttpMethod.PUT,
            url=self._get_path(path=REALM_USER, user_id=user_id),
            headers=headers,
            data=payload.to_dict(),
        )

        return response

    @mark_need_token_verification
    async def update_user_password_by_id_async(
        self, user_id: UUID | str, payload: UserUpdatePasswordPayload, access_token: str
    ) -> Response:
        headers = self._headers.keycloak_bearer(bearer_token=access_token)

        response = await self._wrapper.request(
            method=HttpMethod.PUT,
            url=self._get_path(path=REALM_USER, user_id=user_id),
            headers=headers,
            data=payload.to_dict(),
        )

        return response

    @mark_need_token_verification
    async def get_users_by_role_async(
        self,
        role_name: str,
        access_token: str,
        request_query: RoleMembersListQuery | None = None,
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
    async def get_client_sessions_async(
        self, access_token: str, query: PaginationQuery | None = None
    ) -> Response:
        headers = self._headers.keycloak_bearer(bearer_token=access_token)

        response = await self._wrapper.request(
            method=HttpMethod.GET,
            url=self._get_path(
                path=REALM_CLIENT_USER_SESSIONS, id=self._realm_client.client_uuid
            ),
            headers=headers,
            params=query.to_dict() if query else {},
        )

        return response

    @mark_need_token_verification
    async def get_user_sessions_async(
        self, user_id: UUID | str, access_token: str
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
        self, session_id: UUID, is_offline: bool, access_token: str
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
        access_token: str,
        request_query: PaginationQuery | None = None,
    ) -> Response:
        headers = self._headers.keycloak_bearer(bearer_token=access_token)

        response = await self._wrapper.request(
            method=HttpMethod.GET,
            url=self._get_path(path=REALM_CLIENT_USER_SESSIONS),
            headers=headers,
            params=request_query,
        )

        return response

    @mark_need_token_verification
    async def get_client_sessions_count_async(self, access_token: str) -> Response:
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
        access_token: str,
        query: PaginationQuery | None = None,
    ) -> Response:
        headers = self._headers.keycloak_bearer(bearer_token=access_token)

        response = await self._wrapper.request(
            method=HttpMethod.GET,
            url=self._get_path(path=REALM_CLIENT_OFFLINE_SESSIONS),
            headers=headers,
            params=query,
        )

        return response

    @mark_need_token_verification
    async def get_offline_sessions_count_async(self, access_token: str) -> Response:
        headers = self._headers.keycloak_bearer(bearer_token=access_token)

        response = await self._wrapper.request(
            method=HttpMethod.GET,
            url=self._get_path(path=REALM_CLIENT_OFFLINE_SESSION_COUNT),
            headers=headers,
        )

        return response

    @mark_need_token_verification
    async def remove_user_sessions_async(
        self, user_id: UUID | str, access_token: str
    ) -> Response:
        headers = self._headers.keycloak_bearer(bearer_token=access_token)

        response = await self._wrapper.request(
            method=HttpMethod.POST,
            url=self._get_path(path=REALM_USER_LOGOUT, user_id=user_id),
            headers=headers,
        )

        return response

    @mark_need_token_verification
    async def logout_all_users_async(self, access_token: str) -> Response:
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
        access_token: str,
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
        self, user_id: UUID | str, access_token: str
    ) -> Response:
        headers = self._headers.keycloak_bearer(bearer_token=access_token)

        response = await self._wrapper.request(
            method=HttpMethod.GET,
            url=self._get_path(
                path=REALM_CLIENT_USER_OFFLINE_SESSIONS, user_id=user_id
            ),
            headers=headers,
        )

        return response

    ##############################################################
    #  Roles
    ##############################################################

    @mark_need_token_verification
    async def get_client_roles_async(self, access_token: str) -> Response:
        headers = self._headers.keycloak_bearer(bearer_token=access_token)

        response = await self._wrapper.request(
            method=HttpMethod.GET,
            url=self._get_path(
                path=REALM_CLIENT_ROLES, client_id=self._realm_client.client_uuid
            ),
            headers=headers,
        )

        return response

    @mark_need_token_verification
    async def get_client_role_id_async(
        self, role_name: str, access_token: str
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
        self, role_name: str, access_token: str
    ) -> Response:
        headers = self._headers.keycloak_bearer(bearer_token=access_token)

        response = await self._wrapper.request(
            method=HttpMethod.GET,
            url=self._get_path(path=REALM_CLIENT_ROLE, role_name=role_name),
            headers=headers,
        )

        return response

    @mark_need_token_verification
    async def create_role_async(
        self, payload: RolePayload, access_token: str
    ) -> Response:
        headers = self._headers.keycloak_bearer(bearer_token=access_token)

        response = await self._wrapper.request(
            method=HttpMethod.POST,
            url=self._get_path(path=REALM_CLIENT_ROLES),
            headers=headers,
            data=payload.to_json(),
        )

        return response

    @mark_need_token_verification
    async def update_role_by_id_async(
        self,
        role_id: UUID | str,
        payload: RolePayload,
        access_token: str,
        skip_unexpected_behaviour_exception: bool = False,
    ) -> Response:
        """
        !!!WARNING!!!
        v26.3.3 will create a new role if you send description and name.
        !!!WARNING!!!

        :param role_id:
        :param payload:
        :param access_token:
        :param skip_unexpected_behaviour_exception:
        :return:
        """
        if not skip_unexpected_behaviour_exception:
            raise PyKeycloakUnexpectedBehaviourException(
                message="Warning! Unexpected Keycloak API behavior encountered.",
                description=(
                    "The Keycloak API requires 'name' and 'description', yet produces inconsistent results: "
                    "setting the correct name returns 409 (Conflict), omitting it returns 500 (Internal Error), "
                    "and any other name returns 201 (Created). Updating both name and description results "
                    "in an entirely new role instead of an update."
                ),
                affected_versions=["26.3.3"],
            )

        headers = self._headers.keycloak_bearer(bearer_token=access_token)

        response = await self._wrapper.request(
            method=HttpMethod.PUT,
            url=self._get_path(path=REALM_ROLES_ROLE_BY_ID, role_id=str(role_id)),
            headers=headers,
            data=json.dumps(payload.to_dict()),
        )

        return response

    @mark_need_token_verification
    async def update_role_by_name_async(
        self, role_name: str, payload: RolePayload, access_token: str
    ) -> Response:
        headers = self._headers.keycloak_bearer(bearer_token=access_token)

        response = await self._wrapper.request(
            method=HttpMethod.PUT,
            url=self._get_path(
                path=REALM_CLIENT_ROLE,
                role_name=role_name,
            ),
            headers=headers,
            data=json.dumps(payload.to_dict()),
        )

        return response

    @mark_need_token_verification
    async def delete_role_by_id_async(
        self, role_id: UUID | str, access_token: str
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
        self, role_name: str, access_token: str
    ) -> Response:
        headers = self._headers.keycloak_bearer(bearer_token=access_token)

        response = await self._wrapper.request(
            method=HttpMethod.DELETE,
            url=self._get_path(
                path=REALM_ROLES_DELETE_ROLE_BY_NAME, role_name=role_name
            ),
            headers=headers,
        )

        return response

    @mark_need_token_verification
    async def assign_client_role_async(
        self, user_id: UUID | str, roles: list[str], access_token: str
    ) -> Response:
        headers = self._headers.keycloak_bearer(bearer_token=access_token)

        response = await self._wrapper.request(
            method=HttpMethod.POST,
            url=self._get_path(
                path=REALM_CLIENT_USER_ROLE_MAPPING, user_id=str(user_id)
            ),
            headers=headers,
            data=json.dumps(roles),
        )

        return response

    @mark_need_token_verification
    async def get_client_roles_of_user_async(
        self, user_id: UUID | str, access_token: str
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
        user_id: UUID | str,
        access_token: str,
        request_query: BriefRepresentationQuery | None = None,
    ) -> Response:
        headers = self._headers.keycloak_bearer(bearer_token=access_token)

        response = await self._wrapper.request(
            method=HttpMethod.GET,
            url=self._get_path(
                path=REALM_CLIENT_USER_ROLE_MAPPING_COMPOSITE, user_id=user_id
            ),
            headers=headers,
            params=request_query,
        )

        return response

    @mark_need_token_verification
    async def get_available_client_roles_of_user_async(
        self, user_id: UUID | str, access_token: str
    ) -> Response:
        headers = self._headers.keycloak_bearer(bearer_token=access_token)

        response = await self._wrapper.request(
            method=HttpMethod.GET,
            url=self._get_path(
                path=REALM_CLIENT_USER_ROLE_MAPPING_AVAILABLE, user_id=user_id
            ),
            headers=headers,
        )

        return response

    @mark_need_token_verification
    async def delete_client_roles_of_user_async(
        self, user_id: UUID | str, roles: list[str], access_token: str
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
        self, user_id: UUID | str, access_token: str
    ) -> Response:
        headers = self._headers.keycloak_bearer(bearer_token=access_token)

        response = await self._wrapper.request(
            method=HttpMethod.GET,
            url=self._get_path(path=REALM_CLIENT_USER_ROLE_MAPPING, user_id=user_id),
            headers=headers,
        )

        return response

    ##############################################################
    #  Authz Scopes
    ##############################################################

    @mark_need_token_verification
    async def get_client_authz_scopes_async(self, access_token: str) -> Response:
        headers = self._headers.keycloak_bearer(bearer_token=access_token)

        response = await self._wrapper.request(
            method=HttpMethod.GET,
            url=self._get_path(path=REALM_CLIENT_AUTHZ_SCOPES),
            headers=headers,
        )

        return response

    ##############################################################
    #  Authz Resources
    ##############################################################

    ##############################################################
    #  Authz Policies
    ##############################################################

    ##############################################################
    #  Authz Permissions
    ##############################################################

    ##############################################################
    #  ...
    ##############################################################

    async def close(self) -> None:
        await self._wrapper.client.aclose()

    def _get_path(self, path: str, **kwargs: Any) -> str:
        params = {
            "realm": self._realm,
            "client_id": self._realm_client.client_id,
            "client_uuid": self._realm_client.client_uuid,
            **kwargs,
        }
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


@TokenAutoRefresher(token_manager=TokenManager())
class KeycloakInMemoryProviderAsync(KeycloakProviderAsync): ...
