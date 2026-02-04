# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Anton "Tony" Nazarov <tonynazarov+dev@gmail.com>

import json
import logging
from collections.abc import Awaitable, Callable
from typing import TYPE_CHECKING, Any, Unpack
from uuid import UUID

from pykeycloak.core.clients import (
    HttpMethod,
    KeycloakHttpClientWrapperAsync,
)
from pykeycloak.core.headers import HeadersProtocol
from pykeycloak.providers.payloads import (
    PermissionPayload,
    PermissionScopesPayload,
    ResourcePayload,
    RolePayload,
    RolePolicyPayload,
    UpdateUserPayload,
)

from ..core.exceptions import (
    AccessTokenIsRequiredError,
    KeycloakUnexpectedBehaviourException,
)
from ..core.protocols import KeycloakProviderProtocol, ResponseProtocol
from ..core.realm import Realm, RealmClient
from ..core.token_manager import (
    TokenAutoRefresher,
    TokenManager,
    inject_verified_access_token,
    mark_need_access_token_initialization,
)
from ..core.types import InternalAccessToken
from ..core.urls import (
    REALM_CLIENT,
    REALM_CLIENT_ACTIVE_SESSION_COUNT,
    REALM_CLIENT_AUTHZ_CLIENT_POLICY_ASSOCIATED_ROLE_POLICIES,
    REALM_CLIENT_AUTHZ_PERMISSION_SCOPE,
    REALM_CLIENT_AUTHZ_PERMISSIONS,
    REALM_CLIENT_AUTHZ_POLICIES,
    REALM_CLIENT_AUTHZ_POLICY,
    REALM_CLIENT_AUTHZ_POLICY_SCOPES,
    REALM_CLIENT_AUTHZ_RESOURCE,
    REALM_CLIENT_AUTHZ_RESOURCE_BASED_PERMISSION,
    REALM_CLIENT_AUTHZ_RESOURCE_PERMISSION,
    REALM_CLIENT_AUTHZ_RESOURCE_PERMISSIONS,
    REALM_CLIENT_AUTHZ_RESOURCE_POLICY_ROLE,
    REALM_CLIENT_AUTHZ_RESOURCE_POLICY_SEARCH,
    REALM_CLIENT_AUTHZ_RESOURCE_POLICY_USER,
    REALM_CLIENT_AUTHZ_RESOURCES,
    REALM_CLIENT_AUTHZ_SCOPE_BASED_PERMISSION,
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
    FilterFindPolicyParams,
    FindPermissionQuery,
    GetUsersQuery,
    PaginationQuery,
    ResourcesListQuery,
    RoleMembersListQuery,
)

logger = logging.getLogger(__name__)


class KeycloakProviderAsync:
    def __init__(
        self,
        *,
        realm: Realm,
        realm_client: RealmClient,
        headers: HeadersProtocol,
        wrapper: KeycloakHttpClientWrapperAsync,
    ) -> None:
        self._realm: Realm = realm
        self._realm_client: RealmClient = realm_client

        self._headers = headers
        self._wrapper = wrapper

    ##############################################################
    #  Clint endpoints
    ##############################################################

    @inject_verified_access_token
    async def get_clients_async(
        self,
        **kwargs: Unpack[InternalAccessToken],
    ) -> ResponseProtocol:
        access_token: str = self.get_access_token(**kwargs)
        headers = self._headers.keycloak_bearer(bearer_token=access_token)

        response = await self._wrapper.request_async(
            method=HttpMethod.GET,
            url=self._get_path(path=REALM_CLIENTS),
            headers=headers,
        )

        return response

    @inject_verified_access_token
    async def get_client_async(
        self,
        **kwargs: Unpack[InternalAccessToken],
    ) -> ResponseProtocol:
        access_token: str = self.get_access_token(**kwargs)
        headers = self._headers.keycloak_bearer(bearer_token=access_token)

        response = await self._wrapper.request_async(
            method=HttpMethod.GET,
            url=self._get_path(path=REALM_CLIENT),
            headers=headers,
        )

        return response

    ##############################################################
    #  Authz endpoints
    ##############################################################

    @inject_verified_access_token
    async def get_client_authz_settings(
        self,
        **kwargs: Unpack[InternalAccessToken],
    ) -> ResponseProtocol:
        access_token: str = self.get_access_token(**kwargs)
        headers = self._headers.keycloak_bearer(bearer_token=access_token)

        response = await self._wrapper.request_async(
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
    ) -> ResponseProtocol:
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
                    basic_token=self._realm_client.base64_encoded_client_secret()
                )

            case _:
                raise TypeError(
                    f"Unsupported payload type: {type(payload).__name__}. "
                    "Expected RTPExchangeTokenPayload or RefreshTokenPayload"
                )

        response = await self._wrapper.request_async(
            method=HttpMethod.POST,
            url=self._get_path(path=REALM_CLIENT_OPENID_URL_TOKEN),
            data=payload.to_dict(),
            headers=headers,
        )

        return response

    @mark_need_access_token_initialization
    async def obtain_token_async(
        self,
        payload: ObtainTokenPayload,
    ) -> ResponseProtocol:
        headers = self._headers.openid_basic(
            self._realm_client.base64_encoded_client_secret()
        )

        response = await self._wrapper.request_async(
            method=HttpMethod.POST,
            url=self._get_path(path=REALM_CLIENT_OPENID_URL_TOKEN),
            data=payload.to_dict(),
            headers=headers,
        )

        return response

    async def introspect_token_async(
        self,
        payload: RTPIntrospectionPayload | TokenIntrospectionPayload,
    ) -> ResponseProtocol:
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
                    basic_token=self._realm_client.base64_encoded_client_secret()
                )

            case _:
                raise TypeError(
                    f"Unsupported payload type: {type(payload).__name__}. "
                    "Expected RTPIntrospectionPayload or TokenIntrospectionPayload"
                )

        response = await self._wrapper.request_async(
            method=HttpMethod.POST,
            url=self._get_path(path=REALM_CLIENT_OPENID_URL_INTROSPECT),
            data=payload.to_dict(),
            headers=headers,
        )

        return response

    async def auth_device_async(self) -> ResponseProtocol:
        headers: dict[str, str] | None = None
        data = {
            "client_id": self._realm_client.client_id,
            "scope": "openid profile email",
        }

        if self._realm_client.is_confidential:
            headers = self._headers.openid_basic(
                basic_token=self._realm_client.base64_encoded_client_secret()
            )

        response = await self._wrapper.request_async(
            method=HttpMethod.POST,
            url=self._get_path(path=REALM_CLIENT_OPENID_URL_AUTH_DEVICE),
            headers=headers,
            data=data,
        )

        return response

    @inject_verified_access_token
    async def get_certs_async(
        self,
        **kwargs: Unpack[InternalAccessToken],
    ) -> ResponseProtocol:
        access_token: str = self.get_access_token(**kwargs)
        headers: dict[str, str] = self._headers.openid_bearer(bearer_token=access_token)

        response = await self._wrapper.request_async(
            method=HttpMethod.GET,
            url=self._get_path(path=REALM_CLIENT_OPENID_URL_CERTS),
            headers=headers,
        )

        return response

    async def logout_async(self, refresh_token: str) -> ResponseProtocol:
        payload = {
            "client_id": self._realm_client.client_id,
            "refresh_token": refresh_token,
        }

        if self._realm_client.client_secret:
            payload |= {
                "client_secret": self._realm_client.client_secret,
            }

        headers: dict[str, str] = self._headers.openid_bearer(
            bearer_token=self._realm_client.base64_encoded_client_secret()
        )

        response = await self._wrapper.request_async(
            method=HttpMethod.POST,
            url=self._get_path(path=REALM_CLIENT_OPENID_URL_LOGOUT),
            data=payload,
            headers=headers,
        )

        return response

    async def revoke_async(self, refresh_token: str) -> ResponseProtocol:
        payload: ConfidentialClientRevokePayload | PublicClientRevokePayload | None = (
            None
        )
        headers: dict[str, str] | None = None

        match self._realm_client.is_confidential:
            case True:
                payload = ConfidentialClientRevokePayload(token=refresh_token)

                headers = self._headers.openid_basic(
                    basic_token=self._realm_client.base64_encoded_client_secret()
                )

            case False:
                payload = PublicClientRevokePayload(
                    client_id=self._realm_client.client_id, token=refresh_token
                )

                headers = self._headers.openid_bearer(bearer_token=str(payload.token))

        response = await self._wrapper.request_async(
            method=HttpMethod.POST,
            url=self._get_path(path=REALM_CLIENT_OPENID_URL_REVOKE),
            data=payload.to_dict(),
            headers=headers,
        )

        return response

    async def get_user_info_async(
        self,
        **kwargs: Unpack[InternalAccessToken],
    ) -> ResponseProtocol:
        access_token: str = self.get_access_token(**kwargs)
        headers = self._headers.openid_bearer(bearer_token=str(access_token))

        response = await self._wrapper.request_async(
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
    ) -> ResponseProtocol:
        headers = self._headers.openid_basic(
            basic_token=self._realm_client.base64_encoded_client_secret()
        )

        data = payload.to_dict()

        if not data.get("audience"):
            data["audience"] = self._realm_client.client_id

        response = await self._wrapper.request_async(
            method=HttpMethod.POST,
            url=self._get_path(path=REALM_CLIENT_OPENID_URL_TOKEN),
            data=data,
            headers=headers,
        )

        return response

    ##############################################################
    #  Users
    ##############################################################

    @inject_verified_access_token
    async def get_users_count_async(
        self,
        query: GetUsersQuery | None = None,
        **kwargs: Unpack[InternalAccessToken],
    ) -> ResponseProtocol:
        access_token: str = self.get_access_token(**kwargs)
        headers = self._headers.keycloak_bearer(bearer_token=access_token)

        return await self._wrapper.request_async(
            method=HttpMethod.GET,
            url=self._get_path(path=REALM_USERS_COUNT),
            headers=headers,
            params=query.to_dict() if query else None,
        )

    @inject_verified_access_token
    async def get_users_async(
        self,
        query: GetUsersQuery | None = None,
        **kwargs: Unpack[InternalAccessToken],
    ) -> ResponseProtocol:
        access_token: str = self.get_access_token(**kwargs)
        headers = self._headers.keycloak_bearer(bearer_token=access_token)

        _query = query or GetUsersQuery()

        return await self._wrapper.request_async(
            method=HttpMethod.GET,
            url=self._get_path(path=REALM_USERS_LIST),
            headers=headers,
            params=_query,
        )

    @inject_verified_access_token
    async def get_user_async(
        self,
        user_id: UUID | str,
        **kwargs: Unpack[InternalAccessToken],
    ) -> ResponseProtocol:
        access_token: str = self.get_access_token(**kwargs)
        headers = self._headers.keycloak_bearer(bearer_token=access_token)

        response = await self._wrapper.request_async(
            method=HttpMethod.GET,
            url=self._get_path(path=REALM_USER, user_id=user_id),
            headers=headers,
        )

        return response

    @inject_verified_access_token
    async def delete_user_async(
        self,
        user_id: UUID | str,
        **kwargs: Unpack[InternalAccessToken],
    ) -> ResponseProtocol:
        access_token: str = self.get_access_token(**kwargs)
        headers = self._headers.keycloak_bearer(bearer_token=access_token)

        response = await self._wrapper.request_async(
            method=HttpMethod.DELETE,
            url=self._get_path(path=REALM_USER, user_id=user_id),
            headers=headers,
        )

        return response

    @inject_verified_access_token
    async def create_user_async(
        self,
        payload: CreateUserPayload,
        **kwargs: Unpack[InternalAccessToken],
    ) -> ResponseProtocol:
        access_token: str = self.get_access_token(**kwargs)
        headers = self._headers.keycloak_bearer(bearer_token=access_token)

        response = await self._wrapper.request_async(
            method=HttpMethod.POST,
            url=self._get_path(path=REALM_USERS_LIST),
            headers=headers,
            data=payload.to_json(),
        )

        return response

    @inject_verified_access_token
    async def update_user_by_id_async(
        self,
        user_id: UUID | str,
        payload: UpdateUserPayload,
        **kwargs: Unpack[InternalAccessToken],
    ) -> ResponseProtocol:
        access_token: str = self.get_access_token(**kwargs)
        headers = self._headers.keycloak_bearer(bearer_token=access_token)

        response = await self._wrapper.request_async(
            method=HttpMethod.PUT,
            url=self._get_path(path=REALM_USER, user_id=user_id),
            headers=headers,
            data=payload.to_json(),
        )

        return response

    @inject_verified_access_token
    async def update_user_enable_by_id_async(
        self,
        user_id: UUID | str,
        payload: UserUpdateEnablePayload,
        **kwargs: Unpack[InternalAccessToken],
    ) -> ResponseProtocol:
        access_token: str = self.get_access_token(**kwargs)
        headers = self._headers.keycloak_bearer(bearer_token=access_token)

        response = await self._wrapper.request_async(
            method=HttpMethod.PUT,
            url=self._get_path(path=REALM_USER, user_id=user_id),
            headers=headers,
            data=payload.to_json(),
        )

        return response

    @inject_verified_access_token
    async def update_user_password_by_id_async(
        self,
        user_id: UUID | str,
        payload: UserUpdatePasswordPayload,
        **kwargs: Unpack[InternalAccessToken],
    ) -> ResponseProtocol:
        access_token: str = self.get_access_token(**kwargs)
        headers = self._headers.keycloak_bearer(bearer_token=access_token)

        response = await self._wrapper.request_async(
            method=HttpMethod.PUT,
            url=self._get_path(path=REALM_USER, user_id=user_id),
            headers=headers,
            data=payload.to_json(),
        )

        return response

    @inject_verified_access_token
    async def get_users_by_role_async(
        self,
        role_name: str,
        request_query: RoleMembersListQuery | None = None,
        **kwargs: Unpack[InternalAccessToken],
    ) -> ResponseProtocol:
        access_token: str = self.get_access_token(**kwargs)
        headers = self._headers.keycloak_bearer(bearer_token=access_token)

        response = await self._wrapper.request_async(
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

    @inject_verified_access_token
    async def get_client_sessions_async(
        self,
        query: PaginationQuery | None = None,
        **kwargs: Unpack[InternalAccessToken],
    ) -> ResponseProtocol:
        access_token: str = self.get_access_token(**kwargs)
        headers = self._headers.keycloak_bearer(bearer_token=access_token)

        response = await self._wrapper.request_async(
            method=HttpMethod.GET,
            url=self._get_path(
                path=REALM_CLIENT_USER_SESSIONS, id=self._realm_client.client_uuid
            ),
            headers=headers,
            params=query.to_dict() if query else None,
        )

        return response

    @inject_verified_access_token
    async def get_user_sessions_async(
        self,
        user_id: UUID | str,
        **kwargs: Unpack[InternalAccessToken],
    ) -> ResponseProtocol:
        access_token: str = self.get_access_token(**kwargs)
        headers = self._headers.keycloak_bearer(bearer_token=access_token)

        response = await self._wrapper.request_async(
            method=HttpMethod.GET,
            url=self._get_path(path=REALM_USER_SESSIONS, user_id=user_id),
            headers=headers,
        )

        return response

    @inject_verified_access_token
    async def delete_session_by_id_async(
        self,
        session_id: UUID | str,
        is_offline: bool,
        **kwargs: Unpack[InternalAccessToken],
    ) -> ResponseProtocol:
        access_token: str = self.get_access_token(**kwargs)
        headers = self._headers.keycloak_bearer(bearer_token=access_token)

        offline_status = "true" if is_offline else "false"

        response = await self._wrapper.request_async(
            method=HttpMethod.DELETE,
            url=self._get_path(path=REALM_DELETE_SESSION, session_id=session_id),
            headers=headers,
            params={"isOffline": offline_status},
        )

        return response

    @inject_verified_access_token
    async def get_client_user_sessions_async(
        self,
        request_query: PaginationQuery | None = None,
        **kwargs: Unpack[InternalAccessToken],
    ) -> ResponseProtocol:
        access_token: str = self.get_access_token(**kwargs)
        headers = self._headers.keycloak_bearer(bearer_token=access_token)

        response = await self._wrapper.request_async(
            method=HttpMethod.GET,
            url=self._get_path(path=REALM_CLIENT_USER_SESSIONS),
            headers=headers,
            params=request_query,
        )

        return response

    @inject_verified_access_token
    async def get_client_sessions_count_async(
        self,
        **kwargs: Unpack[InternalAccessToken],
    ) -> ResponseProtocol:
        access_token: str = self.get_access_token(**kwargs)
        headers = self._headers.keycloak_bearer(bearer_token=access_token)

        response = await self._wrapper.request_async(
            method=HttpMethod.GET,
            url=self._get_path(path=REALM_CLIENT_ACTIVE_SESSION_COUNT),
            headers=headers,
        )

        return response

    @inject_verified_access_token
    async def get_offline_sessions_async(
        self,
        query: PaginationQuery | None = None,
        **kwargs: Unpack[InternalAccessToken],
    ) -> ResponseProtocol:
        access_token: str = self.get_access_token(**kwargs)
        headers = self._headers.keycloak_bearer(bearer_token=access_token)

        response = await self._wrapper.request_async(
            method=HttpMethod.GET,
            url=self._get_path(path=REALM_CLIENT_OFFLINE_SESSIONS),
            headers=headers,
            params=query.to_dict() if query else None,
        )

        return response

    @inject_verified_access_token
    async def get_offline_sessions_count_async(
        self,
        **kwargs: Unpack[InternalAccessToken],
    ) -> ResponseProtocol:
        access_token: str = self.get_access_token(**kwargs)
        headers = self._headers.keycloak_bearer(bearer_token=access_token)

        response = await self._wrapper.request_async(
            method=HttpMethod.GET,
            url=self._get_path(path=REALM_CLIENT_OFFLINE_SESSION_COUNT),
            headers=headers,
        )

        return response

    @inject_verified_access_token
    async def remove_user_sessions_async(
        self,
        user_id: UUID | str,
        **kwargs: Unpack[InternalAccessToken],
    ) -> ResponseProtocol:
        access_token: str = self.get_access_token(**kwargs)
        headers = self._headers.keycloak_bearer(bearer_token=access_token)

        response = await self._wrapper.request_async(
            method=HttpMethod.POST,
            url=self._get_path(path=REALM_USER_LOGOUT, user_id=user_id),
            headers=headers,
        )

        return response

    @inject_verified_access_token
    async def logout_all_users_async(
        self,
        **kwargs: Unpack[InternalAccessToken],
    ) -> ResponseProtocol:
        access_token: str = self.get_access_token(**kwargs)
        headers = self._headers.keycloak_bearer(bearer_token=access_token)

        response = await self._wrapper.request_async(
            method=HttpMethod.POST,
            url=self._get_path(path=REALM_LOGOUT_ALL),
            headers=headers,
        )

        return response

    @inject_verified_access_token
    async def get_client_session_stats_async(
        self,
        **kwargs: Unpack[InternalAccessToken],
    ) -> ResponseProtocol:
        access_token: str = self.get_access_token(**kwargs)
        headers = self._headers.keycloak_bearer(bearer_token=access_token)

        response = await self._wrapper.request_async(
            method=HttpMethod.GET,
            url=self._get_path(path=REALM_CLIENT_SESSION_STATS),
            headers=headers,
        )

        return response

    @inject_verified_access_token
    async def get_client_user_offline_sessions_async(
        self,
        user_id: UUID | str,
        **kwargs: Unpack[InternalAccessToken],
    ) -> ResponseProtocol:
        access_token: str = self.get_access_token(**kwargs)
        headers = self._headers.keycloak_bearer(bearer_token=access_token)

        response = await self._wrapper.request_async(
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

    @inject_verified_access_token
    async def get_client_roles_async(
        self,
        **kwargs: Unpack[InternalAccessToken],
    ) -> ResponseProtocol:
        access_token: str = self.get_access_token(**kwargs)
        headers = self._headers.keycloak_bearer(bearer_token=access_token)

        response = await self._wrapper.request_async(
            method=HttpMethod.GET,
            url=self._get_path(
                path=REALM_CLIENT_ROLES, client_id=self._realm_client.client_uuid
            ),
            headers=headers,
        )

        return response

    @inject_verified_access_token
    async def get_client_role_id_async(
        self,
        role_name: str,
        **kwargs: Unpack[InternalAccessToken],
    ) -> ResponseProtocol:
        access_token: str = self.get_access_token(**kwargs)
        headers = self._headers.keycloak_bearer(bearer_token=access_token)

        response = await self._wrapper.request_async(
            method=HttpMethod.GET,
            url=self._get_path(path=REALM_CLIENT_ROLE, role_name=role_name),
            headers=headers,
        )

        return response

    @inject_verified_access_token
    async def get_role_by_name_async(
        self,
        role_name: str,
        **kwargs: Unpack[InternalAccessToken],
    ) -> ResponseProtocol:
        access_token: str = self.get_access_token(**kwargs)
        headers = self._headers.keycloak_bearer(bearer_token=access_token)

        response = await self._wrapper.request_async(
            method=HttpMethod.GET,
            url=self._get_path(path=REALM_CLIENT_ROLE, role_name=role_name),
            headers=headers,
        )

        return response

    @inject_verified_access_token
    async def create_role_async(
        self,
        payload: RolePayload,
        **kwargs: Unpack[InternalAccessToken],
    ) -> ResponseProtocol:
        access_token: str = self.get_access_token(**kwargs)
        headers = self._headers.keycloak_bearer(bearer_token=access_token)

        response = await self._wrapper.request_async(
            method=HttpMethod.POST,
            url=self._get_path(path=REALM_CLIENT_ROLES),
            headers=headers,
            data=payload.to_json(),
        )

        return response

    @inject_verified_access_token
    async def update_role_by_id_async(
        self,
        role_id: UUID | str,
        payload: RolePayload,
        skip_unexpected_behaviour_exception: bool = False,
        **kwargs: Unpack[InternalAccessToken],
    ) -> ResponseProtocol:
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
        access_token: str = self.get_access_token(**kwargs)
        if not skip_unexpected_behaviour_exception:
            raise KeycloakUnexpectedBehaviourException(
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

        response = await self._wrapper.request_async(
            method=HttpMethod.PUT,
            url=self._get_path(path=REALM_ROLES_ROLE_BY_ID, role_id=str(role_id)),
            headers=headers,
            data=payload.to_json(),
        )

        return response

    @inject_verified_access_token
    async def update_role_by_name_async(
        self,
        role_name: str,
        payload: RolePayload,
        **kwargs: Unpack[InternalAccessToken],
    ) -> ResponseProtocol:
        access_token: str = self.get_access_token(**kwargs)
        headers = self._headers.keycloak_bearer(bearer_token=access_token)

        response = await self._wrapper.request_async(
            method=HttpMethod.PUT,
            url=self._get_path(
                path=REALM_CLIENT_ROLE,
                role_name=role_name,
            ),
            headers=headers,
            data=payload.to_json(),
        )

        return response

    @inject_verified_access_token
    async def delete_role_by_id_async(
        self,
        role_id: UUID | str,
        **kwargs: Unpack[InternalAccessToken],
    ) -> ResponseProtocol:
        access_token: str = self.get_access_token(**kwargs)
        headers = self._headers.keycloak_bearer(bearer_token=access_token)

        response = await self._wrapper.request_async(
            method=HttpMethod.DELETE,
            url=self._get_path(path=REALM_ROLES_ROLE_BY_ID, role_id=role_id),
            headers=headers,
        )

        return response

    @inject_verified_access_token
    async def delete_role_by_name_async(
        self,
        role_name: str,
        **kwargs: Unpack[InternalAccessToken],
    ) -> ResponseProtocol:
        access_token: str = self.get_access_token(**kwargs)
        headers = self._headers.keycloak_bearer(bearer_token=access_token)

        response = await self._wrapper.request_async(
            method=HttpMethod.DELETE,
            url=self._get_path(
                path=REALM_ROLES_DELETE_ROLE_BY_NAME, role_name=role_name
            ),
            headers=headers,
        )

        return response

    @inject_verified_access_token
    async def assign_client_role_async(
        self,
        user_id: UUID | str,
        roles: list[str],
        **kwargs: Unpack[InternalAccessToken],
    ) -> ResponseProtocol:
        access_token: str = self.get_access_token(**kwargs)
        headers = self._headers.keycloak_bearer(bearer_token=access_token)

        response = await self._wrapper.request_async(
            method=HttpMethod.POST,
            url=self._get_path(
                path=REALM_CLIENT_USER_ROLE_MAPPING, user_id=str(user_id)
            ),
            headers=headers,
            data=json.dumps(roles),
        )

        return response

    @inject_verified_access_token
    async def get_client_roles_of_user_async(
        self,
        user_id: UUID | str,
        **kwargs: Unpack[InternalAccessToken],
    ) -> ResponseProtocol:
        access_token: str = self.get_access_token(**kwargs)
        headers = self._headers.keycloak_bearer(bearer_token=access_token)

        response = await self._wrapper.request_async(
            method=HttpMethod.GET,
            url=self._get_path(path=REALM_CLIENT_USER_ROLE_MAPPING, user_id=user_id),
            headers=headers,
        )

        return response

    @inject_verified_access_token
    async def get_composite_client_roles_of_user_async(
        self,
        user_id: UUID | str,
        request_query: BriefRepresentationQuery | None = None,
        **kwargs: Unpack[InternalAccessToken],
    ) -> ResponseProtocol:
        access_token: str = self.get_access_token(**kwargs)
        headers = self._headers.keycloak_bearer(bearer_token=access_token)

        response = await self._wrapper.request_async(
            method=HttpMethod.GET,
            url=self._get_path(
                path=REALM_CLIENT_USER_ROLE_MAPPING_COMPOSITE, user_id=user_id
            ),
            headers=headers,
            params=request_query,
        )

        return response

    @inject_verified_access_token
    async def get_available_client_roles_of_user_async(
        self,
        user_id: UUID | str,
        **kwargs: Unpack[InternalAccessToken],
    ) -> ResponseProtocol:
        access_token: str = self.get_access_token(**kwargs)
        headers = self._headers.keycloak_bearer(bearer_token=access_token)

        response = await self._wrapper.request_async(
            method=HttpMethod.GET,
            url=self._get_path(
                path=REALM_CLIENT_USER_ROLE_MAPPING_AVAILABLE, user_id=user_id
            ),
            headers=headers,
        )

        return response

    @inject_verified_access_token
    async def delete_client_roles_of_user_async(
        self,
        user_id: UUID | str,
        roles: list[str],
        **kwargs: Unpack[InternalAccessToken],
    ) -> ResponseProtocol:
        access_token: str = self.get_access_token(**kwargs)
        headers = self._headers.keycloak_bearer(bearer_token=access_token)

        response = await self._wrapper.request_async(
            method=HttpMethod.DELETE,
            url=self._get_path(path=REALM_CLIENT_USER_ROLE_MAPPING, user_id=user_id),
            headers=headers,
            data=json.dumps(roles),
        )

        return response

    @inject_verified_access_token
    async def get_user_roles_async(
        self,
        user_id: UUID | str,
        **kwargs: Unpack[InternalAccessToken],
    ) -> ResponseProtocol:
        access_token: str = self.get_access_token(**kwargs)
        headers = self._headers.keycloak_bearer(bearer_token=access_token)

        response = await self._wrapper.request_async(
            method=HttpMethod.GET,
            url=self._get_path(path=REALM_CLIENT_USER_ROLE_MAPPING, user_id=user_id),
            headers=headers,
        )

        return response

    ##############################################################
    #  Authz Scopes
    ##############################################################

    @inject_verified_access_token
    async def get_client_authz_scopes_async(
        self,
        **kwargs: Unpack[InternalAccessToken],
    ) -> ResponseProtocol:
        access_token: str = self.get_access_token(**kwargs)
        headers = self._headers.keycloak_bearer(bearer_token=access_token)

        response = await self._wrapper.request_async(
            method=HttpMethod.GET,
            url=self._get_path(path=REALM_CLIENT_AUTHZ_SCOPES),
            headers=headers,
        )

        return response

    ##############################################################
    #  Authz Resources
    ##############################################################

    @inject_verified_access_token
    async def get_resources_async(
        self,
        query: ResourcesListQuery | None = None,
        **kwargs: Unpack[InternalAccessToken],
    ) -> ResponseProtocol:
        access_token: str = self.get_access_token(**kwargs)
        headers = self._headers.keycloak_bearer(bearer_token=access_token)

        response = await self._wrapper.request_async(
            method=HttpMethod.GET,
            url=self._get_path(path=REALM_CLIENT_AUTHZ_RESOURCES),
            headers=headers,
            params=query.to_dict() if query else None,
        )

        return response

    @inject_verified_access_token
    async def create_resource_async(
        self,
        payload: ResourcePayload,
        **kwargs: Unpack[InternalAccessToken],
    ) -> ResponseProtocol:
        access_token: str = self.get_access_token(**kwargs)
        headers = self._headers.keycloak_bearer(bearer_token=access_token)

        response = await self._wrapper.request_async(
            method=HttpMethod.POST,
            url=self._get_path(path=REALM_CLIENT_AUTHZ_RESOURCES),
            headers=headers,
            data=payload.to_json(),
        )

        return response

    @inject_verified_access_token
    async def get_resource_by_id_async(
        self,
        resource_id: str,
        **kwargs: Unpack[InternalAccessToken],
    ) -> ResponseProtocol:
        access_token: str = self.get_access_token(**kwargs)
        headers = self._headers.keycloak_bearer(bearer_token=access_token)

        response = await self._wrapper.request_async(
            method=HttpMethod.GET,
            url=self._get_path(
                path=REALM_CLIENT_AUTHZ_RESOURCE, resource_id=resource_id
            ),
            headers=headers,
        )

        return response

    @inject_verified_access_token
    async def delete_resource_by_id_async(
        self,
        resource_id: str,
        **kwargs: Unpack[InternalAccessToken],
    ) -> ResponseProtocol:
        access_token: str = self.get_access_token(**kwargs)
        headers = self._headers.keycloak_bearer(bearer_token=access_token)

        response = await self._wrapper.request_async(
            method=HttpMethod.DELETE,
            url=self._get_path(
                path=REALM_CLIENT_AUTHZ_RESOURCE, resource_id=resource_id
            ),
            headers=headers,
        )

        return response

    @inject_verified_access_token
    async def get_resource_permissions_async(
        self,
        resource_id: str,
        **kwargs: Unpack[InternalAccessToken],
    ) -> ResponseProtocol:
        access_token: str = self.get_access_token(**kwargs)
        headers = self._headers.keycloak_bearer(bearer_token=access_token)

        response = await self._wrapper.request_async(
            method=HttpMethod.GET,
            url=self._get_path(
                path=REALM_CLIENT_AUTHZ_RESOURCE_PERMISSIONS, resource_id=resource_id
            ),
            headers=headers,
        )

        return response

    ##############################################################
    #  Authz Policies
    ##############################################################

    @inject_verified_access_token
    async def create_policy_role_async(
        self,
        payload: RolePolicyPayload,
        **kwargs: Unpack[InternalAccessToken],
    ) -> ResponseProtocol:
        access_token: str = self.get_access_token(**kwargs)
        headers = self._headers.keycloak_bearer(bearer_token=access_token)

        response = await self._wrapper.request_async(
            method=HttpMethod.GET,
            url=self._get_path(path=REALM_CLIENT_AUTHZ_RESOURCE_POLICY_ROLE),
            headers=headers,
            data=payload.to_json(),
        )

        return response

    @inject_verified_access_token
    async def delete_policy_async(
        self,
        policy_id: str,
        **kwargs: Unpack[InternalAccessToken],
    ) -> ResponseProtocol:
        access_token: str = self.get_access_token(**kwargs)
        headers = self._headers.keycloak_bearer(bearer_token=access_token)

        response = await self._wrapper.request_async(
            method=HttpMethod.DELETE,
            url=self._get_path(path=REALM_CLIENT_AUTHZ_POLICY, policy_id=policy_id),
            headers=headers,
        )

        return response

    @inject_verified_access_token
    async def create_policy_async(
        self,
        payload: PermissionPayload,
        **kwargs: Unpack[InternalAccessToken],
    ) -> ResponseProtocol:
        access_token: str = self.get_access_token(**kwargs)
        headers = self._headers.keycloak_bearer(bearer_token=access_token)

        response = await self._wrapper.request_async(
            method=HttpMethod.POST,
            url=self._get_path(path=REALM_CLIENT_AUTHZ_RESOURCE_POLICY_USER),
            headers=headers,
            data=payload.to_json(),
        )

        return response

    @inject_verified_access_token
    async def get_policy_by_name_async(
        self,
        query: FilterFindPolicyParams | None = None,
        **kwargs: Unpack[InternalAccessToken],
    ) -> ResponseProtocol:
        access_token: str = self.get_access_token(**kwargs)
        headers = self._headers.keycloak_bearer(bearer_token=access_token)

        response = await self._wrapper.request_async(
            method=HttpMethod.GET,
            url=self._get_path(path=REALM_CLIENT_AUTHZ_RESOURCE_POLICY_SEARCH),
            headers=headers,
            params=query.to_dict() if query else None,
        )

        return response

    @inject_verified_access_token
    async def get_associated_policies_async(
        self,
        policy_id: str,
        **kwargs: Unpack[InternalAccessToken],
    ) -> ResponseProtocol:
        access_token: str = self.get_access_token(**kwargs)
        headers = self._headers.keycloak_bearer(bearer_token=access_token)

        response = await self._wrapper.request_async(
            method=HttpMethod.GET,
            url=self._get_path(
                path=REALM_CLIENT_AUTHZ_CLIENT_POLICY_ASSOCIATED_ROLE_POLICIES,
                policy_id=policy_id,
            ),
            headers=headers,
        )

        return response

    @inject_verified_access_token
    async def get_policy_authorisation_scopes_async(
        self,
        permission_id: str,
        **kwargs: Unpack[InternalAccessToken],
    ) -> ResponseProtocol:
        access_token: str = self.get_access_token(**kwargs)
        headers = self._headers.keycloak_bearer(bearer_token=access_token)

        response = await self._wrapper.request_async(
            method=HttpMethod.GET,
            url=self._get_path(
                path=REALM_CLIENT_AUTHZ_POLICY_SCOPES, permission_id=permission_id
            ),
            headers=headers,
        )

        return response

    @inject_verified_access_token
    async def get_policies_async(
        self,
        **kwargs: Unpack[InternalAccessToken],
    ) -> ResponseProtocol:
        access_token: str = self.get_access_token(**kwargs)
        headers = self._headers.keycloak_bearer(bearer_token=access_token)

        response = await self._wrapper.request_async(
            method=HttpMethod.GET,
            url=self._get_path(path=REALM_CLIENT_AUTHZ_POLICIES),
            headers=headers,
        )

        return response

    @inject_verified_access_token
    async def get_policy_associated_role_policies_async(
        self,
        policy_id: str,
        **kwargs: Unpack[InternalAccessToken],
    ) -> ResponseProtocol:
        access_token: str = self.get_access_token(**kwargs)
        headers = self._headers.keycloak_bearer(bearer_token=access_token)

        response = await self._wrapper.request_async(
            method=HttpMethod.GET,
            url=self._get_path(
                path=REALM_CLIENT_AUTHZ_CLIENT_POLICY_ASSOCIATED_ROLE_POLICIES,
                policy_id=policy_id,
            ),
            headers=headers,
        )

        return response

    ##############################################################
    #  Authz Permissions
    ##############################################################

    @inject_verified_access_token
    async def create_client_authz_permission_resource_based_async(
        self,
        payload: PermissionPayload,
        **kwargs: Unpack[InternalAccessToken],
    ) -> ResponseProtocol:
        access_token: str = self.get_access_token(**kwargs)
        headers = self._headers.keycloak_bearer(bearer_token=access_token)

        response = await self._wrapper.request_async(
            method=HttpMethod.POST,
            url=self._get_path(path=REALM_CLIENT_AUTHZ_RESOURCE_BASED_PERMISSION),
            headers=headers,
            data=payload.to_dict(),
        )

        return response

    @inject_verified_access_token
    async def create_client_authz_permission_scope_based_async(
        self,
        payload: PermissionPayload,
        **kwargs: Unpack[InternalAccessToken],
    ) -> ResponseProtocol:
        access_token: str = self.get_access_token(**kwargs)
        headers = self._headers.keycloak_bearer(bearer_token=access_token)

        response = await self._wrapper.request_async(
            method=HttpMethod.POST,
            url=self._get_path(path=REALM_CLIENT_AUTHZ_SCOPE_BASED_PERMISSION),
            headers=headers,
            data=payload.to_dict(),
        )

        return response

    @inject_verified_access_token
    async def get_permissions_async(
        self,
        query: FindPermissionQuery | None = None,
        **kwargs: Unpack[InternalAccessToken],
    ) -> ResponseProtocol:
        access_token: str = self.get_access_token(**kwargs)
        headers = self._headers.keycloak_bearer(bearer_token=access_token)

        response = await self._wrapper.request_async(
            method=HttpMethod.GET,
            url=self._get_path(path=REALM_CLIENT_AUTHZ_PERMISSIONS),
            headers=headers,
            params=query.to_dict() if query else None,
        )

        return response

    @inject_verified_access_token
    async def get_permissions_for_scope_by_id_async(
        self,
        permission_id: str,
        **kwargs: Unpack[InternalAccessToken],
    ) -> ResponseProtocol:
        access_token: str = self.get_access_token(**kwargs)
        headers = self._headers.keycloak_bearer(bearer_token=access_token)

        response = await self._wrapper.request_async(
            method=HttpMethod.GET,
            url=self._get_path(
                path=REALM_CLIENT_AUTHZ_PERMISSION_SCOPE, permission_id=permission_id
            ),
            headers=headers,
        )

        return response

    @inject_verified_access_token
    async def delete_permission_async(
        self,
        permission_id: str,
        **kwargs: Unpack[InternalAccessToken],
    ) -> ResponseProtocol:
        access_token: str = self.get_access_token(**kwargs)
        headers = self._headers.keycloak_bearer(bearer_token=access_token)

        response = await self._wrapper.request_async(
            method=HttpMethod.DELETE,
            url=self._get_path(
                path=REALM_CLIENT_AUTHZ_RESOURCE_PERMISSION, permission_id=permission_id
            ),
            headers=headers,
        )

        return response

    @staticmethod
    def get_access_token(**kwargs: Unpack[InternalAccessToken]) -> str:
        access_token = kwargs.pop("access_token")

        if not access_token:
            raise AccessTokenIsRequiredError(
                "Access token should be injected using TokenManager or manually"
            )

        return access_token

    @inject_verified_access_token
    async def update_permission_scopes_async(
        self,
        permission_id: str,  # resource OR scope based permission
        payload: PermissionScopesPayload,
        **kwargs: Unpack[InternalAccessToken],
    ) -> ResponseProtocol:
        access_token = self.get_access_token(**kwargs)
        headers = self._headers.keycloak_bearer(bearer_token=access_token)

        response = await self._wrapper.request_async(
            method=HttpMethod.PUT,
            url=self._get_path(
                path=REALM_CLIENT_AUTHZ_PERMISSION_SCOPE, permission_id=permission_id
            ),
            headers=headers,
            data=payload.to_dict(),
        )

        return response

    ##############################################################
    #  ...
    ##############################################################

    async def close(self) -> None:
        await self._wrapper.client.aclose()

    def _get_path(self, path: str, **kwargs: Any) -> str:
        params = {
            "realm": str(self._realm.name),
            "client_id": str(self._realm_client.client_id),
            "client_uuid": str(self._realm_client.client_uuid),
            **{k: str(v) for k, v in kwargs.items()},
        }
        return path.format(**params)

    ##############################################################
    #  Token manager
    ##############################################################

    def token_manager_update_access_token(
        self,
    ) -> Callable[[str], Awaitable[ResponseProtocol]]:
        async def _refresh(refresh_token: str) -> ResponseProtocol:
            return await self.refresh_token_async(
                payload=RefreshTokenPayload(refresh_token=refresh_token)
            )

        return _refresh


@TokenAutoRefresher(token_manager=TokenManager())
class KeycloakInMemoryProviderAsync(KeycloakProviderAsync): ...


if TYPE_CHECKING:
    _ch_kpa: KeycloakProviderProtocol = type[KeycloakProviderAsync]
    _ch_kimpa: KeycloakProviderProtocol = type[KeycloakInMemoryProviderAsync]
