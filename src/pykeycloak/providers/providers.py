import logging
import json
from typing import Any
from uuid import UUID

from httpx import Response

from pykeycloak.core.clients import (
    KeycloakHttpClientWrapperAsync,
    get_keycloak_client_wrapper_from_env, HttpMethod,
)
from pykeycloak.core.headers import Headers, get_headers
from .payloads import (
    ObtainTokenPayload,
    RefreshTokenPayload,
    RTPIntrospectionPayload,
    TokenIntrospectionPayload,
    UMAAuthorizationPayload, CreateUserPayload, UserUpdateEnablePayload, UserUpdatePasswordPayload,
)
from .queries import GetUsersQuery, RoleMembersListQuery, PaginationQuery, BriefRepresentationQuery
from ..core.constants import DEFAULT_PAGE_SIZE
from ..core.entities import RealmClient
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
    REALM_CLIENT_USER_ROLE_MAPPING_COMPOSITE, REALM_CLIENT_SESSION_STATS
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

    ##############################################################
    #  Auth/OpenID endpoints
    ##############################################################

    async def auth_device_async(self) -> Response:
        payload = {
            "client_id": self._realm_client.client_id,
            "client_secret": self._realm_client.client_secret,
        }

        with self._headers.override_with_openid_headers():
            response = await self._wrapper.request(
                method=HttpMethod.POST,
                url=self._get_path(path=REALM_CLIENT_OPENID_URL_AUTH_DEVICE),
                data=payload,
                headers=self._headers,
            )

        return response

    async def get_certs_async(self) -> Response:
        with self._headers.override_with_openid_headers():
            response = await self._wrapper.request(
                method=HttpMethod.GET,
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

        with self._headers.override_with_openid_headers():
            response = await self._wrapper.request(
                method=HttpMethod.POST,
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

        with self._headers.override_with_openid_headers():
            response = await self._wrapper.request(
                method=HttpMethod.POST,
                url=self._get_path(path=REALM_CLIENT_OPENID_URL_TOKEN),
                data=_payload,
                headers=self._headers,
            )

        return response

    async def get_user_info_async(
            self,
            access_token: str,
    ) -> Response:
        with self._headers.override_with_openid_headers(
                access_token=access_token
        ):
            response = await self._wrapper.request(
                method=HttpMethod.GET,
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

        with self._headers.override_with_openid_headers():
            response = await self._wrapper.request(
                method=HttpMethod.POST,
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

        with self._headers.override_with_openid_headers(
                access_token=access_token
        ):
            response = await self._wrapper.request(
                method=HttpMethod.POST,
                url=self._get_path(path=REALM_CLIENT_OPENID_URL_INTROSPECT),
                data=_payload,
                headers=self._headers,
            )

        return response

    ##############################################################
    #  Uma endpoints
    ##############################################################

    async def get_uma_permission_async(
            self,
            payload: UMAAuthorizationPayload,
            access_token: str,
    ) -> Response:
        with self._headers.override_with_openid_headers(access_token):
            response = await self._wrapper.request(
                method=HttpMethod.POST,
                url=self._get_path(path=REALM_CLIENT_OPENID_URL_TOKEN),
                data=payload.to_dict(),
                headers=self._headers,
            )

        return response

    ##############################################################
    #  Users
    ##############################################################

    async def get_users_count_async(
            self,
            query: GetUsersQuery | None = None
    ) -> Response:
        return await self._wrapper.request(
            method=HttpMethod.GET,
            url=self._get_path(path=REALM_USERS_COUNT),
            headers=self._headers,
            query=query,
        )

    async def get_users_async(
            self,
            query: GetUsersQuery | None = None,
    ) -> Response:
        _query = query or GetUsersQuery(max=DEFAULT_PAGE_SIZE)

        return await self._wrapper.request(
            method=HttpMethod.GET,
            url=self._get_path(path=REALM_USERS_LIST),
            headers=self._headers,
            query=_query,
        )

    async def get_user_async(self, user_id: str):
        response = await self._wrapper.request(
            method=HttpMethod.GET,
            url=self._get_path(path=REALM_USER, user_id=user_id),
            headers=self._headers,
        )

        return response

    async def delete_user_async(self, user_id: str):
        response = await self._wrapper.request(
            method=HttpMethod.DELETE,
            url=self._get_path(path=REALM_USER, user_id=user_id),
            headers=self._headers,
        )

        return response

    async def create_user_async(self, payload: CreateUserPayload) -> Response:
        response = await self._wrapper.request(
            method=HttpMethod.POST,
            url=self._get_path(path=REALM_USER),
            headers=self._headers,
            data=payload
        )

        return response

    async def update_user_by_id_async(
            self,
            user_id: str,
            payload: CreateUserPayload
    ) -> Response:
        response = await self._wrapper.request(
            method=HttpMethod.PUT,
            url=self._get_path(path=REALM_USER, user_id=user_id),
            headers=self._headers,
            data=payload,
        )

        return response

    async def update_user_enable_by_id_async(
            self,
            user_id: str,
            payload: UserUpdateEnablePayload,
    ) -> Response:
        response = await self._wrapper.request(
            method=HttpMethod.PUT,
            url=self._get_path(path=REALM_USER, user_id=user_id),
            headers=self._headers,
            data=payload,
        )

        return response

    async def update_user_password_by_id_async(
            self,
            user_id: str,
            payload: UserUpdatePasswordPayload,
    ) -> Response:
        response = await self._wrapper.request(
            method=HttpMethod.PUT,
            url=self._get_path(
                path=REALM_USER,
                user_id=user_id
            ),
            headers=self._headers,
            data=payload,
        )

        return response

    async def get_users_by_role_async(
            self,
            role_name: str,
            request_query: RoleMembersListQuery | None = None
    ) -> Response:
        response = await self._wrapper.request(
            method=HttpMethod.GET,
            url=self._get_path(
                path=REALM_CLIENT_ROLE_MEMBERS,
                role_name=role_name,
            ),
            headers=self._headers,
            query=request_query if request_query else {},
        )

        return response

    ##############################################################
    #  Sessions
    ##############################################################

    async def get_user_sessions_async(
            self,
            user_id: str,
    ) -> Response:
        response = await self._wrapper.request(
            method=HttpMethod.GET,
            url=self._get_path(path=REALM_USER_SESSIONS, user_id=user_id),
            headers=self._headers,
        )

        return response

    async def delete_session_by_id_async(self, session_id: str, is_offline: bool) -> Response:
        offline_status = "true" if is_offline else "false"

        response = await self._wrapper.request(
            method=HttpMethod.DELETE,
            url=self._get_path(path=REALM_DELETE_SESSION, session_id=session_id),
            headers=self._headers,
            query={"isOffline": offline_status},
        )

        return response

    async def get_client_user_sessions_async(
            self,
            request_query: PaginationQuery | None = None,
    ) -> Response:
        response = await self._wrapper.request(
            method=HttpMethod.GET,
            url=self._get_path(path=REALM_CLIENT_USER_SESSIONS),
            headers=self._headers,
            query=request_query
        )

        return response

    async def get_client_sessions_count_async(self) -> Response:
        response = await self._wrapper.request(
            method=HttpMethod.GET,
            url=self._get_path(path=REALM_CLIENT_ACTIVE_SESSION_COUNT),
            headers=self._headers,
        )

        return response

    async def get_offline_sessions_async(
            self,
            request_query: PaginationQuery | None = None,
    ) -> Response:
        response = await self._wrapper.request(
            method=HttpMethod.GET,
            url=self._get_path(path=REALM_CLIENT_OFFLINE_SESSIONS),
            headers=self._headers,
            query=request_query
        )

        return response

    async def get_offline_sessions_count_async(
            self,
    ) -> Response:
        response = await self._wrapper.request(
            method=HttpMethod.GET,
            url=self._get_path(path=REALM_CLIENT_OFFLINE_SESSION_COUNT),
            headers=self._headers,
        )

        return response

    async def remove_user_sessions_async(self, user_id: str) -> Response:
        response = await self._wrapper.request(
            method=HttpMethod.POST,
            url=self._get_path(path=REALM_USER_LOGOUT, user_id=user_id),
            headers=self._headers,
        )

        return response

    async def logout_all_users_async(self):
        response = await self._wrapper.request(
            method=HttpMethod.POST,
            url=self._get_path(path=REALM_LOGOUT_ALL),
            headers=self._headers,
        )

        return response

    async def get_client_session_stats_async(
            self,
    ) -> Response:
        response = await self._wrapper.request(
            method=HttpMethod.GET,
            url=self._get_path(path=REALM_CLIENT_SESSION_STATS),
            headers=self._headers,
        )

        return response

    async def get_client_user_offline_sessions_async(
            self, user_id: str,
    ) -> Response:
        response = await self._wrapper.request(
            method=HttpMethod.GET,
            url=self._get_path(path=REALM_CLIENT_USER_OFFLINE_SESSIONS, user_id=user_id),
            headers=self._headers,
        )

        return response

    ##############################################################
    #  Roles
    ##############################################################

    async def get_client_roles_async(self) -> Response:
        response = await self._wrapper.request(
            method=HttpMethod.GET,
            url=self._get_path(path=REALM_CLIENT_ROLES),
            headers=self._headers,
        )

        return response

    async def get_client_role_id_async(self, role_name:str) -> Response:
        response = await self._wrapper.request(
            method=HttpMethod.GET,
            url=self._get_path(path=REALM_CLIENT_ROLE, role_name=role_name),
            headers=self._headers,
        )

        return response


    async def get_role_by_name_async(self, role_name: str) -> Response:
        response = await self._wrapper.request(
            method=HttpMethod.GET,
            url=self._get_path(path=REALM_CLIENT_ROLE, role_name=role_name),
            headers=self._headers,
        )

        return response

    async def create_role(self, payload: dict) -> Response:
        response = await self._wrapper.request(
            method=HttpMethod.POST,
            url=self._get_path(path=REALM_CLIENT_ROLES),
            headers=self._headers,
            data=payload,
        )

        return response

    async def update_role_by_id_async(self, role_id: UUID, payload:dict) -> Response:
        response = await self._wrapper.request(
            method=HttpMethod.PUT,
            url=self._get_path(path=REALM_ROLES_ROLE_BY_ID, role_id=role_id),
            headers=self._headers,
            data=payload,
        )

        return response


    async def update_role_by_name_async(self, role_name: str, payload:dict) -> Response:
        response = await self._wrapper.request(
            method=HttpMethod.PUT,
            url=self._get_path(path=REALM_ROLES_ROLE_BY_NAME, role_name=role_name),
            headers=self._headers,
            data=payload,
        )

        return response

    async def delete_role_by_id_async(self, role_id: UUID) -> Response:
        response = await self._wrapper.request(
            method=HttpMethod.DELETE,
            url=self._get_path(path=REALM_ROLES_ROLE_BY_ID, role_id=role_id),
            headers=self._headers,
        )

        return response

    async def delete_role_by_name_async(self, role_name: str) -> Response:
        response = await self._wrapper.request(
            method=HttpMethod.DELETE,
            url=self._get_path(path=REALM_ROLES_ROLE_BY_NAME, role_name=role_name),
            headers=self._headers,
        )

        return response

    async def assign_client_role_async(self, user_id:UUID, roles: list[str]):
        response = await self._wrapper.request(
            method=HttpMethod.POST,
            url=self._get_path(path=REALM_CLIENT_USER_ROLE_MAPPING, user_id=user_id),
            headers=self._headers,
            data=json.dumps(roles),
        )

        return response

    async def get_client_roles_of_user_async(
            self,
            user_id: str,
    ):
        response = await self._wrapper.request(
            method=HttpMethod.GET,
            url=self._get_path(path=REALM_CLIENT_USER_ROLE_MAPPING, user_id=user_id),
            headers=self._headers,
        )

        return response

    async def get_composite_client_roles_of_user_async(
            self,
            user_id: str,
            request_query: BriefRepresentationQuery | None = None,
    ):
        response = await self._wrapper.request(
            method=HttpMethod.GET,
            url=self._get_path(path=REALM_CLIENT_USER_ROLE_MAPPING_COMPOSITE, user_id=user_id),
            headers=self._headers,
            query=request_query
        )

        return response

    async def get_available_client_roles_of_user_async(
            self,
            user_id: str,
    ):
        response = await self._wrapper.request(
            method=HttpMethod.GET,
            url=self._get_path(path=REALM_CLIENT_USER_ROLE_MAPPING_AVAILABLE, user_id=user_id),
            headers=self._headers,
        )

        return response


    async def delete_client_roles_of_user_async(
        self,
        user_id: str,
        roles: list[str],
    ):
        response = await self._wrapper.request(
            method=HttpMethod.DELETE,
            url=self._get_path(path=REALM_CLIENT_USER_ROLE_MAPPING, user_id=user_id),
            headers=self._headers,
            data=json.dumps(roles),
        )

        return response

    async def get_user_roles_async(self, user_id: str):
        response = await self._wrapper.request(
            method=HttpMethod.GET,
            url=self._get_path(path=REALM_CLIENT_USER_ROLE_MAPPING, user_id=user_id),
            headers=self._headers,
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
