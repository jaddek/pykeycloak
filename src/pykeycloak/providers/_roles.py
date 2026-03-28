# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Anton "Tony" Nazarov <tonynazarov+dev@gmail.com>

from collections.abc import Awaitable, Callable
from uuid import UUID

from pykeycloak.core.clients import HttpMethod
from pykeycloak.core.exceptions import KeycloakUnexpectedBehaviourException
from pykeycloak.core.protocols import KeycloakResponseProtocol
from pykeycloak.core.urls import (
    REALM_CLIENT_ROLE,
    REALM_CLIENT_ROLES,
    REALM_CLIENT_USER_ROLE_MAPPING,
    REALM_CLIENT_USER_ROLE_MAPPING_AVAILABLE,
    REALM_CLIENT_USER_ROLE_MAPPING_COMPOSITE,
    REALM_ROLES_DELETE_ROLE_BY_NAME,
    REALM_ROLES_ROLE_BY_ID,
)

from ._base import KeycloakProviderBase
from .payloads import RoleAssignPayload, RolePayload
from .queries import BriefRepresentationQuery


class RolesProvider:
    def __init__(
        self,
        base: KeycloakProviderBase,
        get_access_token: Callable[[], Awaitable[str]],
    ) -> None:
        self._base = base
        self._get_access_token = get_access_token

    async def get_client_roles_async(self) -> KeycloakResponseProtocol:
        access_token = await self._get_access_token()
        return await self._base.request_async(
            method=HttpMethod.GET,
            url=self._base.build_url(
                path=REALM_CLIENT_ROLES, client_id=self._base.realm_client.client_uuid
            ),
            headers=self._base.bearer_headers(access_token),
        )

    async def get_role_by_name_async(
        self,
        role_name: str,
    ) -> KeycloakResponseProtocol:
        access_token = await self._get_access_token()
        return await self._base.request_async(
            method=HttpMethod.GET,
            url=self._base.build_url(path=REALM_CLIENT_ROLE, role_name=role_name),
            headers=self._base.bearer_headers(access_token),
        )

    async def create_role_async(
        self,
        payload: RolePayload,
    ) -> KeycloakResponseProtocol:
        access_token = await self._get_access_token()
        return await self._base.request_async(
            method=HttpMethod.POST,
            url=self._base.build_url(path=REALM_CLIENT_ROLES),
            headers=self._base.bearer_headers(access_token),
            data=payload.to_json(),
        )

    async def update_role_by_id_async(
        self,
        role_id: UUID | str,
        payload: RolePayload,
        skip_unexpected_behaviour_exception: bool = False,
    ) -> KeycloakResponseProtocol:
        """
        !!!WARNING!!!
        v26.3.3 will create a new role if you send description and name.
        !!!WARNING!!!
        """
        access_token = await self._get_access_token()
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

        return await self._base.request_async(
            method=HttpMethod.PUT,
            url=self._base.build_url(path=REALM_ROLES_ROLE_BY_ID, role_id=str(role_id)),
            headers=self._base.bearer_headers(access_token),
            data=payload.to_json(),
        )

    async def update_role_by_name_async(
        self,
        role_name: str,
        payload: RolePayload,
    ) -> KeycloakResponseProtocol:
        access_token = await self._get_access_token()
        return await self._base.request_async(
            method=HttpMethod.PUT,
            url=self._base.build_url(path=REALM_CLIENT_ROLE, role_name=role_name),
            headers=self._base.bearer_headers(access_token),
            data=payload.to_json(),
        )

    async def delete_role_by_id_async(
        self,
        role_id: UUID | str,
    ) -> KeycloakResponseProtocol:
        access_token = await self._get_access_token()
        return await self._base.request_async(
            method=HttpMethod.DELETE,
            url=self._base.build_url(path=REALM_ROLES_ROLE_BY_ID, role_id=role_id),
            headers=self._base.bearer_headers(access_token),
        )

    async def delete_role_by_name_async(
        self,
        role_name: str,
    ) -> KeycloakResponseProtocol:
        access_token = await self._get_access_token()
        return await self._base.request_async(
            method=HttpMethod.DELETE,
            url=self._base.build_url(
                path=REALM_ROLES_DELETE_ROLE_BY_NAME, role_name=role_name
            ),
            headers=self._base.bearer_headers(access_token),
        )

    async def assign_role_async(
        self,
        user_id: UUID | str,
        roles: list[RoleAssignPayload],
    ) -> KeycloakResponseProtocol:
        access_token = await self._get_access_token()
        return await self._base.request_async(
            method=HttpMethod.POST,
            url=self._base.build_url(
                path=REALM_CLIENT_USER_ROLE_MAPPING, user_id=str(user_id)
            ),
            headers=self._base.bearer_headers(access_token),
            json=[role.to_dict() for role in roles],
        )

    async def unassign_role_async(
        self,
        user_id: UUID | str,
        roles: list[RoleAssignPayload],
    ) -> KeycloakResponseProtocol:
        access_token = await self._get_access_token()
        return await self._base.request_async(
            method=HttpMethod.DELETE,
            url=self._base.build_url(
                path=REALM_CLIENT_USER_ROLE_MAPPING, user_id=user_id
            ),
            headers=self._base.bearer_headers(access_token),
            json=[role.to_dict() for role in roles],
        )

    async def get_client_roles_of_user_async(
        self,
        user_id: UUID | str,
    ) -> KeycloakResponseProtocol:
        access_token = await self._get_access_token()
        return await self._base.request_async(
            method=HttpMethod.GET,
            url=self._base.build_url(
                path=REALM_CLIENT_USER_ROLE_MAPPING, user_id=user_id
            ),
            headers=self._base.bearer_headers(access_token),
        )

    async def get_composite_client_roles_of_user_async(
        self,
        user_id: UUID | str,
        request_query: BriefRepresentationQuery | None = None,
    ) -> KeycloakResponseProtocol:
        access_token = await self._get_access_token()
        return await self._base.request_async(
            method=HttpMethod.GET,
            url=self._base.build_url(
                path=REALM_CLIENT_USER_ROLE_MAPPING_COMPOSITE, user_id=user_id
            ),
            headers=self._base.bearer_headers(access_token),
            params=request_query,
        )

    async def get_available_client_roles_of_user_async(
        self,
        user_id: UUID | str,
    ) -> KeycloakResponseProtocol:
        access_token = await self._get_access_token()
        return await self._base.request_async(
            method=HttpMethod.GET,
            url=self._base.build_url(
                path=REALM_CLIENT_USER_ROLE_MAPPING_AVAILABLE, user_id=user_id
            ),
            headers=self._base.bearer_headers(access_token),
        )

    async def get_user_roles_async(
        self,
        user_id: UUID | str,
    ) -> KeycloakResponseProtocol:
        access_token = await self._get_access_token()
        return await self._base.request_async(
            method=HttpMethod.GET,
            url=self._base.build_url(
                path=REALM_CLIENT_USER_ROLE_MAPPING, user_id=user_id
            ),
            headers=self._base.bearer_headers(access_token),
        )
