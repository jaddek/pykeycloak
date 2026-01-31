# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Anton "Tony" Nazarov <tonynazarov+dev@gmail.com>
from collections.abc import ItemsView, Iterator
from dataclasses import dataclass, field, fields
from typing import Any

from pykeycloak.core.constants import (
    KEYCLOAK_MAX_ROWS_QUERY_LIMIT_DEFAULT,
    KEYCLOAK_PAGINATION_FIRST_DEFAULT,
)
from pykeycloak.core.helpers import getenv_int


@dataclass(kw_only=True)
class BaseQuery:
    def to_dict(self, exclude_none: bool = True) -> dict[str, Any]:
        params = {}
        for f in fields(self):
            value = getattr(self, f.name)

            if exclude_none and value is None:
                continue

            name = f.metadata.get("alias", f.name)
            params[name] = str(value)
        return params

    def __call__(self) -> dict[str, Any]:
        return self.to_dict()

    def items(self) -> ItemsView[str, Any]:
        return self.to_dict().items()

    def __iter__(self) -> Iterator[str]:
        return iter(self.to_dict())


@dataclass(kw_only=True)
class PaginationQuery(BaseQuery):
    max: int = field(
        default_factory=lambda: getenv_int(
            "KEYCLOAK_MAX_ROWS_QUERY_LIMIT", KEYCLOAK_MAX_ROWS_QUERY_LIMIT_DEFAULT
        )
    )
    first: int = KEYCLOAK_PAGINATION_FIRST_DEFAULT
    find_all: bool = field(default=False)

    def __post_init__(self) -> None:
        if self.find_all:
            self.max = int(
                getenv_int(
                    "KEYCLOAK_MAX_ROWS_QUERY_LIMIT",
                    KEYCLOAK_MAX_ROWS_QUERY_LIMIT_DEFAULT,
                )
            )

        if self.max < 0:
            raise ValueError("The 'max' parameter must be a positive integer or 0")

        if self.first < 0:
            raise ValueError("The 'first' parameter must be a positive integer or 0")


@dataclass(kw_only=True)
class BriefRepresentationQuery(BaseQuery):
    brief_representation: bool = field(
        default=False, metadata={"alias": "briefRepresentation"}
    )


@dataclass(kw_only=True)
class SearchQuery(BaseQuery):
    search: str | None = None


@dataclass(kw_only=True, slots=True)
class RoleMembersListQuery(PaginationQuery, BriefRepresentationQuery):
    """https://www.keycloak.org/docs-api/latest/rest-api/index.html#_get_adminrealmsrealmclientsclient_uuidrolesrole_nameusers"""


@dataclass(kw_only=True, slots=True)
class GroupMemberListQuery(PaginationQuery, BriefRepresentationQuery):
    """https://www.keycloak.org/docs-api/latest/rest-api/index.html#_get_adminrealmsrealmgroupsgroup_idmembers"""


@dataclass(kw_only=True, slots=True)
class GetUsersCountQuery(SearchQuery):
    pass


@dataclass(kw_only=True, slots=True)
class GetUsersQuery(SearchQuery, PaginationQuery):
    def __post_init__(self) -> None:
        super().__post_init__()

        max_users_per_query = getenv_int(
            "KEYCLOAK_MAX_ROWS_QUERY_LIMIT", KEYCLOAK_MAX_ROWS_QUERY_LIMIT_DEFAULT
        )

        if self.max > max_users_per_query:
            raise ValueError(
                f"The requested page size ({self.max}) exceeds the allowed limit ({max_users_per_query}). "
                f"Please check the 'KEYCLOAK_MAX_ROWS_QUERY_LIMIT' environment variable."
            )


@dataclass(kw_only=True, slots=True)
class ResourcesListQuery(PaginationQuery):
    deep: bool = True
    matchingUri: str | None = None
    name: str | None = None
    owner: str | None = None
    scope: str | None = None
    type: str | None = None
    uri: str | None = None


@dataclass(kw_only=True, slots=True)
class GroupListQuery(PaginationQuery, BriefRepresentationQuery, SearchQuery):
    exact: bool = False
    populate_hierarchy: bool = field(
        default=True, metadata={"alias": "populateHierarchy"}
    )
    q: str | None = None
    sub_group_count: bool = field(default=True, metadata={"alias": "subGroupCount"})


@dataclass(kw_only=True, slots=True)
class AdminRolesQuery(BriefRepresentationQuery, PaginationQuery, SearchQuery):
    pass


@dataclass(kw_only=True, slots=True)
class AdminRealmClientRoleGroupQuery(BriefRepresentationQuery, PaginationQuery):
    pass


@dataclass(kw_only=True, slots=True)
class FilterFindPolicyParams(BaseQuery):
    fields: list[str] | None = None
    name: str | None = None


@dataclass(kw_only=True, slots=True)
class FilterQueryParams(PaginationQuery):
    name: str = ""
    exact_name: bool = field(default=False, metadata={"alias": "exactName"})
    uri: str = ""
    owner: str | None = None
    resource_type: str | None = field(default=None, metadata={"alias": "type"})
    scope: str | None = None
    matching_uri: bool = field(default=False, metadata={"alias": "matchingUri"})


@dataclass(kw_only=True, slots=True)
class FindPermissionQuery(PaginationQuery):
    fields: list[str] | None = None
    name: str | None = None
    owner: str | None = None
    permission: bool | None = None
    policy_id: str | None = field(default=None, metadata={"alias": "policyId"})
    resource: str | None = None
    resource_type: str | None = field(default=None, metadata={"alias": "resourceType"})
    scope: str | None = None
    type: str | None = None
