import os
from abc import ABC
from dataclasses import dataclass, field


@dataclass
class PaginationQuery(ABC):
    max: int = field(default=100)
    first: int = field(default=0)


@dataclass
class BriefRepresentationQuery(ABC):
    brief_representation: bool = field(default=False)


@dataclass
class SearchQuery(ABC):
    search: str | None = field(default=None)


@dataclass
class RoleMembersListQuery(
    PaginationQuery, BriefRepresentationQuery
):
    """
    https://www.keycloak.org/docs-api/latest/rest-api/index.html#_get_adminrealmsrealmclientsclient_uuidrolesrole_nameusers
    """

    ...


@dataclass
class GroupMemberListQuery(
    PaginationQuery, BriefRepresentationQuery
):
    """
    https://www.keycloak.org/docs-api/latest/rest-api/index.html#_get_adminrealmsrealmgroupsgroup_idmembers
    """

    ...


@dataclass
class GetUsersCountQuery(SearchQuery): ...

@dataclass
class GetUsersQuery(SearchQuery, PaginationQuery):
    def __post_init__(self):
        max_limit_str = os.getenv('KEYCLOAK_MAX_USERS_QUERY_LIMIT', '1000')
        max_allowed = int(max_limit_str) if max_limit_str.strip() != '' else 1000
        if self.max > max_allowed:
            raise ValueError(f"Max value {self.max} exceeds allowed limit of {max_allowed}")

@dataclass
class ResourcesListQuery(PaginationQuery):
    """
    https://www.keycloak.org/docs-api/latest/rest-api/index.html#_get_adminrealmsrealmclientsclient_uuidauthzresource_serverresource
    """

    deep: bool = field(default=True)  # when false we do not getting scopes and other fields
    matchingUri: str | None = field(default=None)
    name: str | None = field(default=None)
    owner: str | None = field(default=None)
    scope: str | None = field(default=None)
    type: str | None = field(default=None)
    uri: str | None = field(default=None)


@dataclass
class GroupListQuery(
    PaginationQuery, BriefRepresentationQuery, SearchQuery
):
    """
    https://www.keycloak.org/docs-api/latest/rest-api/index.html#_getgroups
    """

    exact: bool = field(default=False)
    populate_hierarchy: bool = field(default=True)
    q: str | None = field(default=None)
    sub_group_count: bool = field(default=True)


@dataclass
class AdminRolesQuery(
    BriefRepresentationQuery, PaginationQuery, SearchQuery
): ...


@dataclass
class AdminRealmClientRoleGroupQuery(
    BriefRepresentationQuery, PaginationQuery
): ...


@dataclass
class FindPermissionQuery(PaginationQuery):
    fields: list[str] | None = field(default=None)
    name: str | None = field(default=None)
    owner: str | None = field(default=None)
    permission: bool | None = field(default=None)
    policy_id: str | None = field(default=None)
    resource: str | None = field(default=None)
    resource_type: str | None = field(default=None)
    scope: str | None = field(default=None)
    type: str | None = field(default=None)


@dataclass
class FilterFindPolicyParams():
    fields: list[str] | None = field(default=None)
    name: str | None = field(default=None)


@dataclass
class FilterQueryParams(PaginationQuery):
    name: str = field(default="")
    exact_name: bool = field(default=False)
    uri: str = field(default="")
    owner: str | None = field(default=None)
    resource_type: str | None = field(default=None)
    scope: str | None = field(default=None)
    matching_uri: bool = field(default=False)

    def filter_to_query_dict(self) -> dict:
        query = {}

        if self.name:
            query["name"] = self.name
            if self.exact_name:
                query["exactName"] = "true"

        if self.uri:
            query["uri"] = self.uri

        if self.owner is not None:
            query["owner"] = self.owner

        if self.resource_type is not None:
            query["type"] = self.resource_type

        if self.scope is not None:
            query["scope"] = self.scope

        if self.matching_uri:
            query["matchingUri"] = "true"

        if self.first > 0:
            query["first"] = str(self.first)

        if self.max > 0:
            query["max"] = str(self.max)

        return query

