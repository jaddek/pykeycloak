# SPDX-License-Identifier: MIT
import pytest

from pykeycloak.providers.queries import (
    AdminRealmClientRoleGroupQuery,
    AdminRolesQuery,
    BaseQuery,
    BriefRepresentationQuery,
    FilterFindPolicyParams,
    FilterQueryParams,
    FindPermissionQuery,
    GetUsersCountQuery,
    GetUsersQuery,
    GroupListQuery,
    GroupMemberListQuery,
    PaginationQuery,
    ResourcesListQuery,
    RoleMembersListQuery,
    SearchQuery,
)


class TestBaseQuery:
    def test_to_dict_excludes_none_by_default(self):
        q = SearchQuery(search=None)
        assert q.to_dict() == {}

    def test_to_dict_includes_none_when_flag_false(self):
        q = SearchQuery(search=None)
        d = q.to_dict(exclude_none=False)
        assert "search" in d

    def test_alias_applied(self):
        q = BriefRepresentationQuery(brief_representation=True)
        d = q.to_dict()
        assert "briefRepresentation" in d
        assert "brief_representation" not in d

    def test_values_cast_to_str(self):
        q = PaginationQuery(max=50, first=10)
        d = q.to_dict()
        assert d["max"] == "50"
        assert d["first"] == "10"

    def test_call_returns_to_dict(self):
        q = SearchQuery(search="foo")
        assert q() == q.to_dict()

    def test_items_returns_items_view(self):
        q = SearchQuery(search="foo")
        items = dict(q.items())
        assert items["search"] == "foo"

    def test_iter_yields_keys(self):
        q = SearchQuery(search="bar")
        assert "search" in list(q)


class TestPaginationQuery:
    def test_defaults(self):
        q = PaginationQuery()
        assert q.first == 0
        assert q.max > 0

    def test_raises_on_negative_max(self):
        with pytest.raises(ValueError, match="max"):
            PaginationQuery(max=-1)

    def test_raises_on_negative_first(self):
        with pytest.raises(ValueError, match="first"):
            PaginationQuery(first=-1)

    def test_to_dict_excludes_find_all(self):
        q = PaginationQuery(find_all=True)
        d = q.to_dict()
        assert "find_all" not in d

    def test_find_all_sets_max_to_limit(self):
        q = PaginationQuery(find_all=True)
        assert q.max > 0


class TestBriefRepresentationQuery:
    def test_default_is_false(self):
        q = BriefRepresentationQuery()
        d = q.to_dict()
        assert d["briefRepresentation"] == "False"

    def test_true_value(self):
        q = BriefRepresentationQuery(brief_representation=True)
        d = q.to_dict()
        assert d["briefRepresentation"] == "True"


class TestGetUsersQuery:
    def test_inherits_pagination_and_search(self):
        q = GetUsersQuery()
        assert isinstance(q, PaginationQuery)

    def test_raises_when_max_exceeds_limit(self, monkeypatch):
        monkeypatch.setenv("KEYCLOAK_MAX_ROWS_QUERY_LIMIT", "10")
        with pytest.raises(ValueError, match="exceeds the allowed limit"):
            GetUsersQuery(max=9999)

    def test_valid_max(self, monkeypatch):
        monkeypatch.setenv("KEYCLOAK_MAX_ROWS_QUERY_LIMIT", "100")
        q = GetUsersQuery(max=50)
        assert q.max == 50


class TestRoleMembersListQuery:
    def test_inherits_pagination_and_brief(self):
        q = RoleMembersListQuery()
        assert isinstance(q, PaginationQuery)
        assert isinstance(q, BriefRepresentationQuery)

    def test_to_dict_contains_brief_representation(self):
        q = RoleMembersListQuery(brief_representation=True)
        d = q.to_dict()
        assert "briefRepresentation" in d


class TestResourcesListQuery:
    def test_deep_default_true(self):
        q = ResourcesListQuery()
        assert q.deep is True

    def test_to_dict_excludes_none_fields(self):
        q = ResourcesListQuery()
        d = q.to_dict()
        assert "name" not in d
        assert "owner" not in d

    def test_with_name_and_uri(self):
        q = ResourcesListQuery(name="res", uri="/api/resource")
        d = q.to_dict()
        assert d["name"] == "res"
        assert d["uri"] == "/api/resource"


class TestGroupListQuery:
    def test_defaults(self):
        q = GroupListQuery()
        assert q.exact is False
        assert q.populate_hierarchy is True

    def test_alias_populate_hierarchy(self):
        q = GroupListQuery(populate_hierarchy=False)
        d = q.to_dict()
        assert "populateHierarchy" in d
        assert d["populateHierarchy"] == "False"

    def test_sub_group_count_alias(self):
        q = GroupListQuery()
        d = q.to_dict()
        assert "subGroupCount" in d


class TestFilterFindPolicyParams:
    def test_empty_by_default(self):
        q = FilterFindPolicyParams()
        assert q.to_dict() == {}

    def test_with_name(self):
        q = FilterFindPolicyParams(name="my-policy")
        d = q.to_dict()
        assert d["name"] == "my-policy"


class TestFindPermissionQuery:
    def test_inherits_pagination(self):
        q = FindPermissionQuery()
        assert isinstance(q, PaginationQuery)

    def test_policy_id_alias(self):
        q = FindPermissionQuery(policy_id="pid")
        d = q.to_dict()
        assert "policyId" in d
        assert d["policyId"] == "pid"

    def test_resource_type_alias(self):
        q = FindPermissionQuery(resource_type="scope")
        d = q.to_dict()
        assert "resourceType" in d


class TestFilterQueryParams:
    def test_exact_name_alias(self):
        q = FilterQueryParams(exact_name=True)
        d = q.to_dict()
        assert "exactName" in d

    def test_matching_uri_alias(self):
        q = FilterQueryParams(matching_uri=True)
        d = q.to_dict()
        assert "matchingUri" in d

    def test_resource_type_alias(self):
        q = FilterQueryParams(resource_type="scope")
        d = q.to_dict()
        assert "type" in d


class TestAdminRolesQuery:
    def test_inherits_brief_pagination_search(self):
        q = AdminRolesQuery()
        assert isinstance(q, BriefRepresentationQuery)
        assert isinstance(q, PaginationQuery)


class TestGroupMemberListQuery:
    def test_inherits_pagination_and_brief(self):
        q = GroupMemberListQuery()
        assert isinstance(q, PaginationQuery)
        assert isinstance(q, BriefRepresentationQuery)
