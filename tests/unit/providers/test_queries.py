"""
Unit tests for the queries module.
"""

import pytest
from pykeycloak.providers.queries import (
    BaseQuery,
    PaginationQuery,
    BriefRepresentationQuery,
    GetUsersQuery,
    RoleMembersListQuery
)


class TestBaseQuery:
    """Test cases for the BaseQuery class."""

    def test_base_query_to_dict_empty(self):
        """Test converting an empty BaseQuery to dictionary."""
        class EmptyQuery(BaseQuery):
            pass
        
        query = EmptyQuery()
        result = query.to_dict()
        
        # Should return an empty dictionary since there are no fields
        assert result == {}

    def test_base_query_to_dict_with_fields(self):
        """Test converting a BaseQuery with fields to dictionary."""
        from dataclasses import dataclass

        @dataclass(kw_only=True)
        class TestQuery(BaseQuery):
            param1: str | None = None
            param2: str | None = None

        query = TestQuery(param1="value1", param2="value2")
        result = query.to_dict()

        expected = {"param1": "value1", "param2": "value2"}
        assert result == expected

    def test_base_query_to_dict_skips_none_values(self):
        """Test that None values are skipped in to_dict."""
        from dataclasses import dataclass

        @dataclass(kw_only=True)
        class TestQuery(BaseQuery):
            param1: str | None = None
            param2: str | None = None
            param3: str | None = None

        query = TestQuery(param2="has_value")
        result = query.to_dict()

        # Only param2 should be in the result
        assert result == {"param2": "has_value"}
        assert "param1" not in result
        assert "param3" not in result

    def test_base_query_to_dict_skips_false_values(self):
        """Test that False values are skipped in to_dict."""
        from dataclasses import dataclass

        @dataclass(kw_only=True)
        class TestQuery(BaseQuery):
            param1: str | None = None
            param2: bool = False
            param3: bool = True

        query = TestQuery()
        result = query.to_dict()

        # Only param3 should be in the result
        assert result == {"param3": "true"}
        assert "param1" not in result
        assert "param2" not in result

    def test_base_query_call_method(self):
        """Test the __call__ method of BaseQuery."""
        from dataclasses import dataclass

        @dataclass(kw_only=True)
        class TestQuery(BaseQuery):
            param: str = "value"

        query = TestQuery()
        result = query()

        assert result == {"param": "value"}

    def test_base_query_items_method(self):
        """Test the items method of BaseQuery."""
        from dataclasses import dataclass

        @dataclass(kw_only=True)
        class TestQuery(BaseQuery):
            param1: str = "value1"
            param2: str = "value2"

        query = TestQuery()
        items = list(query.items())

        # Convert to dict for easier comparison
        result_dict = dict(items)
        expected = {"param1": "value1", "param2": "value2"}
        assert result_dict == expected

    def test_base_query_iter_method(self):
        """Test the __iter__ method of BaseQuery."""
        from dataclasses import dataclass

        @dataclass(kw_only=True)
        class TestQuery(BaseQuery):
            param1: str = "value1"
            param2: str = "value2"

        query = TestQuery()
        items = list(iter(query))

        # Should return the keys of the dictionary
        assert "param1" in items
        assert "param2" in items
        assert len(items) == 2


class TestPaginationQuery:
    """Test cases for the PaginationQuery class."""

    def test_pagination_query_defaults(self):
        """Test PaginationQuery with default values."""
        query = PaginationQuery()

        # Check defaults - these might come from environment variables
        # but if not set, max should default to 100 and first to 0
        result = query.to_dict()
        assert "max" in result
        assert "first" in result
        assert result["first"] == "0"  # to_dict() converts to string

    def test_pagination_query_custom_values(self):
        """Test PaginationQuery with custom values."""
        max_val = 50
        first_val = 10
        query = PaginationQuery(max=max_val, first=first_val)
        
        result = query.to_dict()
        assert result["max"] == str(max_val)
        assert result["first"] == str(first_val)

    def test_pagination_query_only_max(self):
        """Test PaginationQuery with only max specified."""
        max_val = 75
        query = PaginationQuery(max=max_val)
        
        result = query.to_dict()
        assert result["max"] == str(max_val)
        # first should still be 0
        assert result["first"] == "0"

    def test_pagination_query_only_first(self):
        """Test PaginationQuery with only first specified."""
        first_val = 20
        query = PaginationQuery(first=first_val)
        
        result = query.to_dict()
        # max should be the default value
        assert "max" in result
        assert result["first"] == str(first_val)


class TestBriefRepresentationQuery:
    """Test cases for the BriefRepresentationQuery class."""

    def test_brief_representation_query_default_false(self):
        """Test BriefRepresentationQuery with default false value."""
        query = BriefRepresentationQuery()
        
        result = query.to_dict()
        # Since brief_representation is False by default, it should not appear in the dict
        assert "brief_representation" not in result
        assert "briefRepresentation" not in result

    def test_brief_representation_query_true(self):
        """Test BriefRepresentationQuery with true value."""
        query = BriefRepresentationQuery(brief_representation=True)
        
        result = query.to_dict()
        # Should use the alias "briefRepresentation" and be "true"
        assert result["briefRepresentation"] == "true"
        assert "brief_representation" not in result

    def test_brief_representation_query_false_explicit(self):
        """Test BriefRepresentationQuery with explicitly set false value."""
        query = BriefRepresentationQuery(brief_representation=False)
        
        result = query.to_dict()
        # Even though explicitly set to False, it should still be skipped
        assert "brief_representation" not in result
        assert "briefRepresentation" not in result


class TestGetUsersQuery:
    """Test cases for the GetUsersQuery class."""

    def test_get_users_query_empty(self):
        """Test GetUsersQuery with no parameters."""
        from dataclasses import dataclass

        @dataclass(kw_only=True)
        class EmptyGetUsersQuery(GetUsersQuery):
            pass

        query = EmptyGetUsersQuery()

        result = query.to_dict()
        # Should contain default pagination values
        assert "first" in result
        assert "max" in result

    def test_get_users_query_with_parameters(self):
        """Test GetUsersQuery with various parameters."""
        from dataclasses import dataclass, field

        @dataclass(kw_only=True)
        class CustomGetUsersQuery(GetUsersQuery):
            username: str | None = None
            first_name: str | None = None
            last_name: str | None = None
            email: str | None = None
            brief_representation: bool = field(default=False, metadata={"alias": "briefRepresentation"})
            first_name_field: str | None = field(default=None, metadata={"alias": "firstName"})
            last_name_field: str | None = field(default=None, metadata={"alias": "lastName"})
            email_verified_field: bool = field(default=False, metadata={"alias": "emailVerified"})

        query = CustomGetUsersQuery(
            username="testuser",
            first_name_field="John",
            last_name_field="Doe",
            email="john.doe@example.com",
            brief_representation=True,
            first=0,
            max=10
        )

        result = query.to_dict()

        # Check that all parameters are present with correct values
        assert result["username"] == "testuser"
        assert result["firstName"] == "John"
        assert result["lastName"] == "Doe"
        assert result["email"] == "john.doe@example.com"
        assert result["briefRepresentation"] == "true"
        assert result["first"] == "0"
        assert result["max"] == "10"

    def test_get_users_query_skips_none_and_false_params(self):
        """Test that GetUsersQuery skips None and False parameters."""
        from dataclasses import dataclass, field

        @dataclass(kw_only=True)
        class CustomGetUsersQuery(GetUsersQuery):
            username: str | None = None
            first_name_field: str | None = field(default=None, metadata={"alias": "firstName"})
            email_verified_field: bool = field(default=False, metadata={"alias": "emailVerified"})
            brief_representation: bool = field(default=False, metadata={"alias": "briefRepresentation"})

        query = CustomGetUsersQuery(
            username="testuser",
            first_name_field=None,  # firstName is None, should be skipped
            email_verified_field=False,  # Should be skipped
            brief_representation=True  # Should be included
        )

        result = query.to_dict()

        assert "username" in result
        assert "firstName" not in result  # None value should be skipped
        assert "emailVerified" not in result  # False value should be skipped
        assert "briefRepresentation" in result  # True value should be included as "true"


class TestRoleMembersListQuery:
    """Test cases for the RoleMembersListQuery class."""

    def test_role_members_list_query_empty(self):
        """Test RoleMembersListQuery with no parameters."""
        query = RoleMembersListQuery()

        result = query.to_dict()
        # Should contain default pagination values
        assert "first" in result
        assert "max" in result

    def test_role_members_list_query_with_parameters(self):
        """Test RoleMembersListQuery with parameters."""
        from dataclasses import dataclass

        @dataclass(kw_only=True)
        class CustomRoleMembersListQuery(RoleMembersListQuery):
            search: str | None = None

        query = CustomRoleMembersListQuery(
            first=5,
            max=20,
            search="search_term"
        )

        result = query.to_dict()

        assert result["first"] == "5"
        assert result["max"] == "20"
        assert result["search"] == "search_term"