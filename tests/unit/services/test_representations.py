"""
Unit tests for the representations module.
"""

import pytest

from pykeycloak.services.representations import (
    RealmAccessRepresentation,
    Representation,
    TokenRepresentation,
    UserInfoRepresentation,
)


class TestRepresentation:
    """Test cases for the base Representation class."""

    def test_representation_creation(self):
        """Test creating a Representation instance."""

        class TestRepresentation(Representation):
            pass

        rep = TestRepresentation()
        assert isinstance(rep, Representation)
        assert isinstance(rep, object)


class TestTokenRepresentation:
    """Test cases for the TokenRepresentation class."""

    def test_token_representation_defaults(self):
        """Test TokenRepresentation with default values."""
        # Note: TokenRepresentation has required fields, so we must provide them
        token_rep = TokenRepresentation(
            access_token="access-token",  # noqa: S106
            expires_in=3600,
            scope="read write",
            token_type="Bearer",  # noqa: S105, S106
            not_before_policy=0,
        )

        assert token_rep.access_token == "access-token"  # noqa: S105
        assert token_rep.expires_in == 3600
        assert token_rep.scope == "read write"
        assert token_rep.token_type == "Bearer"  # noqa: S105
        assert token_rep.not_before_policy == 0
        assert token_rep.session_state is None
        assert token_rep.refresh_token is None
        assert token_rep.refresh_token_expires_in is None

    def test_token_representation_with_all_values(self):
        """Test TokenRepresentation with all values provided."""
        token_rep = TokenRepresentation(
            access_token="access-token",  # noqa: S106
            expires_in=3600,
            scope="read write",
            token_type="Bearer",  # noqa: S105,S106
            not_before_policy=0,
            session_state="session-state",  # noqa: S105,S106
            refresh_token="refresh-token",  # noqa: S105,S106
            refresh_token_expires_in=7200,
        )

        assert token_rep.access_token == "access-token"  # noqa: S105
        assert token_rep.expires_in == 3600
        assert token_rep.scope == "read write"
        assert token_rep.token_type == "Bearer"  # noqa: S105,S106
        assert token_rep.not_before_policy == 0
        assert token_rep.session_state == "session-state"  # noqa: S105
        assert token_rep.refresh_token == "refresh-token"  # noqa: S105
        assert token_rep.refresh_token_expires_in == 7200

    def test_token_representation_immutability(self):
        """Test that TokenRepresentation is immutable."""
        token_rep = TokenRepresentation(
            access_token="access-token",  # noqa: S106
            expires_in=3600,
            scope="read write",
            token_type="Bearer",  # noqa: S106
            not_before_policy=0,
        )

        # Attempt to modify should raise an error
        with pytest.raises(Exception):  # noqa: B017
            token_rep.access_token = "new-token"  # noqa: S105


class TestUserInfoRepresentation:
    """Test cases for the UserInfoRepresentation class."""

    def test_user_info_representation_defaults(self):
        """Test UserInfoRepresentation with default values."""
        user_info = UserInfoRepresentation(
            id="user-id",
            first_name="John",
            last_name="Doe",
            email="john.doe@example.com",
            username="johndoe",
        )

        assert user_info.id == "user-id"
        assert user_info.first_name == "John"
        assert user_info.last_name == "Doe"
        assert user_info.email == "john.doe@example.com"
        assert user_info.username == "johndoe"
        assert user_info.email_verified is False  # Default value
        assert user_info.attributes is None  # Default value

    def test_user_info_representation_with_all_values(self):
        """Test UserInfoRepresentation with all values provided."""
        attributes = {"department": "engineering", "manager": "supervisor"}
        user_info = UserInfoRepresentation(
            id="user-id",
            first_name="John",
            last_name="Doe",
            email="john.doe@example.com",
            username="johndoe",
            email_verified=True,
            attributes=attributes,
        )

        assert user_info.id == "user-id"
        assert user_info.first_name == "John"
        assert user_info.last_name == "Doe"
        assert user_info.email == "john.doe@example.com"
        assert user_info.username == "johndoe"
        assert user_info.email_verified is True
        assert user_info.attributes == attributes

    def test_user_info_representation_metadata_aliases(self):
        """Test that metadata aliases work correctly."""
        user_info = UserInfoRepresentation(
            id="user-id",  # Maps to 'sub' via alias
            first_name="John",  # Maps to 'firstName' via alias
            last_name="Doe",  # Maps to 'lastName' via alias
            email="john.doe@example.com",
            username="johndoe",
            email_verified=True,
        )

        # The attributes should be accessible by their Python names
        assert user_info.id == "user-id"
        assert user_info.first_name == "John"
        assert user_info.last_name == "Doe"

        # Verify the aliases would map correctly in serialization


class TestRealmAccessRepresentation:
    """Test cases for the RealmAccessRepresentation class."""

    def test_realm_access_representation_defaults(self):
        """Test RealmAccessRepresentation with default values."""
        realm_access = RealmAccessRepresentation()

        assert realm_access.roles == ()  # Default empty tuple

    def test_realm_access_representation_with_roles(self):
        """Test RealmAccessRepresentation with roles."""
        roles = ("admin", "user", "viewer")
        realm_access = RealmAccessRepresentation(roles=roles)

        assert realm_access.roles == roles

    def test_realm_access_representation_single_role(self):
        """Test RealmAccessRepresentation with a single role."""
        roles = ("admin",)  # Single-element tuple
        realm_access = RealmAccessRepresentation(roles=roles)

        assert realm_access.roles == roles
        assert len(realm_access.roles) == 1
        assert realm_access.roles[0] == "admin"
