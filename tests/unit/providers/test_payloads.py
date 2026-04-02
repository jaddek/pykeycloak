# SPDX-License-Identifier: MIT
import json

import pytest

from pykeycloak.core.enums import (
    GrantTypeEnum,
    UrnIetfOauthUmaTicketPermissionResourceFormatEnum,
    UrnIetfOauthUmaTicketResponseModeEnum,
)
from pykeycloak.providers.payloads import (
    ClientCredentialsLoginPayload,
    ConfidentialClientRevokePayload,
    CreateUserPayload,
    CredentialsPayload,
    PasswordCredentialsPayload,
    PermissionPayload,
    PermissionScopesPayload,
    PublicClientRevokePayload,
    RefreshTokenPayload,
    ResourcePayload,
    RoleAssignPayload,
    RolePolicyPayload,
    RTPExchangeTokenPayload,
    RTPIntrospectionPayload,
    SSOLoginPayload,
    TokenIntrospectionPayload,
    UMAAuthorizationPayload,
    UpdateUserPayload,
    UserAuthorisationCodePayload,
    UserCredentialsLoginPayload,
    UserUpdateEnablePayload,
    UserUpdatePasswordPayload,
)


class TestPayloadToDict:
    def test_excludes_none_by_default(self):
        p = RoleAssignPayload(id="1", name="admin")
        d = p.to_dict()
        assert d == {"id": "1", "name": "admin"}

    def test_includes_none_when_flag_false(self):
        p = PermissionPayload(name="perm")
        d = p.to_dict(exclude_none=False)
        assert "id" in d
        assert d["id"] is None

    def test_alias_applied(self):
        p = PermissionPayload(decision_strategy="AFFIRMATIVE")
        d = p.to_dict()
        assert "decisionStrategy" in d
        assert "decision_strategy" not in d

    def test_to_json_returns_valid_json(self):
        p = RoleAssignPayload(id="1", name="admin")
        result = json.loads(p.to_json())
        assert result["id"] == "1"
        assert result["name"] == "admin"


class TestTokenIntrospectionPayload:
    def test_to_dict_contains_token(self):
        p = TokenIntrospectionPayload(token="mytoken")
        assert p.to_dict()["token"] == "mytoken"


class TestRTPIntrospectionPayload:
    def test_token_type_hint_default(self):
        p = RTPIntrospectionPayload(token="tok")
        d = p.to_dict()
        assert d["token_type_hint"] == "requesting_party_token"

    def test_is_subclass_of_token_introspection(self):
        assert issubclass(RTPIntrospectionPayload, TokenIntrospectionPayload)


class TestSSOLoginPayload:
    def test_default_scope(self):
        p = SSOLoginPayload(client_id="cid", redirect_uri="https://r.com", state="st")
        assert p.scope == "openid profile email"

    def test_custom_scopes(self):
        p = SSOLoginPayload(
            client_id="cid",
            redirect_uri="https://r.com",
            state="st",
            scopes="openid",
        )
        assert p.scope == "openid"

    def test_response_type_is_code(self):
        p = SSOLoginPayload(client_id="cid", redirect_uri="https://r.com", state="st")
        assert p.response_type == "code"

    def test_to_dict_excludes_scopes_field(self):
        p = SSOLoginPayload(client_id="cid", redirect_uri="https://r.com", state="st")
        d = p.to_dict()
        assert "scopes" not in d

    def test_to_dict_includes_response_type(self):
        p = SSOLoginPayload(client_id="cid", redirect_uri="https://r.com", state="st")
        d = p.to_dict()
        assert d["response_type"] == "code"

    def test_to_dict_includes_scope(self):
        p = SSOLoginPayload(client_id="cid", redirect_uri="https://r.com", state="st")
        d = p.to_dict()
        assert "scope" in d


class TestUserCredentialsLoginPayload:
    def test_grant_type_is_password(self):
        p = UserCredentialsLoginPayload(username="u", password="p")
        assert p.grant_type == GrantTypeEnum.PASSWORD

    def test_to_dict_contains_grant_type(self):
        p = UserCredentialsLoginPayload(username="u", password="p")
        d = p.to_dict()
        assert d["grant_type"] == GrantTypeEnum.PASSWORD

    def test_to_dict_excludes_scopes(self):
        p = UserCredentialsLoginPayload(username="u", password="p")
        assert "scopes" not in p.to_dict()

    def test_to_dict_includes_scope(self):
        p = UserCredentialsLoginPayload(username="u", password="p")
        assert "scope" in p.to_dict()


class TestClientCredentialsLoginPayload:
    def test_grant_type_is_client_credentials(self):
        p = ClientCredentialsLoginPayload()
        assert p.grant_type == GrantTypeEnum.CLIENT_CREDENTIALS


class TestUserAuthorisationCodePayload:
    def test_grant_type_is_authorization_code(self):
        p = UserAuthorisationCodePayload(code="code123", redirect_uri="https://r.com")
        assert p.grant_type == GrantTypeEnum.AUTHORIZATION_CODE


class TestRefreshTokenPayload:
    def test_grant_type_is_refresh_token(self):
        p = RefreshTokenPayload(refresh_token="ref")
        assert p.grant_type == GrantTypeEnum.REFRESH_TOKEN

    def test_to_dict_contains_refresh_token(self):
        p = RefreshTokenPayload(refresh_token="ref123")
        d = p.to_dict()
        assert d["refresh_token"] == "ref123"


class TestRTPExchangeTokenPayload:
    def test_grant_type_is_token_exchange(self):
        p = RTPExchangeTokenPayload(refresh_token="tok")
        assert p.grant_type == GrantTypeEnum.URN_IETF_OAUTH_TOKEN_EXCHANGE


class TestRevokePayloads:
    def test_confidential_revoke_defaults(self):
        p = ConfidentialClientRevokePayload(token="tok")
        assert p.token_type_hint == "refresh_token"

    def test_confidential_revoke_to_dict(self):
        p = ConfidentialClientRevokePayload(token="tok")
        d = p.to_dict()
        assert d["token"] == "tok"
        assert d["token_type_hint"] == "refresh_token"

    def test_public_revoke_contains_client_id(self):
        p = PublicClientRevokePayload(client_id="cid", token="tok")
        d = p.to_dict()
        assert d["client_id"] == "cid"


class TestUMAAuthorizationPayload:
    def test_grant_type_is_uma_ticket(self):
        p = UMAAuthorizationPayload(
            permissions=["res1"],
            subject_token="sub_tok",
        )
        assert p.grant_type == str(GrantTypeEnum.URN_IETF_OAUTH_UMA_TICKET)

    def test_default_response_mode_is_decision(self):
        p = UMAAuthorizationPayload(permissions=[], subject_token="t")
        assert p.response_mode == UrnIetfOauthUmaTicketResponseModeEnum.DECISION

    def test_default_resource_format_is_uri(self):
        p = UMAAuthorizationPayload(permissions=[], subject_token="t")
        assert (
            p.permission_resource_format
            == UrnIetfOauthUmaTicketPermissionResourceFormatEnum.URI
        )

    def test_to_dict_includes_grant_type(self):
        p = UMAAuthorizationPayload(permissions=["r1"], subject_token="tok")
        d = p.to_dict()
        assert d["grant_type"] == str(GrantTypeEnum.URN_IETF_OAUTH_UMA_TICKET)

    def test_to_dict_permissions_list(self):
        p = UMAAuthorizationPayload(permissions=["r1", "r2"], subject_token="tok")
        d = p.to_dict()
        assert d["permission"] == ["r1", "r2"]

    def test_audience_can_be_none(self):
        p = UMAAuthorizationPayload(permissions=[], subject_token="t")
        assert p.audience is None


class TestCreateUserPayload:
    def test_minimal_creation(self):
        p = CreateUserPayload(username="john")
        assert p.username == "john"
        assert p.enabled is True
        assert p.emailVerified is False

    def test_first_last_name_alias(self):
        p = CreateUserPayload(username="john", first_name="John", last_name="Doe")
        d = p.to_dict()
        assert "firstName" in d
        assert "lastName" in d
        assert "first_name" not in d
        assert "last_name" not in d

    def test_credentials_serialized(self):
        cred = CredentialsPayload(type="password", value="secret")
        p = CreateUserPayload(username="u", credentials=[cred])
        d = p.to_dict()
        assert d["credentials"] == [{"type": "password", "value": "secret"}]

    def test_empty_credentials_by_default(self):
        p = CreateUserPayload(username="u")
        assert p.to_dict()["credentials"] == []


class TestUpdateUserPayload:
    def test_all_fields_none_by_default(self):
        p = UpdateUserPayload()
        d = p.to_dict()
        assert d == {}

    def test_partial_update(self):
        p = UpdateUserPayload(email="new@example.com", enabled=False)
        d = p.to_dict()
        assert d["email"] == "new@example.com"
        assert d["enabled"] is False
        assert "id" not in d


class TestPasswordCredentialsPayload:
    def test_type_is_password(self):
        p = PasswordCredentialsPayload(value="secret")
        assert p.type == "password"

    def test_temporary_defaults_to_false(self):
        p = PasswordCredentialsPayload(value="secret")
        assert p.temporary is False


class TestUserUpdateEnablePayload:
    def test_enabled_true_by_default(self):
        p = UserUpdateEnablePayload()
        assert p.enabled is True

    def test_can_disable(self):
        p = UserUpdateEnablePayload(enabled=False)
        assert p.to_dict()["enabled"] is False


class TestUserUpdatePasswordPayload:
    def test_empty_credentials_by_default(self):
        p = UserUpdatePasswordPayload()
        assert p.credentials == []


class TestRolePayload:
    def test_name_required(self):
        from pykeycloak.providers.payloads import RolePayload

        p = RolePayload(name="admin")
        d = p.to_dict()
        assert d["name"] == "admin"

    def test_optional_fields_excluded(self):
        from pykeycloak.providers.payloads import RolePayload

        p = RolePayload(name="admin")
        d = p.to_dict()
        assert "id" not in d
        assert "description" not in d


class TestRoleAssignPayload:
    def test_to_dict(self):
        p = RoleAssignPayload(id="role-uuid", name="admin")
        d = p.to_dict()
        assert d == {"id": "role-uuid", "name": "admin"}


class TestPermissionScopesPayload:
    def test_name_required(self):
        p = PermissionScopesPayload(name="perm")
        assert p.name == "perm"

    def test_policies_default_empty(self):
        p = PermissionScopesPayload(name="perm")
        assert p.policies == []

    def test_decision_strategy_alias(self):
        p = PermissionScopesPayload(name="perm", decision_strategy="AFFIRMATIVE")
        d = p.to_dict()
        assert "decisionStrategy" in d
        assert d["decisionStrategy"] == "AFFIRMATIVE"


class TestResourcePayload:
    def test_to_dict_renames_id_to_underscore_id(self):
        p = ResourcePayload(id="res-1", name="myresource")
        d = p.to_dict()
        assert "_id" in d
        assert "id" not in d
        assert d["_id"] == "res-1"

    def test_default_lists(self):
        p = ResourcePayload()
        d = p.to_dict(exclude_none=False)
        assert d["uris"] == []
        assert d["scopes"] == []

    def test_display_name_alias(self):
        p = ResourcePayload(id="res-1", display_name="My Resource")
        d = p.to_dict()
        assert "displayName" in d
        assert "display_name" not in d


class TestRolePolicyPayload:
    def test_name_and_empty_roles(self):
        p = RolePolicyPayload(name="my-policy")
        d = p.to_dict()
        assert d["name"] == "my-policy"
        assert d["roles"] == []

    def test_with_roles(self):
        p = RolePolicyPayload(name="my-policy", roles=["role1", "role2"])
        d = p.to_dict()
        assert d["roles"] == ["role1", "role2"]
