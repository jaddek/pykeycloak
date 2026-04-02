# SPDX-License-Identifier: MIT
import pytest

from pykeycloak.core.enums import (
    AuthFlowsEnum,
    ClientAuthenticatorTypeEnum,
    DecisionStrategyEnum,
    GrantTypeEnum,
    LogicEnum,
    PermissionTypeEnum,
    PolicyEnforcementModeEnum,
    PolicyTypeEnum,
    ProtocolEnum,
    ProtocolMappersEnum,
    SystemPermissionsEnum,
    UrnIetfOauthUmaTicketPermissionResourceFormatEnum,
    UrnIetfOauthUmaTicketResponseModeEnum,
)


class TestAuthFlowsEnum:
    def test_authorization_code_flow_value(self):
        assert AuthFlowsEnum.AuthorizationCodeFlow == "AuthorizationCodeFlow"

    def test_client_credentials_flow_value(self):
        assert AuthFlowsEnum.ClientCredentialsFlow == "ClientCredentialsFlow"

    def test_resource_owner_password_value(self):
        assert (
            AuthFlowsEnum.ResourceOwnerPasswordCredentialsFlow
            == "ResourceOwnerPasswordCredentialsFlow"
        )

    def test_all_members_are_str(self):
        for member in AuthFlowsEnum:
            assert isinstance(member, str)


class TestGrantTypeEnum:
    def test_refresh_token_value(self):
        assert GrantTypeEnum.REFRESH_TOKEN == "refresh_token"

    def test_client_credentials_value(self):
        assert GrantTypeEnum.CLIENT_CREDENTIALS == "client_credentials"

    def test_password_value(self):
        assert GrantTypeEnum.PASSWORD == "password"

    def test_token_exchange_value(self):
        assert (
            GrantTypeEnum.URN_IETF_OAUTH_TOKEN_EXCHANGE
            == "urn:ietf:params:oauth:grant-type:token-exchange"
        )

    def test_uma_ticket_value(self):
        assert (
            GrantTypeEnum.URN_IETF_OAUTH_UMA_TICKET
            == "urn:ietf:params:oauth:grant-type:uma-ticket"
        )

    def test_authorization_code_value(self):
        assert GrantTypeEnum.AUTHORIZATION_CODE == "authorization_code"


class TestPermissionTypeEnum:
    def test_resource_value(self):
        assert PermissionTypeEnum.RESOURCE == "resource"

    def test_scope_value(self):
        assert PermissionTypeEnum.SCOPE == "scope"


class TestDecisionStrategyEnum:
    def test_affirmative_value(self):
        assert DecisionStrategyEnum.AFFIRMATIVE == "AFFIRMATIVE"

    def test_unanimous_value(self):
        assert DecisionStrategyEnum.UNANIMOUS == "UNANIMOUS"

    def test_consensus_value(self):
        assert DecisionStrategyEnum.CONSENSUS == "CONSENSUS"

    def test_has_three_members(self):
        assert len(DecisionStrategyEnum) == 3


class TestLogicEnum:
    def test_positive_value(self):
        assert LogicEnum.POSITIVE == "POSITIVE"

    def test_negative_value(self):
        assert LogicEnum.NEGATIVE == "NEGATIVE"


class TestUrnIetfEnums:
    def test_response_mode_decision(self):
        assert UrnIetfOauthUmaTicketResponseModeEnum.DECISION == "decision"

    def test_response_mode_permissions(self):
        assert UrnIetfOauthUmaTicketResponseModeEnum.PERMISSIONS == "permissions"

    def test_resource_format_id(self):
        assert UrnIetfOauthUmaTicketPermissionResourceFormatEnum.ID == "id"

    def test_resource_format_uri(self):
        assert UrnIetfOauthUmaTicketPermissionResourceFormatEnum.URI == "uri"


class TestClientAuthenticatorTypeEnum:
    def test_client_secret_value(self):
        assert ClientAuthenticatorTypeEnum.CLIENT_SECRET == "client-secret"

    def test_client_jwt_value(self):
        assert ClientAuthenticatorTypeEnum.CLIENT_JWT == "client-jwt"

    def test_client_x509_value(self):
        assert ClientAuthenticatorTypeEnum.CLIENT_X509 == "client-x509"


class TestProtocolEnum:
    def test_openid_connect_value(self):
        assert ProtocolEnum.OPENID_CONNECT == "openid-connect"

    def test_saml_value(self):
        assert ProtocolEnum.SAML == "saml"

    def test_docker_v2_value(self):
        assert ProtocolEnum.DOCKER_V2 == "docker-v2"


class TestPolicyEnforcementModeEnum:
    def test_enforcing_value(self):
        assert PolicyEnforcementModeEnum.ENFORCING == "ENFORCING"

    def test_permissive_value(self):
        assert PolicyEnforcementModeEnum.PERMISSIVE == "PERMISSIVE"

    def test_disabled_value(self):
        assert PolicyEnforcementModeEnum.DISABLED == "DISABLED"


class TestPolicyTypeEnum:
    @pytest.mark.parametrize(
        "member, expected",
        [
            (PolicyTypeEnum.ROLE, "role"),
            (PolicyTypeEnum.GROUP, "group"),
            (PolicyTypeEnum.USER, "user"),
            (PolicyTypeEnum.JS, "js"),
            (PolicyTypeEnum.TIME, "time"),
            (PolicyTypeEnum.AGGREGATE, "aggregate"),
            (PolicyTypeEnum.CLIENT, "client"),
            (PolicyTypeEnum.IP, "ip"),
        ],
    )
    def test_policy_type_values(self, member, expected):
        assert member == expected


class TestSystemPermissionsEnum:
    def test_view_users_value(self):
        assert SystemPermissionsEnum.VIEW_USERS == "view-users"

    def test_manage_users_value(self):
        assert SystemPermissionsEnum.MANAGE_USERS == "manage-users"

    def test_impersonation_value(self):
        assert SystemPermissionsEnum.IMPERSONATION == "impersonation"

    def test_manage_realm_value(self):
        assert SystemPermissionsEnum.MANAGE_REALM == "manage-realm"

    def test_all_members_are_str(self):
        for member in SystemPermissionsEnum:
            assert isinstance(member, str)


class TestProtocolMappersEnum:
    def test_property_mapper_value(self):
        assert ProtocolMappersEnum.PROPERTY_MAPPER == "oidc-usermodel-property-mapper"

    def test_role_mapper_value(self):
        assert ProtocolMappersEnum.ROLE_MAPPER == "oidc-usermodel-realm-role-mapper"

    def test_audience_mapper_value(self):
        assert ProtocolMappersEnum.AUDIENCE_MAPPER == "oidc-audience-mapper"

    def test_group_mapper_value(self):
        assert ProtocolMappersEnum.GROUP_MAPPER == "oidc-group-membership-mapper"
