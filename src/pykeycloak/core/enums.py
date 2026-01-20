# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Anton "Tony" Nazarov <tonynazarov+dev@gmail.com>

from enum import StrEnum


class AuthFlowsEnum(StrEnum):
    """
    Standard Flow and Authorization Code Flow: For web applications with a server-side component, where the client_secret can be securely stored.
    Implicit Flow: For client-side applications, such as SPAs, where the client_secret cannot be securely stored.
    Direct Access Grants: For applications that trust the users, such as mobile applications.
    Service Accounts: For communication between services without user involvement.
    Token Exchange: When there is a need to exchange tokens between different services.
    OAuth 2.0 Device Flow: For devices with limited input capabilities (e.g., smart TVs or consoles).
    OIDC CIBA Grant: For automatic authentication through an API, without interaction with a browser.
    """

    AuthorizationCodeFlow = "AuthorizationCodeFlow"  # StandardFlow
    ImplicitFlow = "ImplicitFlow"
    ResourceOwnerPasswordCredentialsFlow = (
        "ResourceOwnerPasswordCredentialsFlow"  # DirectAccessGrants
    )
    TokenExchangeFlow = "TokenExchangeFlow"
    ClientCredentialsFlow = "ClientCredentialsFlow"  # Service Accounts
    DeviceFlow = "DeviceFlow"
    CibaFlow = "CibaFlow"


class PermissionTypeEnum(StrEnum):
    RESOURCE = "resource"
    SCOPE = "scope"


class DecisionStrategyEnum(StrEnum):
    AFFIRMATIVE = "AFFIRMATIVE"
    UNANIMOUS = "UNANIMOUS"
    CONSENSUS = "CONSENSUS"


class LogicEnum(StrEnum):
    POSITIVE = "POSITIVE"
    NEGATIVE = "NEGATIVE"


class UrnIetfOauthUmaTicketResponseModeEnum(StrEnum):
    DECISION = "decision"
    PERMISSIONS = "permissions"


class UrnIetfOauthUmaTicketPermissionResourceFormatEnum(StrEnum):
    ID = "id"
    URI = "uri"


class GrantTypeEnum(StrEnum):
    AUTHORIZATION_CODE = "authorization_code"
    REFRESH_TOKEN = "refresh_token"  # noqa: S105
    CLIENT_CREDENTIALS = "client_credentials"
    PASSWORD = "password"  # noqa: S105
    URN_IETF_OAUTH_TOKEN_EXCHANGE = "urn:ietf:params:oauth:grant-type:token-exchange"  # noqa: S105
    URN_IETF_OAUTH_UMA_TICKET = "urn:ietf:params:oauth:grant-type:uma-ticket"  # noqa: S105
    URN_IETF_OAUTH_CIBA = "urn:ietf:params:oauth:grant-type:ciba"  # noqa: S105
    URN_IETF_ACCESS_TOKEn = "urn:ietf:params:oauth:token-type:access_token"  # noqa: S105


class ClientAuthenticatorTypeEnum(StrEnum):
    """
    Client authentication types:
      - client-secret: Default shared secret
      - client-jwt: JWT assertion
      - client-x509: Mutual TLS with X.509
    """

    CLIENT_SECRET = "client-secret"  # noqa: S105
    CLIENT_JWT = "client-jwt"
    CLIENT_X509 = "client-x509"


class ProtocolEnum(StrEnum):
    OPENID_CONNECT = "openid-connect"
    SAML = "saml"
    DOCKER_V2 = "docker-v2"


class PolicyEnforcementModeEnum(StrEnum):
    ENFORCING = "ENFORCING"
    PERMISSIVE = "PERMISSIVE"
    DISABLED = "DISABLED"


class PolicyTypeEnum(StrEnum):
    ROLE = "role"
    GROUP = "group"
    USER = "user"
    JS = "js"
    TIME = "time"
    AGGREGATE = "aggregate"
    CLIENT = "client"
    IP = "ip"


class SystemPermissionsEnum(StrEnum):
    VIEW_USERS = "view-users"
    MANAGE_USERS = "manage-users"
    IMPERSONATION = "impersonation"
    MANAGE_IDENTITY_PROVIDERS = "manage-identity-providers"
    VIEW_IDENTITY_PROVIDERS = "view-identity-providers"
    MANAGE_REALM = "manage-realm"
    VIEW_REALM = "view-realm"
    MANAGE_CLIENTS = "manage-clients"
    VIEW_CLIENTS = "view-clients"
    MANAGE_EVENTS = "manage-events"
    VIEW_EVENTS = "view-events"
    MANAGE_AUTHORIZATION = "manage-authorization"
    VIEW_AUTHORIZATION = "view-authorization"
    MANAGE_CLUSTER = "manage-cluster"
    VIEW_CLUSTER = "view-cluster"
    MANAGE_USERS_ROLE_MAPPINGS = "manage-users-role-mappings"
    VIEW_USERS_ROLE_MAPPINGS = "view-users-role-mappings"
    MANAGE_ROLES = "manage-roles"
    VIEW_ROLES = "view-roles"
    QUERY_REALMS = "query-realms"
    MANAGE_PROTOCOL_MAPPERS = "manage-protocol-mappers"
    VIEW_PROTOCOL_MAPPERS = "view-protocol-mappers"


class ProtocolMappersEnum(StrEnum):
    PROPERTY_MAPPER = "oidc-usermodel-property-mapper"
    ATTRIBUTE_MAPPER = "oidc-usermodel-attribute-mapper"
    ROLE_MAPPER = "oidc-usermodel-realm-role-mapper"
    CLIENT_ROLE_MAPPING_MAPPER = "oidc-usermodel-client-role-mappings-mapper"
    CLIENT_ROLE_MAPPER = "oidc-usermodel-client-role-mapper"
    NOTE_MAPPER = "oidc-usersessionmodel-note-mapper"
    GROUP_MAPPER = "oidc-group-membership-mapper"
    FULL_GROUP_MAPPER = "oidc-full-group-path-mapper"
    AUDIENCE_MAPPER = "oidc-audience-mapper"
    SCRIPT_MAPPER = "oidc-script-based-protocol-mapper"
    HARDCODED_CLAIM_MAPPERS = "oidc-hardcoded-claim-mapper"
    SAML_MAPPER = "saml-role-list-mapper"
    SAML_USER_ATTRIBUTE_MAPPER = "saml-user-attribute-mapper"
