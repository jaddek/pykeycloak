# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Anton "Tony" Nazarov <tonynazarov+dev@gmail.com>

from dataclasses import dataclass, field, fields
from typing import Any, Self

from pykeycloak.core.token_manager import AuthToken

type RepresentationModel[T] = AuthToken | Representation | list[Representation]


@dataclass(frozen=True, kw_only=True)
class Representation:
    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Self:
        init_kwargs = {}
        for f in fields(cls):
            source_key = f.metadata.get("alias", f.name)
            if source_key in data:
                val = data[source_key]
                if hasattr(f.type, "from_dict") and isinstance(val, dict):
                    init_kwargs[f.name] = f.type.from_dict(val)
                else:
                    init_kwargs[f.name] = val
        return cls(**init_kwargs)


@dataclass(frozen=True, kw_only=True)
class SessionsCountRepresentation(Representation):
    count: int


@dataclass(frozen=True, kw_only=True)
class SessionsStatsRepresentation(Representation):
    id: str
    offline: str
    client_id: str = field(metadata={"alias": "clientId"})
    active: str


@dataclass(frozen=True, kw_only=True)
class SessionRepresentation(Representation):
    id: str
    user_id: str = field(metadata={"alias": "userId"})
    username: str | None = None
    ip_address: str | None = None
    start: int | None = None
    last_access: int | None = None
    remember_me: bool | None = None
    clients: tuple[str, ...] = field(default_factory=tuple)
    transient_user: bool | None = None


@dataclass(frozen=True, kw_only=True)
class TokenRepresentation(Representation):
    access_token: str
    expires_in: int
    scope: str
    token_type: str
    not_before_policy: int = field(metadata={"alias": "not-before-policy"})
    session_state: str | None = None
    refresh_token: str | None = None
    refresh_token_expires_in: int | None = None

    def __repr__(self) -> str:
        return (
            f"{self.__class__.__name__}("
            f"scope={self.scope!r}, "
            f"expires={self.expires_in}s, "  # Добавили 's' для обозначения секунд
            f"has_refresh={self.refresh_token is not None}"  # Просто флаг наличия
            f")"
        )


@dataclass(frozen=True, kw_only=True)
class UserInfoRepresentation(Representation):
    id: str = field(metadata={"alias": "sub"})
    first_name: str | None = field(default=None, metadata={"alias": "given_name"})
    last_name: str | None = field(default=None, metadata={"alias": "family_name"})
    email: str | None = None
    username: str | None = field(default=None, metadata={"alias": "preferred_username"})
    email_verified: bool = field(default=False, metadata={"alias": "email_verified"})
    attributes: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, kw_only=True)
class UserRepresentation(Representation):
    id: str | None = field(default=None)
    first_name: str | None = field(default=None, metadata={"alias": "firstName"})
    last_name: str | None = field(default=None, metadata={"alias": "lastName"})
    email: str | None = field(default=None)
    username: str | None = field(default=None)
    email_verified: bool = field(default=False, metadata={"alias": "emailVerified"})
    attributes: dict[str, Any] = field(default_factory=dict, repr=False)
    enabled: bool = field(default=False)

    created_datetime: int | None = field(
        default=None, metadata={"alias": "createdDateTime"}, repr=False
    )
    user_profile_metadata: dict[str, Any] = field(
        default_factory=dict, metadata={"alias": "userProfileMetadata"}, repr=False
    )
    self: str | None = field(default=None, repr=False)
    origin: str | None = field(default=None, repr=False)
    created_timestamp: int | None = field(
        default=None, metadata={"alias": "createdTimestamp"}, repr=False
    )
    totp: bool | None = field(default=None, repr=False)
    federal_link: str | None = field(
        default=None, metadata={"alias": "federalLink"}, repr=False
    )
    service_account_client_id: str | None = field(
        default=None, metadata={"alias": "serviceAccountClientId"}, repr=False
    )
    disableable_credential_types: list[str] = field(
        default_factory=list,
        metadata={"alias": "disableableCredentialTypes"},
        repr=False,
    )
    required_actions: list[str] = field(
        default_factory=list, metadata={"alias": "requiredActions"}, repr=False
    )
    federated_identities: list[dict[str, Any]] = field(
        default_factory=list, metadata={"alias": "federatedIdentities"}, repr=False
    )
    realm_roles: list[str] = field(
        default_factory=list, metadata={"alias": "realmRoles"}, repr=False
    )
    client_roles: dict[str, list[str]] = field(
        default_factory=dict, metadata={"alias": "clientRoles"}, repr=False
    )
    client_consents: list[dict[str, Any]] = field(
        default_factory=list, metadata={"alias": "clientConsents"}, repr=False
    )
    not_before: int | None = field(
        default=None, metadata={"alias": "notBeforePolicy"}, repr=False
    )
    application_roles: dict[str, list[str]] = field(
        default_factory=dict, metadata={"alias": "applicationRoles"}, repr=False
    )
    social_links: list[dict[str, Any]] = field(
        default_factory=list, metadata={"alias": "socialLinks"}, repr=False
    )
    groups: list[str] = field(default_factory=list, repr=False)
    access: dict[str, Any] = field(default_factory=dict, repr=False)


@dataclass(frozen=True, kw_only=True)
class RealmAccessRepresentation(Representation):
    roles: tuple[str, ...] = field(default_factory=tuple)


@dataclass(frozen=True, kw_only=True)
class IntrospectRepresentation(Representation):
    allowed_origins: tuple[str, ...] = field(
        default_factory=tuple, metadata={"alias": "allowed-origins"}
    )
    aud: tuple[str, ...] | str | None = None
    exp: int | None = None
    iat: int | None = None
    jti: str | None = None
    iss: str | None = None
    sub: str | None = None
    typ: str | None = None
    azp: str | None = None
    sid: str | None = None
    acr: str | None = None
    realm_access: RealmAccessRepresentation | None = None
    scope: str | None = None
    email_verified: bool | None = field(
        default=None, metadata={"alias": "email_verified"}
    )
    name: str | None = None


@dataclass(frozen=True, kw_only=True)
class RoleRepresentation(Representation):
    id: str | None = None
    name: str | None = None
    description: str | None = None
    scope_param_required: bool | None = None
    composite: bool | None = None
    client_role: bool | None = None
    container_id: str | None = None
    attributes: dict[str, list[str]] | None = None


@dataclass(frozen=True, kw_only=True)
class PolicyRepresentation(Representation):
    id: str | None = None
    name: str | None = None
    type: str | None = None
    logic: str | None = None  # "POSITIVE" or "NEGATIVE"
    decision_strategy: str | None = None  # "AFFIRMATIVE", "UNANIMOUS", "CONSENSUS"
    resources: list[str] = field(default_factory=list)
    scopes: list[str] = field(default_factory=list)
    config: dict[str, object] = field(default_factory=dict)


@dataclass(frozen=True, kw_only=True)
class ResourceRepresentation(Representation):
    id: str | None = None
    name: str | None = None
    display_name: str | None = field(default=None, metadata={"alias": "displayName"})
    type: str | None = None
    owner_managed_access: bool = field(
        default=False, metadata={"alias": "ownerManagedAccess"}
    )
    uris: list[str] = field(default_factory=list)
    scopes: list[dict[str, str]] = field(default_factory=list)
    attributes: dict[str, list[str]] = field(default_factory=dict)
    icon_uri: str | None = None
    owner: dict | None = None
    uri: str | None = None
    scopes_uma: set["ScopeRepresentation"] = field(
        default_factory=set, metadata={"alias": "scopesUma"}
    )


@dataclass(frozen=True, kw_only=True)
class ScopeRepresentation(Representation):
    id: str | None = None
    name: str | None = None
    display_name: str | None = field(default=None, metadata={"alias": "display_name"})


@dataclass(frozen=True, kw_only=True)
class PermissionRepresentation(Representation):
    id: str | None = None
    name: str | None = None
    type: str | None = None  # "resource" or "scope"
    policies: list[Any] = field(default_factory=list)
    resources: list[Any] = field(default_factory=list)
    scopes: list[Any] = field(default_factory=list)
    decision_strategy: str | None = None


@dataclass(frozen=True, kw_only=True)
class AuthzSettingsRepresentation(Representation):
    allow_remote_resource_management: bool = field(
        default=False, metadata={"alias": "allowRemoteResourceManagement"}
    )
    policy_enforcement_mode: str | None = field(
        default=None, metadata={"alias": "policyEnforcementMode"}
    )  # "ENFORCING", "PERMISSIVE", "DISABLED"
    resources: list[ResourceRepresentation] = field(default_factory=list)
    policies: list[PolicyRepresentation] = field(default_factory=list)
    permissions: list[PermissionRepresentation] = field(default_factory=list)
    scopes: list[ScopeRepresentation] = field(default_factory=list)
    decision_strategy: str | None = field(
        default=None, metadata={"alias": "decisionStrategy"}
    )
    name: str | None = None
    id: str | None = None
    type: str | None = None
    description: str | None = None
    attributes: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True, kw_only=True)
class ProtocolMapperRepresentation(Representation):
    id: str | None = None
    name: str | None = None
    protocol: str | None = None
    protocol_mapper: str = field(metadata={"alias": "protocolMapper"})
    consent_required: bool | None = field(
        default=None, metadata={"alias": "consentRequired"}
    )
    config: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True, kw_only=True)
class ClientRepresentation(Representation):
    id: str | None = None
    client_id: str = field(metadata={"alias": "clientId"})
    name: str | None = None
    description: str | None = None
    root_url: str | None = field(default=None, metadata={"alias": "rootUrl"})
    admin_url: str | None = field(default=None, metadata={"alias": "adminUrl"})
    base_url: str | None = field(default=None, metadata={"alias": "baseUrl"})
    surrogate_auth_required: bool = field(
        default=False, metadata={"alias": "surrogateAuthRequired"}
    )
    enabled: bool = field(default=False)
    always_display_in_console: bool = field(
        default=False, metadata={"alias": "alwaysDisplayInConsole"}
    )
    client_authenticator_type: str | None = field(
        default=None, metadata={"alias": "clientAuthenticatorType"}
    )
    secret: str | None = None
    redirect_uris: list[str] = field(
        default_factory=list, metadata={"alias": "redirectUris"}
    )
    web_origins: list[str] = field(
        default_factory=list, metadata={"alias": "webOrigins"}
    )
    not_before: int = field(default=0, metadata={"alias": "notBefore"})
    bearer_only: bool = field(default=False, metadata={"alias": "bearerOnly"})
    consent_required: bool = field(default=False, metadata={"alias": "consentRequired"})
    standard_flow_enabled: bool = field(
        default=False, metadata={"alias": "standardFlowEnabled"}
    )
    implicit_flow_enabled: bool = field(
        default=False, metadata={"alias": "implicitFlowEnabled"}
    )
    direct_access_grants_enabled: bool = field(
        default=False, metadata={"alias": "directAccessGrantsEnabled"}
    )
    service_accounts_enabled: bool = field(
        default=False, metadata={"alias": "serviceAccountsEnabled"}
    )
    authorization_services_enabled: bool = field(
        default=False, metadata={"alias": "authorizationServicesEnabled"}
    )
    public_client: bool = field(default=False, metadata={"alias": "publicClient"})
    frontchannel_logout: bool = field(
        default=False, metadata={"alias": "frontchannelLogout"}
    )
    protocol: str | None = None
    attributes: dict[str, str] = field(default_factory=dict)
    authentication_flow_binding_overrides: dict[str, str] = field(
        default_factory=dict, metadata={"alias": "authenticationFlowBindingOverrides"}
    )
    full_scope_allowed: bool = field(
        default=False, metadata={"alias": "fullScopeAllowed"}
    )
    node_re_registration_timeout: int = field(
        default=-1, metadata={"alias": "nodeReRegistrationTimeout"}
    )
    protocol_mappers: list[ProtocolMapperRepresentation] = field(
        default_factory=list, metadata={"alias": "protocolMappers"}
    )
    default_client_scopes: list[str] = field(
        default_factory=list, metadata={"alias": "defaultClientScopes"}
    )
    optional_client_scopes: list[str] = field(
        default_factory=list, metadata={"alias": "optionalClientScopes"}
    )
    access: dict[str, bool] = field(default_factory=dict)


@dataclass(frozen=True, kw_only=True)
class DeviceAuthRepresentation(Representation):
    device_code: str
    user_code: str
    verification_uri: str
    expires_in: int
    interval: int
