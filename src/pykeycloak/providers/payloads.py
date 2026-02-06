# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Anton "Tony" Nazarov <tonynazarov+dev@gmail.com>

import json
from dataclasses import asdict, dataclass, field, fields
from typing import Any
from uuid import UUID

from pykeycloak.core.enums import (
    GrantTypeEnum,
    LogicEnum,
    UrnIetfOauthUmaTicketPermissionResourceFormatEnum,
    UrnIetfOauthUmaTicketResponseModeEnum,
)


@dataclass(frozen=True, kw_only=True)
class Payload:
    def to_dict(self, exclude_none: bool = True) -> dict[str, Any]:
        result = {}
        for field_info in fields(self):
            value = getattr(self, field_info.name)

            if exclude_none and value is None:
                continue

            alias = field_info.metadata.get("alias", field_info.name)
            result[alias] = value
        return result

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), default=str)


@dataclass(frozen=True, kw_only=True)
class TokenIntrospectionPayload(Payload):
    token: str


@dataclass(frozen=True, kw_only=True)
class RTPIntrospectionPayload(TokenIntrospectionPayload):
    token_type_hint: str = "requesting_party_token"  # noqa: S105


@dataclass(frozen=True, kw_only=True)
class ObtainTokenPayload(Payload):
    scopes: str | None = field(default=None, repr=False, init=False)

    @staticmethod
    def _get_default_scope() -> str:
        return "openid profile email"

    @property
    def grant_type(self) -> str | None:
        return None

    @property
    def scope(self) -> str | None:
        if self.scopes is None:
            return self._get_default_scope()

        return self.scopes

    def to_dict(self, exclude_none: bool = True) -> dict[str, Any]:
        result = asdict(self)
        result |= {
            "grant_type": self.grant_type,
        }

        del result["scopes"]

        if scope := self.scope:
            result |= {"scope": scope}

        return result


@dataclass(frozen=True, kw_only=True)
class UserCredentialsLoginPayload(ObtainTokenPayload):
    username: str
    password: str

    @property
    def grant_type(self) -> str:
        return GrantTypeEnum.PASSWORD


@dataclass(frozen=True, kw_only=True)
class ClientCredentialsLoginPayload(ObtainTokenPayload):
    @property
    def grant_type(self) -> str:
        return GrantTypeEnum.CLIENT_CREDENTIALS


@dataclass(frozen=True, kw_only=True)
class RefreshTokenPayload(ObtainTokenPayload):
    refresh_token: str

    @property
    def grant_type(self) -> str:
        return GrantTypeEnum.REFRESH_TOKEN


@dataclass(frozen=True, kw_only=True)
class ConfidentialClientRevokePayload(Payload):
    token: str
    token_type_hint: str = "refresh_token"  # noqa: S105


@dataclass(frozen=True, kw_only=True)
class PublicClientRevokePayload(Payload):
    client_id: str
    token: str
    token_type_hint: str = "refresh_token"  # noqa: S105


@dataclass(frozen=True, kw_only=True)
class RTPExchangeTokenPayload(ObtainTokenPayload):
    refresh_token: str

    @property
    def grant_type(self) -> str:
        return GrantTypeEnum.URN_IETF_OAUTH_TOKEN_EXCHANGE


#
# @dataclass(frozen=True)
# class FullPayload(ObtainTokenPayload):
#     username: str = ""
#     password: str = ""
#     grant_type: str = ""
#     code: str = ""
#     redirect_uri: str =""
#     totp: int | None = None
#     scope: str = "openid"


@dataclass(frozen=True, kw_only=True)
class UMAAuthorizationPayload(Payload):
    audience: str | None = field(default=None)  # if none the client id will be used
    permissions: list[str]
    response_mode: UrnIetfOauthUmaTicketResponseModeEnum = (
        UrnIetfOauthUmaTicketResponseModeEnum.DECISION
    )
    permission_resource_format: UrnIetfOauthUmaTicketPermissionResourceFormatEnum = (
        UrnIetfOauthUmaTicketPermissionResourceFormatEnum.URI
    )
    subject_token: str
    permission_resource_matching_uri: bool = False
    response_include_resource_name: bool = False

    @property
    def grant_type(self) -> str:
        return str(GrantTypeEnum.URN_IETF_OAUTH_UMA_TICKET)

    def to_dict(self, exclude_none: bool = True) -> dict[str, Any]:
        return {
            "subject_token": self.subject_token,
            "audience": self.audience,
            "grant_type": self.grant_type,
            "permission": self.permissions,
            "response_mode": str(self.response_mode),
            "response_include_resource_name": self.response_include_resource_name,
            "permission_resource_format": str(self.permission_resource_format),
            "permission_resource_matching_uri": self.permission_resource_matching_uri,
        }


@dataclass(frozen=True, kw_only=True)
class CreateUserPayload(Payload):
    id: UUID | None = field(default=None)
    username: str
    email: str = field(default="")
    emailVerified: bool = field(default=False)
    first_name: str = field(default="", metadata={"alias": "firstName"})
    last_name: str = field(default="", metadata={"alias": "lastName"})
    enabled: bool = field(default=True)
    credentials: list["CredentialsPayload"] = field(default_factory=list)
    requiredActions: list[str] = field(default_factory=list)

    def to_dict(self, exclude_none: bool = True) -> dict[str, Any]:
        data = super().to_dict()
        data["credentials"] = [
            credentials.to_dict()
            for credentials in self.credentials
            if isinstance(credentials, CredentialsPayload)
        ]

        return data


@dataclass(frozen=True, kw_only=True)
class UpdateUserPayload(Payload):
    id: UUID | None = field(default=None)
    email: str | None = field(default=None)
    emailVerified: bool | None = field(default=None)
    first_name: str | None = field(default=None, metadata={"alias": "firstName"})
    last_name: str | None = field(default=None, metadata={"alias": "lastName"})
    enabled: bool | None = field(default=None)
    credentials: list["CredentialsPayload"] | None = field(default=None)
    requiredActions: list[str] | None = field(default=None)


@dataclass(frozen=True, kw_only=True)
class CredentialsPayload(Payload):
    type: str
    value: str


@dataclass(frozen=True, kw_only=True)
class PasswordCredentialsPayload(CredentialsPayload):
    type: str = "password"
    value: str
    temporary: bool = False


@dataclass(frozen=True, kw_only=True)
class UserUpdateEnablePayload(Payload):
    enabled: bool = True


@dataclass(frozen=True, kw_only=True)
class UserUpdatePasswordPayload(Payload):
    credentials: list[dict[str, Any]] = field(default_factory=list)


@dataclass(frozen=True, kw_only=True)
class RolePayload(Payload):
    name: str
    id: str | None = None
    description: str | None = None
    scope_param_required: bool | None = None
    composite: bool | None = None
    container_id: str | None = None
    attributes: dict[str, list[str]] | None = None


@dataclass(frozen=True, kw_only=True)
class RoleAssignPayload(Payload):
    id: str
    name: str


@dataclass(frozen=True, kw_only=True)
class PermissionPayload(Payload):
    id: str | None = None
    name: str | None = None
    type: str | None = None
    logic: LogicEnum | None = None
    description: str | None = None
    decision_strategy: str | None = field(
        default=None, metadata={"alias": "decisionStrategy"}
    )


@dataclass(frozen=True, kw_only=True)
class PermissionScopesPayload(Payload):
    name: str
    policies: list[str] = field(default_factory=list)
    decision_strategy: str | None = field(
        default=None, metadata={"alias": "decisionStrategy"}
    )


@dataclass(frozen=True, kw_only=True)
class ResourcePayload(Payload):
    id: str | None = None
    name: str | None = None
    display_name: str | None = field(default=None, metadata={"alias": "displayName"})
    type: str | None = None
    uris: list[str] = field(default_factory=list)
    scopes: list[dict[str, str]] = field(default_factory=list)
    attributes: dict[str, list[str]] = field(default_factory=dict)

    def to_dict(self, exclude_none: bool = True) -> dict[str, Any]:
        result = super().to_dict(exclude_none=exclude_none)

        result["_id"] = result.pop("id")

        return result


@dataclass(frozen=True, kw_only=True)
class RolePolicyPayload(Payload):
    name: str
    roles: list[str] = field(default_factory=list)
