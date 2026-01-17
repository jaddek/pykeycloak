import json
from dataclasses import asdict, dataclass, field
from typing import Any
from uuid import UUID


from pykeycloak.core.enums import (
    GrantTypeEnum,
    UrnIetfOauthUmaTicketPermissionResourceFormatEnum,
    UrnIetfOauthUmaTicketResponseModeEnum,
)


@dataclass(frozen=True)
class Payload:
    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), default=str)


@dataclass(frozen=True)
class TokenIntrospectionPayload(Payload):
    token: str


@dataclass(frozen=True)
class RTPIntrospectionPayload(TokenIntrospectionPayload):
    token_type_hint: str = "requesting_party_token"  # noqa: S105


@dataclass(frozen=True)
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

    def to_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result |= {
            "grant_type": self.grant_type,
        }

        if scope := self.scope:
            result |= {"scope": scope}

        return result


@dataclass(frozen=True)
class UserCredentialsLoginPayload(ObtainTokenPayload):
    username: str
    password: str

    @property
    def grant_type(self) -> str:
        return GrantTypeEnum.PASSWORD


@dataclass(frozen=True)
class ClientCredentialsLoginPayload(ObtainTokenPayload):
    @property
    def grant_type(self) -> str:
        return GrantTypeEnum.CLIENT_CREDENTIALS


@dataclass(frozen=True)
class RefreshTokenPayload(ObtainTokenPayload):
    refresh_token: str

    @property
    def grant_type(self) -> str:
        return GrantTypeEnum.REFRESH_TOKEN

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


@dataclass(frozen=True)
class UMAAuthorizationPayload(Payload):
    audience: str
    permissions: dict[str, list[str]]
    response_mode: UrnIetfOauthUmaTicketResponseModeEnum = (
        UrnIetfOauthUmaTicketResponseModeEnum.DECISION
    )
    permission_resource_format: UrnIetfOauthUmaTicketPermissionResourceFormatEnum = (
        UrnIetfOauthUmaTicketPermissionResourceFormatEnum.URI
    )
    permission_resource_matching_uri: bool = False
    response_include_resource_name: bool = False
    _normalized_permissions: list[str] = field(init=False)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "_normalized_permissions",
            self.build_permission_param(self.permissions),
        )

    @property
    def grant_type(self) -> str:
        return GrantTypeEnum.URN_IETF_OAUTH_UMA_TICKET

    def to_dict(self) -> dict[str, Any]:
        return {
            "audience": self.audience,
            "grant_type": self.grant_type,
            "permission": self._normalized_permissions,
            "response_mode": self.response_mode,
            "response_include_resource_name": self.response_include_resource_name,
            "permission_resource_format": self.permission_resource_format,
            "permission_resource_matching_uri": self.permission_resource_matching_uri,
        }

    @staticmethod
    def build_permission_param(permissions: dict[str, list[str]]) -> list[str]:
        result = set()

        for resource, scopes in permissions.items():
            if not isinstance(resource, str):
                raise TypeError("Resource must be a string")

            if not scopes:
                result.add(resource)
                continue

            if not isinstance(scopes, list):
                raise TypeError("Scopes must be a list of strings")

            for scope in scopes:
                if not isinstance(scope, str) or not scope:
                    raise ValueError("Scope must be a non-empty string")

                result.add(f"{resource}#{scope}")

        return list(result)


@dataclass(frozen=True)
class CreateUserPayload(Payload):
    id: UUID | None = None
    username: str = ""
    first_name: str | None = None
    last_name: str | None = None
    email: str = ""
    enabled: bool | None = None
    credentials: list[dict[str, Any]] = field(default_factory=list)
    location_id: UUID | None = None
    role_ids: list[UUID] | None = field(default_factory=list)


@dataclass(frozen=True)
class UserUpdateEnablePayload(Payload):
    enabled: bool = True


@dataclass(frozen=True)
class UserUpdatePasswordPayload(Payload):
    credentials: list[dict[str, Any]] = field(default_factory=list)