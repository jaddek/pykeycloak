# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Anton "Tony" Nazarov <tonynazarov+dev@gmail.com>

from dataclasses import dataclass, field
from typing import Any, TypeVar


@dataclass(frozen=True)
class Representation: ...


R = TypeVar("R", bound=Representation)


@dataclass(frozen=True)
class TokenRepresentation(Representation):
    access_token: str
    expires_in: int
    scope: str
    token_type: str
    not_before_policy: int = field(metadata={"alias": "not-before-policy"})
    session_state: str | None = None
    refresh_token: str | None = None
    refresh_token_expires_in: int | None = None


@dataclass
class UserInfoRepresentation:
    id: str = field(metadata={"alias": "sub"})
    first_name: str = field(metadata={"alias": "firstName"})
    last_name: str = field(metadata={"alias": "lastName"})
    email: str
    username: str
    email_verified: bool | None = field(
        default=False, metadata={"alias": "emailVerified"}
    )
    attributes: dict[str, Any] | None = field(default=None)


@dataclass(frozen=True)
class RealmAccessRepresentation(Representation):
    roles: tuple[str, ...] = ()


@dataclass(frozen=True)
class IntrospectRepresentation(Representation):
    allowed_origins: tuple[str, ...] = field(
        default_factory=tuple,
        metadata={"alias": "allowed-origins"},
    )

    aud: tuple[str, ...] = ()
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
    email_verified: bool | None = None
    name: str | None = None
    preferred_username: str | None = None
    given_name: str | None = None
    family_name: str | None = None
    client_id: str | None = None
    username: str | None = None
    token_type: str | None = None
    active: bool | None = None

    @property
    def realm_roles(self) -> list[str] | None:
        return list(self.realm_access.roles) if self.realm_access is not None else None
