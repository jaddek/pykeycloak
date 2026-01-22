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
    count: str


@dataclass(frozen=True, kw_only=True)
class SessionsStatsRepresentation(Representation):
    id: str
    offline: int
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
