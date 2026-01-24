# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Anton "Tony" Nazarov <tonynazarov+dev@gmail.com>

import os
from collections.abc import Callable
from dataclasses import fields, is_dataclass
from typing import Any, TypeGuard, cast, get_args, get_origin
from urllib.parse import urlparse

from pykeycloak.core.aliases import JsonData


def getenv_required_url(name: str) -> str:
    value = getenv_required(name)
    parsed = urlparse(value)
    if not parsed.scheme or not parsed.netloc:
        raise RuntimeError(f"Environment variable '{name}' must be a valid URL")
    return value


def getenv_required(name: str) -> str:
    value = os.getenv(name)
    if not value:
        raise RuntimeError(f"Required environment variable '{name}' is not set")
    return value


def getenv_optional(name: str) -> str | None:
    value = os.getenv(name)
    return value if value not in ("", None) else None


def getenv_bool(name: str, default: bool) -> bool:
    val = os.getenv(name)
    if val is None:
        return default
    return val.lower() in ("1", "true", "yes", "on")


def getenv_int(name: str, default: int) -> int:
    val = os.getenv(name)
    if val is None:
        return default
    try:
        return int(val)
    except ValueError:
        return default


def dataclass_from_dict[T](data: Any, cls: type[T]) -> T:
    origin = get_origin(cls)

    if origin is list:
        args = get_args(cls)
        inner_cls = args[0] if args else Any
        if not isinstance(data, list):
            raise TypeError(f"Expected list, got {type(data)}")
        return [dataclass_from_dict(item, inner_cls) for item in data]  # type: ignore

    if not is_dataclass(cls):
        raise TypeError(f"{cls} must be a dataclass")

    if not isinstance(data, dict):
        raise TypeError(f"Expected dict for dataclass conversion, got {type(data)}")

    init_kwargs: dict[str, Any] = {}
    for field in fields(cls):
        key = field.metadata.get("alias", field.name)
        if key in data:
            init_kwargs[field.name] = data[key]

    return cast(Callable[..., T], cls)(**init_kwargs)


def is_json_data(val: Any) -> TypeGuard[JsonData]:
    return isinstance(val, (dict, list, str, int, float, bool)) or val is None


class RoleHelper:
    PUBLIC_ROLE_PREFIX: str = "public_role__"

    @staticmethod
    def hide_prefix(role_name: str) -> str:
        return role_name.replace(RoleHelper.PUBLIC_ROLE_PREFIX, "")

    @staticmethod
    def add_prefix(role_name: str) -> str:
        return f"{RoleHelper.PUBLIC_ROLE_PREFIX}{role_name}"

    @staticmethod
    def get_public_refix() -> str:
        return RoleHelper.PUBLIC_ROLE_PREFIX
