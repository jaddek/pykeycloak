# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Anton "Tony" Nazarov <tonynazarov+dev@gmail.com>

import os
from typing import Any, TypeGuard
from urllib.parse import urlparse

from pykeycloak.core.mapper import PyKeyCloakDataMapper
from pykeycloak.core.types import JsonData


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


def getenv_float(name: str, default: float) -> float:
    val = os.getenv(name)
    if val is None:
        return default
    try:
        return float(val)
    except ValueError:
        return default


def dataclass_from_dict[T](data: Any, cls: type[T]) -> T:
    if data is None:
        raise TypeError(f"Required data '{data}' is None")
    return PyKeyCloakDataMapper.get_handler(cls)(data)


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
