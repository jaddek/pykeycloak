from dataclasses import dataclass
import os
from typing import Any
from urllib.parse import urlparse


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


def dataclass_from_dict(data: dict[str, Any], cls: type[dataclass]) -> type[dataclass]:
    init_kwargs = {}
    for f in cls.__dataclass_fields__.values():
        key = f.metadata.get("alias", f.name)
        if key in data:
            init_kwargs[f.name] = data[key]
    return cls(**init_kwargs)
