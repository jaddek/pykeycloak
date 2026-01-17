import os
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from functools import lru_cache
from typing import Any

JSONType = dict[str, Any] | list[Any] | str | int | float | bool | None


@dataclass(frozen=True)
class SensitiveDataSanitizer:
    sensitive_keys: frozenset[str] = field(
        default_factory=lambda: frozenset(
            {
                # "client_secret",
                # "refresh_token",
                # "access_token",
                # "id_token",
                # "password",
                # "authorization",
            }
        )
    )
    _sensitive_keys_lower: frozenset[str] = field(init=False, repr=False)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "_sensitive_keys_lower",
            frozenset(k.lower() for k in self.sensitive_keys),
        )

    def sanitize(self, data: JSONType) -> JSONType:
        return self._sanitize_recursive(data)

    def _sanitize_recursive(self, obj: JSONType) -> JSONType:
        if isinstance(obj, Mapping):
            changed = False
            sanitized: dict[str, Any] = {}

            for k, v in obj.items():
                lower_k = k.lower()
                if lower_k in self._sensitive_keys_lower:
                    sanitized[k] = "<hidden>"
                    changed = True
                else:
                    sanitized_v = self._sanitize_recursive(v)
                    sanitized[k] = sanitized_v
                    if sanitized_v is not v:
                        changed = True

            return sanitized if changed else obj

        if isinstance(obj, Sequence) and not isinstance(obj, str):
            changed = False
            sanitized_list = []

            for item in obj:
                sanitized_item = self._sanitize_recursive(item)
                sanitized_list.append(sanitized_item)
                if sanitized_item is not item:
                    changed = True

            return sanitized_list if changed else obj

        return obj

    @classmethod
    def from_env(cls) -> "SensitiveDataSanitizer":
        extra_keys = os.getenv("EXTRA_SENSITIVE_KEYS", None)
        combined_keys = cls().sensitive_keys

        if extra_keys is not None:
            extra_keys_set = frozenset(
                k.strip() for k in extra_keys.split(",") if k.strip()
            )
            combined_keys |= extra_keys_set

        return cls(sensitive_keys=combined_keys)


@lru_cache(maxsize=1)
def get_sanitizer() -> SensitiveDataSanitizer:
    return SensitiveDataSanitizer.from_env()
