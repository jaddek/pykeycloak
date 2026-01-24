# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Anton "Tony" Nazarov <tonynazarov+dev@gmail.com>

import json
import os
import re
from collections.abc import Mapping, Sequence
from functools import lru_cache
from typing import Any

from pykeycloak.core.helpers import getenv_bool

JSONType = dict[str, Any] | list[Any] | str | int | float | bool | None


class SensitiveDataSanitizer:
    DEFAULT_SENSITIVE_KEYS = frozenset(
        {
            "client_secret",
            "refresh_token",
            "access_token",
            "id_token",
            "password",
            "authorization",
            "api_key",
        }
    )

    def __init__(self, sensitive_keys: frozenset[str] | None = None):
        self.sensitive_keys = (
            sensitive_keys
            if sensitive_keys is not None
            else self.DEFAULT_SENSITIVE_KEYS
        )
        self._sensitive_keys_lower = frozenset(k.lower() for k in self.sensitive_keys)

        keys_pattern = "|".join(re.escape(k) for k in self.sensitive_keys)
        self._mask_re = re.compile(
            rf"({keys_pattern})([\s:=]+)([^\s&,\"\']+)", re.IGNORECASE
        )

    def sanitize(self, data: Any) -> Any:
        if isinstance(data, str):
            try:
                parsed = json.loads(data)
                if isinstance(parsed, (dict, list)):
                    return self._sanitize_recursive(parsed)
            except (json.JSONDecodeError, TypeError):
                pass

            return self._sanitize_string(data)

        return self._sanitize_recursive(data)

    def _sanitize_string(self, text: str) -> str:
        if text.startswith("eyJ") and text.count(".") == 2:
            return "<jwt_token_hidden>"

        return self._mask_re.sub(r"\1\2<hidden>", text)

    def _sanitize_recursive(self, obj: Any) -> Any:
        if isinstance(obj, Mapping):
            changed = False
            sanitized: dict[str, Any] = {}

            for k, v in obj.items():
                is_sensitive = (
                    isinstance(k, str) and k.lower() in self._sensitive_keys_lower
                )

                if is_sensitive:
                    sanitized[k] = "<hidden>"
                    changed = True
                else:
                    sanitized_v = self._sanitize_recursive(v)
                    sanitized[k] = sanitized_v
                    if sanitized_v is not v:
                        changed = True

            return sanitized if changed else obj

        if isinstance(obj, Sequence) and not isinstance(obj, (str, bytes)):
            changed = False
            sanitized_list = []

            for item in obj:
                sanitized_item = self._sanitize_recursive(item)
                sanitized_list.append(sanitized_item)
                if sanitized_item is not item:
                    changed = True

            return sanitized_list if changed else obj

        if isinstance(obj, str):
            return self._sanitize_string(obj)

        return obj

    @classmethod
    def from_env(cls) -> "SensitiveDataSanitizer":
        extra_keys_str = os.getenv("DATA_SANITIZER_EXTRA_SENSITIVE_KEYS", "")
        debug = getenv_bool("DATA_SANITIZER_DEBUG", default=False)

        if debug:
            return cls(sensitive_keys=frozenset())

        combined_keys = set(cls.DEFAULT_SENSITIVE_KEYS)
        if extra_keys_str:
            extra_keys = {k.strip() for k in extra_keys_str.split(",") if k.strip()}
            combined_keys.update(extra_keys)

        return cls(sensitive_keys=frozenset(combined_keys))


@lru_cache(maxsize=1)
def get_sanitizer() -> SensitiveDataSanitizer:
    return SensitiveDataSanitizer.from_env()
