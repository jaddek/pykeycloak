import logging
from typing import Any

from .sanitizer import SensitiveDataSanitizer

keycloak_log_keys = ["content", "headers"]


class SanitizingFilter(logging.Filter):
    def __init__(self, sanitizer: SensitiveDataSanitizer):
        super().__init__()
        self.sanitizer = sanitizer

    def filter(self, record: Any) -> bool:
        extra_info = []

        for key in keycloak_log_keys:
            if hasattr(record, key):
                val = getattr(record, key)
                sanitized_val = self.sanitizer.sanitize(val)
                setattr(record, key, sanitized_val)
                extra_info.append(f"{key}: {getattr(record, key)}")

        if record.args:
            record.args = tuple(
                self.sanitizer.sanitize(arg) if isinstance(arg, (dict, str)) else arg
                for arg in record.args
            )

        if extra_info:
            extra_str = " | ".join(map(str, extra_info))

            try:
                message = record.getMessage()
            except (TypeError, ValueError):
                message = str(record.msg)

            record.msg = f"{message} | {extra_str}"
            record.args = ()

        return True
