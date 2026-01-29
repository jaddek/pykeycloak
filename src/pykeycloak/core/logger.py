import logging
from typing import Any

from .sanitizer import SensitiveDataSanitizer


class SanitizingFilter(logging.Filter):
    keycloak_log_keys = ["content", "headers"]

    def __init__(self, sanitizer: SensitiveDataSanitizer):
        super().__init__()
        self.sanitizer = sanitizer

    def filter(self, record: Any) -> bool:
        extra_info = []

        for key in self.keycloak_log_keys:
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
            try:
                formatted_msg = record.msg % record.args
                record.msg = f"{formatted_msg} | {' | '.join(extra_info)}"
                record.args = ()
            except Exception:
                record.msg = f"{record.msg} | {' | '.join(extra_info)}"

        return True
