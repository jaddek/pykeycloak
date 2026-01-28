import logging
from typing import Any

from .sanitizer import SensitiveDataSanitizer


class SanitizingFilter(logging.Filter):
    def __init__(self, sanitizer: SensitiveDataSanitizer):
        super().__init__()
        self.sanitizer = sanitizer

    def filter(self, record: Any) -> bool:
        if record.args:
            record.args = tuple(
                self.sanitizer.sanitize(arg) if isinstance(arg, dict) else arg
                for arg in record.args
            )

        return True
