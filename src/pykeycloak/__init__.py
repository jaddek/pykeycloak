# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Anton "Tony" Nazarov <tonynazarov+dev@gmail.com>
import logging

from .core.logger import SanitizingFilter
from .core.sanitizer import SensitiveDataSanitizer

logger = logging.getLogger(__package__)
logger.setLevel(logging.NOTSET)
logger.propagate = False

_sanitizer = SensitiveDataSanitizer.from_env()
_handler = logging.NullHandler()
_handler.addFilter(SanitizingFilter(_sanitizer))

logger.addHandler(_handler)
