# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Anton "Tony" Nazarov <tonynazarov+dev@gmail.com>
import logging

from pykeycloak.core.logger import SanitizingFilter
from pykeycloak.core.sanitizer import SensitiveDataSanitizer

logger = logging.getLogger(__package__)
logger.addHandler(logging.NullHandler())
logger.propagate = True
sanitizer = SensitiveDataSanitizer.from_env()
logger.addFilter(SanitizingFilter(sanitizer))
