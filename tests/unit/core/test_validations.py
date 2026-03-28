# SPDX-License-Identifier: MIT
import pytest

from pykeycloak.core.validations.uuid import is_uuid


class TestIsUuid:
    @pytest.mark.parametrize(
        "value",
        [
            "550e8400-e29b-41d4-a716-446655440000",
            "00000000-0000-0000-0000-000000000000",
            "ffffffff-ffff-ffff-ffff-ffffffffffff",
            "550E8400-E29B-41D4-A716-446655440000",
        ],
    )
    def test_valid_uuid(self, value):
        assert is_uuid(value) is True

    @pytest.mark.parametrize(
        "value",
        [
            "not-a-uuid",
            "550e8400-e29b-41d4-a716-44665544000z",
            "",
            "550e8400-e29b-41d4-a716",
            "gggggggg-gggg-gggg-gggg-gggggggggggg",
            "123",
        ],
    )
    def test_invalid_uuid(self, value):
        assert is_uuid(value) is False
