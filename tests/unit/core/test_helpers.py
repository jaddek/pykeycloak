# SPDX-License-Identifier: MIT
import pytest

from pykeycloak.core.helpers import (
    RoleHelper,
    dataclass_from_dict,
    getenv_bool,
    getenv_float,
    getenv_int,
    getenv_optional,
    getenv_required,
    getenv_required_url,
    is_json_data,
)


class TestGetenvRequired:
    def test_returns_value_when_set(self, monkeypatch):
        monkeypatch.setenv("MY_VAR", "hello")
        assert getenv_required("MY_VAR") == "hello"

    def test_raises_when_not_set(self, monkeypatch):
        monkeypatch.delenv("MY_VAR", raising=False)
        with pytest.raises(RuntimeError, match="MY_VAR"):
            getenv_required("MY_VAR")

    def test_raises_when_empty_string(self, monkeypatch):
        monkeypatch.setenv("MY_VAR", "")
        with pytest.raises(RuntimeError, match="MY_VAR"):
            getenv_required("MY_VAR")


class TestGetenvRequiredUrl:
    def test_returns_valid_url(self, monkeypatch):
        monkeypatch.setenv("MY_URL", "https://example.com")
        assert getenv_required_url("MY_URL") == "https://example.com"

    def test_raises_when_not_set(self, monkeypatch):
        monkeypatch.delenv("MY_URL", raising=False)
        with pytest.raises(RuntimeError):
            getenv_required_url("MY_URL")

    def test_raises_when_no_scheme(self, monkeypatch):
        monkeypatch.setenv("MY_URL", "example.com")
        with pytest.raises(RuntimeError, match="valid URL"):
            getenv_required_url("MY_URL")

    def test_raises_when_no_netloc(self, monkeypatch):
        monkeypatch.setenv("MY_URL", "https://")
        with pytest.raises(RuntimeError, match="valid URL"):
            getenv_required_url("MY_URL")


class TestGetenvOptional:
    def test_returns_value_when_set(self, monkeypatch):
        monkeypatch.setenv("OPT_VAR", "value")
        assert getenv_optional("OPT_VAR") == "value"

    def test_returns_none_when_not_set(self, monkeypatch):
        monkeypatch.delenv("OPT_VAR", raising=False)
        assert getenv_optional("OPT_VAR") is None

    def test_returns_none_when_empty(self, monkeypatch):
        monkeypatch.setenv("OPT_VAR", "")
        assert getenv_optional("OPT_VAR") is None


class TestGetenvBool:
    @pytest.mark.parametrize("val", ["1", "true", "True", "TRUE", "yes", "YES", "on", "ON"])
    def test_truthy_values(self, monkeypatch, val):
        monkeypatch.setenv("BOOL_VAR", val)
        assert getenv_bool("BOOL_VAR", False) is True

    @pytest.mark.parametrize("val", ["0", "false", "False", "no", "off", "random"])
    def test_falsy_values(self, monkeypatch, val):
        monkeypatch.setenv("BOOL_VAR", val)
        assert getenv_bool("BOOL_VAR", True) is False

    def test_returns_default_when_not_set(self, monkeypatch):
        monkeypatch.delenv("BOOL_VAR", raising=False)
        assert getenv_bool("BOOL_VAR", True) is True
        assert getenv_bool("BOOL_VAR", False) is False


class TestGetenvInt:
    def test_returns_int_value(self, monkeypatch):
        monkeypatch.setenv("INT_VAR", "42")
        assert getenv_int("INT_VAR", 0) == 42

    def test_returns_default_when_not_set(self, monkeypatch):
        monkeypatch.delenv("INT_VAR", raising=False)
        assert getenv_int("INT_VAR", 99) == 99

    def test_returns_default_on_invalid_value(self, monkeypatch):
        monkeypatch.setenv("INT_VAR", "not_a_number")
        assert getenv_int("INT_VAR", 5) == 5


class TestGetenvFloat:
    def test_returns_float_value(self, monkeypatch):
        monkeypatch.setenv("FLOAT_VAR", "3.14")
        assert getenv_float("FLOAT_VAR", 0.0) == pytest.approx(3.14)

    def test_returns_default_when_not_set(self, monkeypatch):
        monkeypatch.delenv("FLOAT_VAR", raising=False)
        assert getenv_float("FLOAT_VAR", 1.5) == pytest.approx(1.5)

    def test_returns_default_on_invalid_value(self, monkeypatch):
        monkeypatch.setenv("FLOAT_VAR", "abc")
        assert getenv_float("FLOAT_VAR", 2.0) == pytest.approx(2.0)


class TestIsJsonData:
    @pytest.mark.parametrize("val", [{"key": "value"}, [1, 2], "string", 42, 3.14, True, None])
    def test_returns_true_for_valid_types(self, val):
        assert is_json_data(val) is True

    @pytest.mark.parametrize("val", [object(), b"bytes", (1, 2)])
    def test_returns_false_for_invalid_types(self, val):
        assert is_json_data(val) is False


class TestDataclassFromDict:
    def test_raises_on_none(self):
        from dataclasses import dataclass

        @dataclass
        class Dummy:
            x: int

        with pytest.raises(TypeError):
            dataclass_from_dict(None, Dummy)


class TestRoleHelper:
    def test_add_prefix(self):
        assert RoleHelper.add_prefix("admin") == "public_role__admin"

    def test_hide_prefix(self):
        assert RoleHelper.hide_prefix("public_role__admin") == "admin"

    def test_hide_prefix_no_prefix(self):
        assert RoleHelper.hide_prefix("admin") == "admin"

    def test_get_public_prefix(self):
        assert RoleHelper.get_public_refix() == "public_role__"

    def test_add_then_hide_is_identity(self):
        name = "some_role"
        assert RoleHelper.hide_prefix(RoleHelper.add_prefix(name)) == name
