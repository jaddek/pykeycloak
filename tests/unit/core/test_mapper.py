# SPDX-License-Identifier: MIT
from dataclasses import dataclass, field

import pytest

from pykeycloak.core.mapper import PyKeycloakDataMapper, dataclass_from_dict


@pytest.fixture(autouse=True)
def clear_mapper_cache():
    PyKeycloakDataMapper._cache.clear()
    yield
    PyKeycloakDataMapper._cache.clear()


class TestPrimitiveHandlers:
    def test_str_handler(self):
        h = PyKeycloakDataMapper.get_handler(str)
        assert h("hello") == "hello"

    def test_str_handler_rejects_int(self):
        h = PyKeycloakDataMapper.get_handler(str)
        with pytest.raises(TypeError):
            h(42)

    def test_int_handler(self):
        h = PyKeycloakDataMapper.get_handler(int)
        assert h(42) == 42

    def test_int_handler_rejects_bool(self):
        h = PyKeycloakDataMapper.get_handler(int)
        with pytest.raises(TypeError):
            h(True)

    def test_int_handler_rejects_str(self):
        h = PyKeycloakDataMapper.get_handler(int)
        with pytest.raises(TypeError):
            h("42")

    def test_float_handler(self):
        h = PyKeycloakDataMapper.get_handler(float)
        assert h(3.14) == pytest.approx(3.14)

    def test_bool_handler_true(self):
        h = PyKeycloakDataMapper.get_handler(bool)
        assert h(True) is True

    def test_bool_handler_false(self):
        h = PyKeycloakDataMapper.get_handler(bool)
        assert h(False) is False

    def test_bool_handler_string_true(self):
        h = PyKeycloakDataMapper.get_handler(bool)
        assert h("true") is True

    def test_bool_handler_string_false(self):
        h = PyKeycloakDataMapper.get_handler(bool)
        assert h("false") is False

    def test_bool_handler_rejects_int(self):
        h = PyKeycloakDataMapper.get_handler(bool)
        with pytest.raises(TypeError):
            h(1)


class TestListHandler:
    def test_list_of_str(self):
        h = PyKeycloakDataMapper.get_handler(list[str])
        assert h(["a", "b"]) == ["a", "b"]

    def test_list_of_int(self):
        h = PyKeycloakDataMapper.get_handler(list[int])
        assert h([1, 2, 3]) == [1, 2, 3]

    def test_list_rejects_non_list(self):
        h = PyKeycloakDataMapper.get_handler(list[str])
        with pytest.raises(TypeError):
            h("not a list")

    def test_list_accepts_tuple(self):
        h = PyKeycloakDataMapper.get_handler(list[int])
        assert h((1, 2)) == [1, 2]


class TestUnionHandler:
    def test_optional_str_with_value(self):
        h = PyKeycloakDataMapper.get_handler(str | None)
        assert h("hello") == "hello"

    def test_optional_str_with_none(self):
        h = PyKeycloakDataMapper.get_handler(str | None)
        assert h(None) is None

    def test_optional_int_with_value(self):
        h = PyKeycloakDataMapper.get_handler(int | None)
        assert h(5) == 5

    def test_union_raises_on_no_match(self):
        h = PyKeycloakDataMapper.get_handler(str | None)
        with pytest.raises(TypeError):
            h(42)


class TestDataclassHandler:
    def test_simple_dataclass(self):
        @dataclass
        class Point:
            x: int
            y: int

        h = PyKeycloakDataMapper.get_handler(Point)
        result = h({"x": 1, "y": 2})
        assert result.x == 1
        assert result.y == 2

    def test_dataclass_with_optional_field(self):
        @dataclass
        class Item:
            name: str
            value: int | None = None

        h = PyKeycloakDataMapper.get_handler(Item)
        result = h({"name": "foo"})
        assert result.name == "foo"
        assert result.value is None

    def test_dataclass_with_alias(self):
        @dataclass
        class Token:
            not_before_policy: int | None = field(
                metadata={"alias": "not-before-policy"}, default=None
            )

        h = PyKeycloakDataMapper.get_handler(Token)
        result = h({"not-before-policy": 42})
        assert result.not_before_policy == 42

    def test_nested_dataclass(self):
        @dataclass
        class Inner:
            value: int

        @dataclass
        class Outer:
            inner: Inner

        h = PyKeycloakDataMapper.get_handler(Outer)
        result = h({"inner": {"value": 99}})
        assert result.inner.value == 99

    def test_dataclass_handler_rejects_non_dict(self):
        @dataclass
        class Simple:
            x: int

        h = PyKeycloakDataMapper.get_handler(Simple)
        with pytest.raises(TypeError):
            h([1, 2])

    def test_dataclass_with_default_factory(self):
        @dataclass
        class WithList:
            items: list[str] = field(default_factory=list)

        h = PyKeycloakDataMapper.get_handler(WithList)
        result = h({})
        assert result.items == []


class TestDataclassFromDictFunction:
    def test_returns_none_on_none_input(self):
        @dataclass
        class Dummy:
            x: int

        result = dataclass_from_dict(None, Dummy)
        assert result is None

    def test_converts_dict_to_dataclass(self):
        @dataclass
        class Dummy:
            x: int

        result = dataclass_from_dict({"x": 5}, Dummy)
        assert result is not None
        assert result.x == 5


class TestCaching:
    def test_same_handler_returned_on_second_call(self):
        h1 = PyKeycloakDataMapper.get_handler(str)
        h2 = PyKeycloakDataMapper.get_handler(str)
        assert h1 is h2
