# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Anton "Tony" Nazarov <tonynazarov+dev@gmail.com>

import sys
from collections.abc import Callable, Sequence
from dataclasses import MISSING, fields, is_dataclass
from types import UnionType
from typing import Any, Union, get_args, get_origin, get_type_hints


class PyKeyCloakDataMapper:
    _cache: dict[Any, Callable] = {}

    @classmethod
    def get_handler[T](cls, target_cls: type[T]) -> Callable[[Any], T]:
        if h := cls._cache.get(target_cls):
            return h

        origin = get_origin(target_cls)
        args = get_args(target_cls)

        if origin is Union or isinstance(target_cls, UnionType):
            handler = cls._create_union_handler(target_cls, args)
        elif origin in (list, Sequence) or target_cls is list:
            handler = cls._create_list_handler(args)
        elif is_dataclass(target_cls):
            handler = cls._create_dataclass_handler(target_cls)
        elif target_cls in (str, int, float, bool):
            handler = cls._create_primitive_handler(target_cls)
        else:

            def default_handler(data: Any) -> Any:
                return data

            handler = default_handler

        cls._cache[target_cls] = handler
        return handler

    @classmethod
    def _create_union_handler(cls, target_cls: type, args: tuple) -> Callable:
        none_type = type(None)
        allow_none = none_type in args
        non_none_handlers = [
            cls.get_handler(arg) for arg in args if arg is not none_type
        ]

        def union_handler(data: Any) -> Any:
            if data is None:
                if allow_none:
                    return None
                raise TypeError(f"Expected {target_cls}, got None")

            last_err = None
            for handler in non_none_handlers:
                try:
                    return handler(data)
                except (TypeError, ValueError, KeyError) as e:
                    last_err = e
                    continue

            raise TypeError(
                f"Value {data!r} matches no type in {target_cls}. Last error: {last_err}"
            )

        return union_handler

    @classmethod
    def _create_list_handler(cls, args: tuple) -> Callable:
        # Check if list has arguments (e.g. list[int])
        item_type = args[0] if args else Any
        item_h = cls.get_handler(item_type)

        def list_handler(data: Any) -> list:
            if type(data) is not list and type(data) is not tuple:
                raise TypeError(f"Expected list or tuple, got {type(data).__name__}")
            return [item_h(item) for item in data]

        return list_handler

    @classmethod
    def _create_dataclass_handler(cls, target_cls: type) -> Callable:
        module = sys.modules.get(target_cls.__module__)
        local_ns = getattr(module, "__dict__", {})
        hints = get_type_hints(target_cls, localns=local_ns)

        field_configs = []
        for f in fields(target_cls):
            f_type = hints.get(f.name, f.type)
            field_configs.append(
                (
                    f.name,
                    f.metadata.get("alias", f.name),
                    cls.get_handler(f_type),
                    f.default,
                    f.default_factory,
                )
            )

        def dataclass_handler(data: Any) -> Any:
            if type(data) is not dict:
                raise TypeError(
                    f"Expected dict for {target_cls.__name__}, got {type(data).__name__}"
                )

            kwargs = {}
            for name, key, h, def_v, fac in field_configs:
                if key in data:
                    try:
                        kwargs[name] = h(data[key])
                    except Exception as e:
                        raise TypeError(f"Field '{name}' (key '{key}'): {e}") from e
                elif fac is not MISSING:
                    kwargs[name] = fac()
                elif def_v is not MISSING:
                    kwargs[name] = def_v

            return target_cls(**kwargs)

        return dataclass_handler

    @classmethod
    def _create_primitive_handler(cls, target_cls: type) -> Callable:
        if target_cls is int:

            def int_handler(data: Any) -> int:
                if type(data) is int:
                    return data
                if type(data) is bool:
                    raise TypeError("Expected int, got bool")
                raise TypeError(f"Expected int, got {type(data).__name__}")

            return int_handler

        if target_cls is bool:

            def bool_handler(data: Any) -> bool:
                if type(data) is bool:
                    return data
                if data == "true":
                    return True
                if data == "false":
                    return False
                raise TypeError(f"Expected bool, got {type(data).__name__}")

            return bool_handler

        def generic_handler(data: Any) -> Any:
            if type(data) is target_cls:
                return data
            raise TypeError(
                f"Expected {target_cls.__name__}, got {type(data).__name__}"
            )

        return generic_handler


def dataclass_from_dict[T](data: Any, cls: type[T]) -> T | None:
    if data is None:
        return None
    return PyKeyCloakDataMapper.get_handler(cls)(data)
