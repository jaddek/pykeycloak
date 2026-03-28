# SPDX-License-Identifier: MIT
import pytest

from pykeycloak.core.sanitizer import SensitiveDataSanitizer


@pytest.fixture
def sanitizer():
    return SensitiveDataSanitizer()


class TestSanitizeDict:
    def test_hides_sensitive_key(self, sanitizer):
        result = sanitizer.sanitize({"access_token": "abc123"})
        assert result["access_token"] == "<hidden>"

    def test_leaves_non_sensitive_key_unchanged(self, sanitizer):
        data = {"username": "tony"}
        result = sanitizer.sanitize(data)
        assert result["username"] == "tony"

    def test_hides_all_default_sensitive_keys(self, sanitizer):
        data = {
            "client_secret": "s",
            "refresh_token": "r",
            "access_token": "a",
            "id_token": "i",
            "password": "p",
            "authorization": "auth",
            "api_key": "k",
        }
        result = sanitizer.sanitize(data)
        for key in data:
            assert result[key] == "<hidden>"

    def test_case_insensitive_key_matching(self, sanitizer):
        result = sanitizer.sanitize({"Access_Token": "secret"})
        assert result["Access_Token"] == "<hidden>"

    def test_nested_dict(self, sanitizer):
        data = {"user": {"password": "qwerty", "name": "tony"}}
        result = sanitizer.sanitize(data)
        assert result["user"]["password"] == "<hidden>"
        assert result["user"]["name"] == "tony"

    def test_list_of_dicts(self, sanitizer):
        data = [{"access_token": "t1"}, {"username": "u"}]
        result = sanitizer.sanitize(data)
        assert result[0]["access_token"] == "<hidden>"
        assert result[1]["username"] == "u"

    def test_returns_same_object_when_no_sensitive_data(self, sanitizer):
        data = {"name": "tony", "role": "admin"}
        result = sanitizer.sanitize(data)
        assert result is data


class TestSanitizeString:
    def test_hides_jwt_token(self, sanitizer):
        jwt = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxMjM0In0.signature"
        assert sanitizer.sanitize(jwt) == "<jwt_token_hidden>"

    def test_masks_key_value_in_string(self, sanitizer):
        text = "password=mysecret&user=tony"
        result = sanitizer.sanitize(text)
        assert "mysecret" not in result
        assert "<hidden>" in result
        assert "tony" in result

    def test_json_string_is_parsed_and_sanitized(self, sanitizer):
        import json
        data = json.dumps({"access_token": "tok123", "name": "tony"})
        result = sanitizer.sanitize(data)
        assert isinstance(result, dict)
        assert result["access_token"] == "<hidden>"
        assert result["name"] == "tony"

    def test_plain_string_without_sensitive_data_unchanged(self, sanitizer):
        text = "hello world"
        assert sanitizer.sanitize(text) == "hello world"


class TestCustomSensitiveKeys:
    def test_custom_keys_override_defaults(self):
        sanitizer = SensitiveDataSanitizer(sensitive_keys=frozenset({"my_secret"}))
        result = sanitizer.sanitize({"my_secret": "val", "password": "pw"})
        assert result["my_secret"] == "<hidden>"
        assert result["password"] == "pw"

    def test_from_env_adds_extra_keys(self, monkeypatch):
        monkeypatch.setenv("DATA_SANITIZER_EXTRA_SENSITIVE_KEYS", "token_x, custom_key")
        sanitizer = SensitiveDataSanitizer.from_env()
        result = sanitizer.sanitize({"token_x": "v", "custom_key": "v2", "access_token": "a"})
        assert result["token_x"] == "<hidden>"
        assert result["custom_key"] == "<hidden>"
        assert result["access_token"] == "<hidden>"

    def test_from_env_without_extra_keys(self, monkeypatch):
        monkeypatch.delenv("DATA_SANITIZER_EXTRA_SENSITIVE_KEYS", raising=False)
        sanitizer = SensitiveDataSanitizer.from_env()
        assert sanitizer.sensitive_keys == SensitiveDataSanitizer.DEFAULT_SENSITIVE_KEYS
