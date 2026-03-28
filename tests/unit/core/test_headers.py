# SPDX-License-Identifier: MIT
import pytest

from pykeycloak.core.headers import HeadersFactory


@pytest.fixture
def factory():
    return HeadersFactory()


class TestHeadersFactory:
    def test_openid_basic_authorization_header(self, factory):
        headers = factory.openid_basic("dXNlcjpwYXNz")
        assert headers["Authorization"] == "Basic dXNlcjpwYXNz"

    def test_openid_basic_content_type(self, factory):
        headers = factory.openid_basic("token")
        assert headers["Content-Type"] == "application/x-www-form-urlencoded"

    def test_openid_bearer_authorization_header(self, factory):
        headers = factory.openid_bearer("mytoken")
        assert headers["Authorization"] == "Bearer mytoken"

    def test_openid_bearer_content_type(self, factory):
        headers = factory.openid_bearer("mytoken")
        assert headers["Content-Type"] == "application/x-www-form-urlencoded"

    def test_keycloak_bearer_authorization_header(self, factory):
        headers = factory.keycloak_bearer("mytoken")
        assert headers["Authorization"] == "Bearer mytoken"

    def test_keycloak_bearer_content_type_is_json(self, factory):
        headers = factory.keycloak_bearer("mytoken")
        assert headers["Content-Type"] == "application/json"

    def test_openid_basic_and_bearer_differ_in_scheme(self, factory):
        basic = factory.openid_basic("tok")
        bearer = factory.openid_bearer("tok")
        assert basic["Authorization"].startswith("Basic ")
        assert bearer["Authorization"].startswith("Bearer ")

    def test_openid_bearer_and_keycloak_bearer_differ_in_content_type(self, factory):
        openid = factory.openid_bearer("tok")
        keycloak = factory.keycloak_bearer("tok")
        assert openid["Content-Type"] != keycloak["Content-Type"]
