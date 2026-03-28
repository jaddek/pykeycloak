# SPDX-License-Identifier: MIT
import base64

import pytest

from pykeycloak.core.realm import RealmClient

VALID_UUID = "550e8400-e29b-41d4-a716-446655440000"


class TestRealmClientInit:
    def test_creates_confidential_client(self):
        rc = RealmClient(
            realm_name="myrealm",
            client_uuid=VALID_UUID,
            client_id="my-client",
            client_secret="secret",
        )
        assert rc.realm_name == "myrealm"
        assert rc.client_uuid == VALID_UUID
        assert rc.client_id == "my-client"
        assert rc.client_secret == "secret"
        assert rc.is_confidential is True

    def test_creates_public_client(self):
        rc = RealmClient(
            realm_name="myrealm",
            client_uuid=VALID_UUID,
            client_id="my-client",
        )
        assert rc.is_confidential is False
        assert rc.client_secret is None

    def test_raises_when_client_uuid_empty(self):
        with pytest.raises(ValueError):
            RealmClient(realm_name="r", client_uuid="", client_id="c")

    def test_raises_when_client_id_empty(self):
        with pytest.raises(ValueError):
            RealmClient(realm_name="r", client_uuid=VALID_UUID, client_id="")


class TestBase64EncodedClientSecret:
    def test_returns_correct_base64(self):
        rc = RealmClient(
            realm_name="r", client_uuid=VALID_UUID, client_id="cid", client_secret="sec"
        )
        expected = base64.b64encode(b"cid:sec").decode()
        assert rc.base64_encoded_client_secret() == expected

    def test_raises_for_public_client(self):
        rc = RealmClient(realm_name="r", client_uuid=VALID_UUID, client_id="cid")
        with pytest.raises(AttributeError):
            rc.base64_encoded_client_secret()


class TestResolveId:
    def test_returns_override_when_provided(self):
        rc = RealmClient(realm_name="r", client_uuid=VALID_UUID, client_id="cid")
        assert rc.resolve_id("override") == "override"

    def test_returns_client_id_when_no_override(self):
        rc = RealmClient(realm_name="r", client_uuid=VALID_UUID, client_id="cid")
        assert rc.resolve_id() == "cid"

    def test_returns_client_id_when_override_is_none(self):
        rc = RealmClient(realm_name="r", client_uuid=VALID_UUID, client_id="cid")
        assert rc.resolve_id(None) == "cid"


class TestFromEnv:
    def _set_env(self, monkeypatch, name="TEST"):
        monkeypatch.setenv(f"KEYCLOAK_REALM_{name}_REALM_NAME", "myrealm")
        monkeypatch.setenv(f"KEYCLOAK_REALM_{name}_CLIENT_UUID", VALID_UUID)
        monkeypatch.setenv(f"KEYCLOAK_REALM_{name}_CLIENT_ID", "my-client")
        monkeypatch.setenv(f"KEYCLOAK_REALM_{name}_CLIENT_SECRET", "my-secret")

    def test_creates_client_from_env(self, monkeypatch):
        self._set_env(monkeypatch)
        rc = RealmClient.from_env("test")
        assert rc.realm_name == "myrealm"
        assert rc.client_id == "my-client"
        assert rc.client_secret == "my-secret"
        assert rc.client_uuid == VALID_UUID

    def test_raises_when_env_var_missing(self, monkeypatch):
        monkeypatch.delenv("KEYCLOAK_REALM_TEST_REALM_NAME", raising=False)
        with pytest.raises(RuntimeError):
            RealmClient.from_env("test")

    def test_raises_when_uuid_is_invalid(self, monkeypatch):
        self._set_env(monkeypatch)
        monkeypatch.setenv("KEYCLOAK_REALM_TEST_CLIENT_UUID", "not-a-uuid")
        with pytest.raises(RuntimeError, match="invalid format"):
            RealmClient.from_env("test")

    def test_client_name_uppercased(self, monkeypatch):
        self._set_env(monkeypatch, name="TEST")
        rc = RealmClient.from_env("test")
        assert rc.client_id == "my-client"


class TestRealmClientStrRepr:
    def test_str(self):
        rc = RealmClient(realm_name="r", client_uuid=VALID_UUID, client_id="cid")
        assert "cid" in str(rc)

    def test_repr(self):
        rc = RealmClient(realm_name="r", client_uuid=VALID_UUID, client_id="cid")
        r = repr(rc)
        assert "cid" in r
        assert VALID_UUID in r
