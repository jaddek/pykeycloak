# SPDX-License-Identifier: MIT
import pykeycloak.core.urls as urls


class TestBaseUrls:
    def test_base_realms_pattern(self):
        assert "{realm}" in urls.BASE_REALMS

    def test_base_admin_realms_contains_admin_and_realm(self):
        assert "/admin" in urls.BASE_ADMIN_REALMS
        assert "{realm}" in urls.BASE_ADMIN_REALMS

    def test_base_admin_extends_base_realms(self):
        assert urls.BASE_ADMIN_REALMS.startswith("/admin")
        assert urls.BASE_REALMS in urls.BASE_ADMIN_REALMS


class TestOpenIdUrls:
    def test_token_url_contains_token(self):
        assert "/token" in urls.REALM_CLIENT_OPENID_URL_TOKEN

    def test_auth_url_contains_auth(self):
        assert "/auth" in urls.REALM_CLIENT_OPENID_URL_AUTH

    def test_logout_url_contains_logout(self):
        assert "/logout" in urls.REALM_CLIENT_OPENID_URL_LOGOUT

    def test_revoke_url_contains_revoke(self):
        assert "/revoke" in urls.REALM_CLIENT_OPENID_URL_REVOKE

    def test_userinfo_url_contains_userinfo(self):
        assert "/userinfo" in urls.REALM_CLIENT_OPENID_URL_USERINFO

    def test_introspect_url_contains_introspect(self):
        assert "/introspect" in urls.REALM_CLIENT_OPENID_URL_INTROSPECT

    def test_certs_url_contains_certs(self):
        assert "/certs" in urls.REALM_CLIENT_OPENID_URL_CERTS

    def test_auth_device_url_contains_device(self):
        assert "/device" in urls.REALM_CLIENT_OPENID_URL_AUTH_DEVICE


class TestWellKnownUrls:
    def test_openid_configuration_url_ends_with_openid_configuration(self):
        assert urls.REALM_CLIENT_OPENID_CONFIGURATION.endswith(
            "/.well-known/openid-configuration"
        )

    def test_uma2_configuration_url_ends_with_uma2_configuration(self):
        assert urls.REALM_CLIENT_UMA2_CONFIGURATION.endswith(
            "/.well-known/uma2-configuration"
        )

    def test_issuer_url_equals_base_realms(self):
        assert urls.REALM_ISSUER == urls.BASE_REALMS

    def test_openid_configuration_contains_realm_placeholder(self):
        assert "{realm}" in urls.REALM_CLIENT_OPENID_CONFIGURATION

    def test_uma2_configuration_contains_realm_placeholder(self):
        assert "{realm}" in urls.REALM_CLIENT_UMA2_CONFIGURATION

    def test_openid_and_uma2_differ(self):
        assert urls.REALM_CLIENT_OPENID_CONFIGURATION != urls.REALM_CLIENT_UMA2_CONFIGURATION


class TestUserUrls:
    def test_users_list_contains_users(self):
        assert "/users" in urls.REALM_USERS_LIST

    def test_user_url_contains_user_id_placeholder(self):
        assert "{user_id}" in urls.REALM_USER

    def test_reset_password_contains_reset_password(self):
        assert "reset-password" in urls.REALM_RESET_PASSWORD

    def test_user_sessions_contains_sessions(self):
        assert "sessions" in urls.REALM_USER_SESSIONS


class TestClientUrls:
    def test_clients_url_contains_clients(self):
        assert "/clients" in urls.REALM_CLIENTS

    def test_client_url_contains_client_uuid_placeholder(self):
        assert "{client_uuid}" in urls.REALM_CLIENT

    def test_client_roles_contains_roles(self):
        assert "/roles" in urls.REALM_CLIENT_ROLES

    def test_client_secrets_contains_client_secret(self):
        assert "client-secret" in urls.REALM_CLIENT_SECRETS


class TestAuthzUrls:
    def test_authz_url_contains_resource_server(self):
        assert "resource-server" in urls.REALM_CLIENT_AUTHZ

    def test_authz_policy_contains_policy_id_placeholder(self):
        assert "{policy_id}" in urls.REALM_CLIENT_AUTHZ_POLICY

    def test_authz_resource_contains_resource_id_placeholder(self):
        assert "{resource_id}" in urls.REALM_CLIENT_AUTHZ_RESOURCE

    def test_authz_permission_scope_contains_scope(self):
        assert "/scope" in urls.REALM_CLIENT_AUTHZ_PERMISSIONS_BASED_ON_SCOPES

    def test_authz_permission_resource_contains_resource(self):
        assert "/resource" in urls.REALM_CLIENT_AUTHZ_PERMISSIONS_BASED_ON_RESOURCE
