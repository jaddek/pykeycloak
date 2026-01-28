"""
Unit tests for the urls module.
"""

from pykeycloak.core.urls import (
    BASE_ADMIN_REALMS,
    BASE_PROTOCOL_OPENID_CONNECT,
    BASE_REALMS,
    REALM_CLIENT_ACTIVE_SESSION_COUNT,
    REALM_CLIENT_AUTHZ_RESOURCE_PERMISSIONS,
    REALM_CLIENT_AUTHZ_RESOURCE_POLICY_ROLE,
    REALM_CLIENT_AUTHZ_RESOURCE_POLICY_SEARCH,
    REALM_CLIENT_AUTHZ_RESOURCE_POLICY_USER,
    REALM_CLIENT_OFFLINE_SESSION_COUNT,
    REALM_CLIENT_OFFLINE_SESSIONS,
    REALM_CLIENT_OPENID_URL_AUTH_DEVICE,
    REALM_CLIENT_OPENID_URL_CERTS,
    REALM_CLIENT_OPENID_URL_INTROSPECT,
    REALM_CLIENT_OPENID_URL_LOGOUT,
    REALM_CLIENT_OPENID_URL_REVOKE,
    REALM_CLIENT_OPENID_URL_TOKEN,
    REALM_CLIENT_OPENID_URL_USERINFO,
    REALM_CLIENT_ROLE,
    REALM_CLIENT_ROLE_MEMBERS,
    REALM_CLIENT_ROLES,
    REALM_CLIENT_SESSION_STATS,
    REALM_CLIENT_USER_OFFLINE_SESSIONS,
    REALM_CLIENT_USER_ROLE_MAPPING,
    REALM_CLIENT_USER_ROLE_MAPPING_AVAILABLE,
    REALM_CLIENT_USER_ROLE_MAPPING_COMPOSITE,
    REALM_CLIENT_USER_SESSIONS,
    REALM_DELETE_SESSION,
    REALM_LOGOUT_ALL,
    REALM_ROLES_ROLE_BY_ID,
    REALM_ROLES_ROLE_BY_NAME,
    REALM_USER,
    REALM_USER_LOGOUT,
    REALM_USER_SESSIONS,
    REALM_USERS_COUNT,
    REALM_USERS_LIST,
    USER_LOGOUT, REALM_CLIENT_AUTHZ_CLIENT_POLICY_ASSOCIATED_ROLE_POLICIES,
)


class TestURLConstants:
    """Test cases for URL constants in the urls module."""

    def test_base_realms_constant(self):
        """Test the BASE_REALMS constant."""
        assert BASE_REALMS == "/realms/{realm}"

    def test_base_admin_realms_constant(self):
        """Test the BASE_ADMIN_REALMS constant."""
        expected = "/admin/realms/{realm}"
        assert BASE_ADMIN_REALMS == expected

    def test_user_logout_constant(self):
        """Test the USER_LOGOUT constant."""
        expected = "/admin/realms/{realm}/users/{user_id}/logout"
        assert USER_LOGOUT == expected

    def test_realm_logout_all_constant(self):
        """Test the REALM_LOGOUT_ALL constant."""
        expected = "/admin/realms/{realm}/logout-all"
        assert REALM_LOGOUT_ALL == expected

    def test_realm_client_authz_resource_policy_search_constant(self):
        """Test the REALM_CLIENT_AUTHZ_RESOURCE_POLICY_SEARCH constant."""
        expected = "/admin/realms/{realm}/clients/{client_id}/authz/resource-server/policy/search"
        assert REALM_CLIENT_AUTHZ_RESOURCE_POLICY_SEARCH == expected

    def test_realm_client_authz_resource_permissions_constant(self):
        """Test the REALM_CLIENT_AUTHZ_RESOURCE_PERMISSIONS constant."""
        expected = "/admin/realms/{realm}/clients/{client_id}/authz/resource-server/resource/{resource_id}/permissions"
        assert REALM_CLIENT_AUTHZ_RESOURCE_PERMISSIONS == expected

    def test_realm_client_authz_resource_permission_policy_scopes_constant(self):
        """Test the REALM_CLIENT_AUTHZ_RESOURCE_PERMISSION_POLICY_SCOPES constant."""
        expected = "/admin/realms/{realm}/clients/{client_id}/authz/resource-server/policy/{policy_id}/associatedPolicies"
        assert REALM_CLIENT_AUTHZ_CLIENT_POLICY_ASSOCIATED_ROLE_POLICIES == expected

    def test_realm_client_authz_resource_policy_user_constant(self):
        """Test the REALM_CLIENT_AUTHZ_RESOURCE_POLICY_USER constant."""
        expected = "/admin/realms/{realm}/clients/{client_id}/authz/resource-server/policy/user"
        assert REALM_CLIENT_AUTHZ_RESOURCE_POLICY_USER == expected

    def test_realm_client_authz_resource_policy_role_constant(self):
        """Test the REALM_CLIENT_AUTHZ_RESOURCE_POLICY_ROLE constant."""
        expected = "/admin/realms/{realm}/clients/{client_id}/authz/resource-server/policy/role"
        assert REALM_CLIENT_AUTHZ_RESOURCE_POLICY_ROLE == expected

    def test_base_protocol_openid_connect_constant(self):
        """Test the BASE_PROTOCOL_OPENID_CONNECT constant."""
        expected = "/realms/{realm}/protocol/openid-connect"
        assert BASE_PROTOCOL_OPENID_CONNECT == expected

    def test_realm_client_openid_url_token_constant(self):
        """Test the REALM_CLIENT_OPENID_URL_TOKEN constant."""
        expected = "/realms/{realm}/protocol/openid-connect/token"
        assert REALM_CLIENT_OPENID_URL_TOKEN == expected

    def test_realm_client_openid_url_logout_constant(self):
        """Test the REALM_CLIENT_OPENID_URL_LOGOUT constant."""
        expected = "/realms/{realm}/protocol/openid-connect/logout"
        assert REALM_CLIENT_OPENID_URL_LOGOUT == expected

    def test_realm_client_openid_url_userinfo_constant(self):
        """Test the REALM_CLIENT_OPENID_URL_USERINFO constant."""
        expected = "/realms/{realm}/protocol/openid-connect/userinfo"
        assert REALM_CLIENT_OPENID_URL_USERINFO == expected

    def test_realm_client_openid_url_introspect_constant(self):
        """Test the REALM_CLIENT_OPENID_URL_INTROSPECT constant."""
        expected = "/realms/{realm}/protocol/openid-connect/token/introspect"
        assert REALM_CLIENT_OPENID_URL_INTROSPECT == expected

    def test_realm_client_openid_url_auth_device_constant(self):
        """Test the REALM_CLIENT_OPENID_URL_AUTH_DEVICE constant."""
        expected = "/realms/{realm}/protocol/openid-connect/auth/device"
        assert REALM_CLIENT_OPENID_URL_AUTH_DEVICE == expected

    def test_realm_client_openid_url_certs_constant(self):
        """Test the REALM_CLIENT_OPENID_URL_CERTS constant."""
        expected = "/realms/{realm}/protocol/openid-connect/certs"
        assert REALM_CLIENT_OPENID_URL_CERTS == expected

    def test_realm_client_openid_url_revoke_constant(self):
        """Test the REALM_CLIENT_OPENID_URL_REVOKE constant."""
        expected = "/realms/{realm}/protocol/openid-connect/revoke"
        assert REALM_CLIENT_OPENID_URL_REVOKE == expected

    def test_realm_users_list_constant(self):
        """Test the REALM_USERS_LIST constant."""
        expected = "/admin/realms/{realm}/users"
        assert REALM_USERS_LIST == expected

    def test_realm_users_count_constant(self):
        """Test the REALM_USERS_COUNT constant."""
        expected = "/admin/realms/{realm}/users/count"
        assert REALM_USERS_COUNT == expected

    def test_realm_user_constant(self):
        """Test the REALM_USER constant."""
        expected = "/admin/realms/{realm}/users/{user_id}"
        assert REALM_USER == expected

    def test_realm_user_logout_constant(self):
        """Test the REALM_USER_LOGOUT constant."""
        expected = "/admin/realms/{realm}/users/{user_id}/logout"
        assert REALM_USER_LOGOUT == expected

    def test_realm_client_roles_constant(self):
        """Test the REALM_CLIENT_ROLES constant."""
        expected = "/admin/realms/{realm}/clients/{client_id}/roles"
        assert REALM_CLIENT_ROLES == expected

    def test_realm_client_role_members_constant(self):
        """Test the REALM_CLIENT_ROLE_MEMBERS constant."""
        expected = "/admin/realms/{realm}/clients/{client_id}/roles/{role_name}/users"
        assert REALM_CLIENT_ROLE_MEMBERS == expected

    def test_realm_user_sessions_constant(self):
        """Test the REALM_USER_SESSIONS constant."""
        expected = "/admin/realms/{realm}/users/{user_id}/sessions"
        assert REALM_USER_SESSIONS == expected

    def test_realm_delete_session_constant(self):
        """Test the REALM_DELETE_SESSION constant."""
        expected = "/admin/realms/{realm}/sessions/{session_id}"
        assert REALM_DELETE_SESSION == expected

    def test_realm_client_user_sessions_constant(self):
        """Test the REALM_CLIENT_USER_SESSIONS constant."""
        expected = "/admin/realms/{realm}/clients/{client_id}/user-sessions"
        assert REALM_CLIENT_USER_SESSIONS == expected

    def test_realm_client_active_session_count_constant(self):
        """Test the REALM_CLIENT_ACTIVE_SESSION_COUNT constant."""
        expected = "/admin/realms/{realm}/clients/{client_id}/session-count"
        assert REALM_CLIENT_ACTIVE_SESSION_COUNT == expected

    def test_realm_client_offline_session_count_constant(self):
        """Test the REALM_CLIENT_OFFLINE_SESSION_COUNT constant."""
        expected = "/admin/realms/{realm}/clients/{client_id}/offline-session-count"
        assert REALM_CLIENT_OFFLINE_SESSION_COUNT == expected

    def test_realm_client_offline_sessions_constant(self):
        """Test the REALM_CLIENT_OFFLINE_SESSIONS constant."""
        expected = "/admin/realms/{realm}/clients/{client_id}/offline-sessions"
        assert REALM_CLIENT_OFFLINE_SESSIONS == expected

    def test_realm_client_user_offline_sessions_constant(self):
        """Test the REALM_CLIENT_USER_OFFLINE_SESSIONS constant."""
        expected = "/admin/realms/{realm}/users/{user_id}/offline-sessions/{client_id}"
        assert REALM_CLIENT_USER_OFFLINE_SESSIONS == expected

    def test_realm_roles_role_by_id_constant(self):
        """Test the REALM_ROLES_ROLE_BY_ID constant."""
        expected = "/admin/realms/{realm}/roles-by-id/{role_id}"
        assert REALM_ROLES_ROLE_BY_ID == expected

    def test_realm_client_role_constant(self):
        """Test the REALM_CLIENT_ROLE constant."""
        expected = "/admin/realms/{realm}/clients/{client_id}/roles/{role_name}"
        assert REALM_CLIENT_ROLE == expected

    def test_realm_roles_role_by_name_constant(self):
        """Test the REALM_ROLES_ROLE_BY_NAME constant."""
        expected = "/admin/realms/{realm}/roles/{role_name}"
        assert REALM_ROLES_ROLE_BY_NAME == expected

    def test_realm_client_user_role_mapping_constant(self):
        """Test the REALM_CLIENT_USER_ROLE_MAPPING constant."""
        expected = (
            "/admin/realms/{realm}/users/{user_id}/role-mappings/clients/{client_id}"
        )
        assert REALM_CLIENT_USER_ROLE_MAPPING == expected

    def test_realm_client_user_role_mapping_available_constant(self):
        """Test the REALM_CLIENT_USER_ROLE_MAPPING_AVAILABLE constant."""
        expected = "/admin/realms/{realm}/users/{user_id}/role-mappings/clients/{client_id}/available"
        assert REALM_CLIENT_USER_ROLE_MAPPING_AVAILABLE == expected

    def test_realm_client_user_role_mapping_composite_constant(self):
        """Test the REALM_CLIENT_USER_ROLE_MAPPING_COMPOSITE constant."""
        expected = "/admin/realms/{realm}/users/{user_id}/role-mappings/clients/{client_id}/composite"
        assert REALM_CLIENT_USER_ROLE_MAPPING_COMPOSITE == expected

    def test_realm_client_session_stats_constant(self):
        """Test the REALM_CLIENT_SESSION_STATS constant."""
        expected = "/admin/realms/{realm}/client-session-stats"
        assert REALM_CLIENT_SESSION_STATS == expected
