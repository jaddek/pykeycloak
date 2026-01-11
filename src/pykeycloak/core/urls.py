BASE_REALMS = "/realms/{realm}"
BASE_ADMIN_REALMS = "/admin" + BASE_REALMS

USER_SESSIONS = BASE_ADMIN_REALMS + "/users/{user_id}/sessions"
DELETE_SESSION = BASE_ADMIN_REALMS + "/sessions/{session_id}"
USER_LOGOUT = BASE_ADMIN_REALMS + "/users/{user_id}/logout"
REALM_LOGOUT_ALL = BASE_ADMIN_REALMS + "/logout-all"
CLIENT_SESSION_STATS = BASE_ADMIN_REALMS + "/client-session-stats"
CLIENT_OFFLINE_SESSION_COUNT = (
    BASE_ADMIN_REALMS + "/clients/{client_id}/offline-session-count"
)
CLIENT_OFFLINE_SESSIONS = BASE_ADMIN_REALMS + "/clients/{client_id}/offline-sessions"
CLIENT_ACTIVE_SESSION_COUNT = BASE_ADMIN_REALMS + "/clients/{client_id}/session-count"
CLIENT_USER_SESSIONS = BASE_ADMIN_REALMS + "/clients/{client_id}/user-sessions"
CLIENT_USER_OFFLINE_SESSIONS = (
    BASE_ADMIN_REALMS + "/users/{user_id}/offline-sessions/{client_id}"
)

REALM_CLIENT_AUTHZ_RESOURCE_POLICY_SEARCH = (
    BASE_ADMIN_REALMS + "/clients/{client_id}/authz/resource-server/policy/search"
)

REALM_CLIENT_AUTHZ_RESOURCE_PERMISSIONS = (
    BASE_ADMIN_REALMS
    + "/clients/{client_id}/authz/resource-server/resource/{resource_id}/permissions"
)

REALM_CLIENT_AUTHZ_RESOURCE_PERMISSION_POLICY_SCOPES = (
    BASE_ADMIN_REALMS
    + "/clients/{client_id}/authz/resource-server/policy/{policy_id}/associatedPolicies"
)

REALM_CLIENT_AUTHZ_RESOURCE_POLICY_USER = (
    BASE_ADMIN_REALMS + "/clients/{client_id}/authz/resource-server/policy/user"
)

REALM_CLIENT_AUTHZ_RESOURCE_POLICY_ROLE = (
    BASE_ADMIN_REALMS + "/clients/{client_id}/authz/resource-server/policy/role"
)

####
# OpenID urls
####

BASE_PROTOCOL_OPENID_CONNECT = BASE_REALMS + "/protocol/openid-connect"

REALM_CLIENT_OPENID_URL_TOKEN = BASE_PROTOCOL_OPENID_CONNECT + "/token"  # noqa: S105
REALM_CLIENT_OPENID_URL_LOGOUT = BASE_PROTOCOL_OPENID_CONNECT + "/logout"
REALM_CLIENT_OPENID_URL_USERINFO = BASE_PROTOCOL_OPENID_CONNECT + "/userinfo"
REALM_CLIENT_OPENID_URL_INTROSPECT = BASE_PROTOCOL_OPENID_CONNECT + "/token/introspect"
REALM_CLIENT_OPENID_URL_AUTH_DEVICE = BASE_PROTOCOL_OPENID_CONNECT + "/auth/device"
REALM_CLIENT_OPENID_URL_CERTS = BASE_PROTOCOL_OPENID_CONNECT + "/certs"
# _URL_WELL_KNOWN_BASE = "realms/{realm-name}/.well-known/openid-configuration"
# _URL_WELL_KNOWN = _URL_WELL_KNOWN_BASE + "/openid-configuration"
