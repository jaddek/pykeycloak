# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Anton "Tony" Nazarov <tonynazarov+dev@gmail.com>

# ###
# Mess
# ###

# ######################################################################
# Base URLs
# ######################################################################

BASE_REALMS = "/realms/{realm}"
BASE_ADMIN_REALMS = "/admin" + BASE_REALMS

# ######################################################################
# Client Authorization
# ######################################################################

USER_LOGOUT = BASE_ADMIN_REALMS + "/users/{user_id}/logout"
REALM_LOGOUT_ALL = BASE_ADMIN_REALMS + "/logout-all"

# ######################################################################
# OpenID URLs
# ######################################################################

BASE_PROTOCOL_OPENID_CONNECT = BASE_REALMS + "/protocol/openid-connect"

REALM_CLIENT_OPENID_URL_TOKEN = BASE_PROTOCOL_OPENID_CONNECT + "/token"  # noqa: S105
REALM_CLIENT_OPENID_URL_LOGOUT = BASE_PROTOCOL_OPENID_CONNECT + "/logout"
REALM_CLIENT_OPENID_URL_REVOKE = BASE_PROTOCOL_OPENID_CONNECT + "/revoke"
REALM_CLIENT_OPENID_URL_USERINFO = BASE_PROTOCOL_OPENID_CONNECT + "/userinfo"
REALM_CLIENT_OPENID_URL_INTROSPECT = BASE_PROTOCOL_OPENID_CONNECT + "/token/introspect"
REALM_CLIENT_OPENID_URL_AUTH_DEVICE = BASE_PROTOCOL_OPENID_CONNECT + "/auth/device"
REALM_CLIENT_OPENID_URL_CERTS = BASE_PROTOCOL_OPENID_CONNECT + "/certs"
# _URL_WELL_KNOWN_BASE = "realms/{realm}/.well-known/openid-configuration"
# _URL_WELL_KNOWN = _URL_WELL_KNOWN_BASE + "/openid-configuration"

# ######################################################################
# Users
# ######################################################################

REALM_USERS_LIST = BASE_ADMIN_REALMS + "/users"
REALM_USERS_COUNT = BASE_ADMIN_REALMS + "/users/count"
REALM_USER_SESSIONS = BASE_ADMIN_REALMS + "/users/{user_id}/sessions"
REALM_USER = BASE_ADMIN_REALMS + "/users/{user_id}"
REALM_USER_CONSENTS = BASE_ADMIN_REALMS + "/users/{user_id}/consents"
REALM_USER_CONSENT = REALM_USER_CONSENTS + "/{client_id}"
REALM_SEND_UPDATE_ACCOUNT = BASE_ADMIN_REALMS + "/users/{user_id}/execute-actions-email"
REALM_SEND_VERIFY_EMAIL = BASE_ADMIN_REALMS + "/users/{user_id}/send-verify-email"
REALM_RESET_PASSWORD = BASE_ADMIN_REALMS + "/users/{user_id}/reset-password"  # noqa: S105
REALM_GET_SESSIONS = BASE_ADMIN_REALMS + "/users/{user_id}/sessions"
REALM_USER_ALL_ROLES = BASE_ADMIN_REALMS + "/users/{user_id}/role-mappings"
REALM_USER_CLIENT_ROLES = (
        BASE_ADMIN_REALMS + "/users/{user_id}/role-mappings/clients/{client_id}"
)
REALM_USER_REALM_ROLES = BASE_ADMIN_REALMS + "/users/{user_id}/role-mappings/realm"
REALM_USER_REALM_ROLES_AVAILABLE = (
        BASE_ADMIN_REALMS + "/users/{user_id}/role-mappings/realm/available"
)
REALM_USER_REALM_ROLES_COMPOSITE = (
        BASE_ADMIN_REALMS + "/users/{user_id}/role-mappings/realm/composite"
)

REALM_CLIENT_USER_ROLE_MAPPING = (
        BASE_ADMIN_REALMS + "/users/{user_id}/role-mappings/clients/{client_uuid}"
)

REALM_CLIENT_USER_ROLE_MAPPING_AVAILABLE = (
        BASE_ADMIN_REALMS + "/users/{user_id}/role-mappings/clients/{client_uuid}/available"
)

REALM_CLIENT_USER_ROLE_MAPPING_COMPOSITE = (
        BASE_ADMIN_REALMS + "/users/{user_id}/role-mappings/clients/{client_uuid}/composite"
)

# ######################################################################
# Sessions
# ######################################################################

REALM_DELETE_SESSION = BASE_ADMIN_REALMS + "/sessions/{session_id}"
REALM_SESSION_STATS = BASE_ADMIN_REALMS + "/client-session-stats"
REALM_CLIENT_OFFLINE_SESSION_COUNT = (
        BASE_ADMIN_REALMS + "/clients/{client_uuid}/offline-session-count"
)
REALM_CLIENT_OFFLINE_SESSIONS = (
        BASE_ADMIN_REALMS + "/clients/{client_uuid}/offline-sessions"
)
REALM_CLIENT_ACTIVE_SESSION_COUNT = (
        BASE_ADMIN_REALMS + "/clients/{client_uuid}/session-count"
)
REALM_CLIENT_USER_SESSIONS = BASE_ADMIN_REALMS + "/clients/{client_uuid}/user-sessions"

REALM_CLIENT_USER_OFFLINE_SESSIONS = (
        BASE_ADMIN_REALMS + "/users/{client_uuid}/offline-sessions/{client_id}"
)

# ######################################################################
# Groups
# ######################################################################

REALM_GROUPS_REALM_ROLES = BASE_ADMIN_REALMS + "/groups/{id}/role-mappings/realm"
REALM_GROUPS_CLIENT_ROLES = (
        BASE_ADMIN_REALMS + "/groups/{id}/role-mappings/clients/{client_id}"
)

REALM_USER_CLIENT_ROLES_AVAILABLE = (
        BASE_ADMIN_REALMS + "/users/{user_id}/role-mappings/clients/{client_id}/available"
)
REALM_USER_CLIENT_ROLES_COMPOSITE = (
        BASE_ADMIN_REALMS + "/users/{user_id}/role-mappings/clients/{client_id}/composite"
)

REALM_USER_GROUP = BASE_ADMIN_REALMS + "/users/{user_id}/groups/{group_id}"
REALM_USER_GROUPS = BASE_ADMIN_REALMS + "/users/{user_id}/groups"

REALM_USER_CREDENTIALS = BASE_ADMIN_REALMS + "/users/{user_id}/credentials"
REALM_USER_CREDENTIAL = (
        BASE_ADMIN_REALMS + "/users/{user_id}/credentials/{credential_id}"
)
REALM_USER_LOGOUT = BASE_ADMIN_REALMS + "/users/{user_id}/logout"
REALM_USER_STORAGE = BASE_ADMIN_REALMS + "/user-storage/{id}/sync"

REALM_SERVER_INFO = "admin/serverinfo"

# ######################################################################
# Clients
# ######################################################################

REALM_CLIENT_INITIAL_ACCESS = BASE_ADMIN_REALMS + "/clients-initial-access"
REALM_CLIENTS = BASE_ADMIN_REALMS + "/clients"
REALM_CLIENT = REALM_CLIENTS + "/{client_uuid}"
REALM_CLIENT_ALL_SESSIONS = REALM_CLIENT + "/user-sessions"
REALM_CLIENT_SECRETS = REALM_CLIENT + "/client-secret"
REALM_CLIENT_ROLES = REALM_CLIENT + "/roles"
REALM_CLIENT_ROLE = REALM_CLIENT + "/roles/{role_name}"
REALM_CLIENT_ROLES_COMPOSITE_CLIENT_ROLE = REALM_CLIENT_ROLE + "/composites"
REALM_CLIENT_ROLE_MEMBERS = REALM_CLIENT + "/roles/{role_name}/users"
REALM_CLIENT_ROLE_GROUPS = REALM_CLIENT + "/roles/{role_name}/groups"
REALM_CLIENT_MANAGEMENT_PERMISSIONS = REALM_CLIENT + "/management/permissions"
REALM_CLIENT_SCOPE_MAPPINGS_REALM_ROLES = REALM_CLIENT + "/scope-mappings/realm"
REALM_CLIENT_SCOPE_MAPPINGS_CLIENT_ROLES = (
        REALM_CLIENT + "/scope-mappings/clients/{client_id}"
)
REALM_CLIENT_OPTIONAL_CLIENT_SCOPES = REALM_CLIENT + "/optional-client-scopes"
REALM_CLIENT_OPTIONAL_CLIENT_SCOPE = (
        REALM_CLIENT_OPTIONAL_CLIENT_SCOPES + "/{client_scope_id}"
)
REALM_CLIENT_DEFAULT_CLIENT_SCOPES = REALM_CLIENT + "/default-client-scopes"
REALM_CLIENT_DEFAULT_CLIENT_SCOPE = (
        REALM_CLIENT_DEFAULT_CLIENT_SCOPES + "/{client_scope_id}"
)

# ######################################################################
# Client Authorization
# ######################################################################

REALM_CLIENT_AUTHZ = REALM_CLIENT + "/authz/resource-server"

### Settings

REALM_CLIENT_AUTHZ_SETTINGS = REALM_CLIENT_AUTHZ + "/settings"

### Policy

REALM_CLIENT_AUTHZ_POLICIES         = REALM_CLIENT_AUTHZ + "/policy"
REALM_CLIENT_AUTHZ_POLICY           = REALM_CLIENT_AUTHZ + "/policy/{policy_id}"
REALM_CLIENT_AUTHZ_POLICY_RESOURCES = REALM_CLIENT_AUTHZ + "/policy/{policy_id}/resources"
REALM_CLIENT_AUTHZ_POLICY_SEARCH    = REALM_CLIENT_AUTHZ + "/policy/search"
REALM_CLIENT_AUTHZ_POLICY_USER      = REALM_CLIENT_AUTHZ + "/policy/user"
REALM_CLIENT_AUTHZ_POLICY_ROLE      = REALM_CLIENT_AUTHZ + "/policy/role"
REALM_CLIENT_AUTHZ_POLICY_SCOPES    = REALM_CLIENT_AUTHZ + "/policy/{policy_id}/scopes"

### Scopes

REALM_CLIENT_AUTHZ_SCOPES = REALM_CLIENT_AUTHZ + "/scope"

### Resources

REALM_CLIENT_AUTHZ_RESOURCES            = REALM_CLIENT_AUTHZ + "/resource"
REALM_CLIENT_AUTHZ_RESOURCE             = REALM_CLIENT_AUTHZ + "/resource/{resource_id}"
REALM_CLIENT_AUTHZ_RESOURCE_PERMISSIONS = REALM_CLIENT_AUTHZ + "/resource/{resource_id}/permissions"

### Permissions

REALM_CLIENT_AUTHZ_PERMISSIONS                   = REALM_CLIENT_AUTHZ + "/permission"
REALM_CLIENT_AUTHZ_PERMISSIONS_BASED_ON_SCOPES   = REALM_CLIENT_AUTHZ + "/permission/scope"
REALM_CLIENT_AUTHZ_PERMISSIONS_BASED_ON_RESOURCE = REALM_CLIENT_AUTHZ + "/permission/resource"

REALM_CLIENT_AUTHZ_PERMISSION_BASED_ON_SCOPES   = REALM_CLIENT_AUTHZ + "/permission/scope/{permission_id}"
REALM_CLIENT_AUTHZ_PERMISSION_BASED_ON_RESOURCE = REALM_CLIENT_AUTHZ + "/permission/resource/{permission_id}"

### Policies

REALM_CLIENT_AUTHZ_CLIENT_POLICY = REALM_CLIENT_AUTHZ + "/policy/client"
REALM_CLIENT_AUTHZ_CLIENT_POLICY_ASSOCIATED_ROLE_POLICIES = (
        REALM_CLIENT_AUTHZ + "/policy/{policy_id}/associatedPolicies"
)

### Other

REALM_CLIENT_SERVICE_ACCOUNT_USER = REALM_CLIENT + "/service-account-user"
REALM_CLIENT_CERTS = REALM_CLIENT + "/certificates/{attr}"
REALM_CLIENT_INSTALLATION_PROVIDER = (
        REALM_CLIENT + "/installation/providers/{provider_id}"
)
REALM_CLIENT_PROTOCOL_MAPPERS = REALM_CLIENT + "/protocol-mappers/models"
REALM_CLIENT_PROTOCOL_MAPPER = REALM_CLIENT_PROTOCOL_MAPPERS + "/{protocol_mapper_id}"

# ######################################################################
# Client Scopes
# ######################################################################

REALM_CLIENT_SCOPES = BASE_ADMIN_REALMS + "/client-scopes"
REALM_CLIENT_SCOPE = REALM_CLIENT_SCOPES + "/{scope_id}"
REALM_CLIENT_SCOPES_ADD_MAPPER = REALM_CLIENT_SCOPE + "/protocol-mappers/models"
REALM_CLIENT_SCOPES_MAPPERS = REALM_CLIENT_SCOPES_ADD_MAPPER + "/{protocol_mapper_id}"
REALM_CLIENT_SCOPE_ROLE_MAPPINGS = REALM_CLIENT_SCOPE + "/scope-mappings"
REALM_CLIENT_SCOPE_ROLE_MAPPINGS_REALM = REALM_CLIENT_SCOPE_ROLE_MAPPINGS + "/realm"
REALM_CLIENT_SCOPE_ROLE_MAPPINGS_CLIENT = (
        REALM_CLIENT_SCOPE_ROLE_MAPPINGS + "/clients/{client_id}"
)

# ######################################################################
# Roles
# ######################################################################

REALM_ROLES = BASE_ADMIN_REALMS + "/roles"
REALM_ROLES_MEMBERS = REALM_ROLES + "/{role_name}/users"
REALM_ROLES_GROUPS = REALM_ROLES + "/{role_name}/groups"
REALM_USER_PROFILE = BASE_ADMIN_REALMS + "/users/profile"

# ######################################################################
# Identity Providers
# ######################################################################

REALM_IDPS = BASE_ADMIN_REALMS + "/identity-provider/instances"
REALM_IDP_MAPPERS = (
        BASE_ADMIN_REALMS + "/identity-provider/instances/{idp_alias}/mappers"
)
REALM_IDP_MAPPER_UPDATE = REALM_IDP_MAPPERS + "/{mapper_id}"
REALM_IDP = BASE_ADMIN_REALMS + "/identity-provider/instances/{alias}"

# ######################################################################
# Roles by ID
# ######################################################################

REALM_ROLES_ROLE_BY_ID = BASE_ADMIN_REALMS + "/roles-by-id/{role_id}"
REALM_ROLES_ROLE_BY_NAME = BASE_ADMIN_REALMS + "/roles/{role_name}"
REALM_ROLES_COMPOSITE = BASE_ADMIN_REALMS + "/roles/{role_name}/composites"
REALM_ROLES_DELETE_ROLE_BY_NAME = (
        BASE_ADMIN_REALMS + "/clients/{client_uuid}/roles/{role_name}"
)

# ######################################################################
# Export/Import
# ######################################################################

REALM_REALM_EXPORT = BASE_ADMIN_REALMS + "/partial-export"
REALM_REALM_PARTIAL_IMPORT = BASE_ADMIN_REALMS + "/partialImport"

# ######################################################################
# Default Scopes
# ######################################################################

REALM_DEFAULT_DEFAULT_CLIENT_SCOPES = (
        BASE_ADMIN_REALMS + "/default-default-client-scopes"
)
REALM_DEFAULT_DEFAULT_CLIENT_SCOPE = REALM_DEFAULT_DEFAULT_CLIENT_SCOPES + "/{id}"
REALM_DEFAULT_OPTIONAL_CLIENT_SCOPES = (
        BASE_ADMIN_REALMS + "/default-optional-client-scopes"
)
REALM_DEFAULT_OPTIONAL_CLIENT_SCOPE = REALM_DEFAULT_OPTIONAL_CLIENT_SCOPES + "/{id}"

# ######################################################################
# Authentication Flows
# ######################################################################

REALM_FLOWS = BASE_ADMIN_REALMS + "/authentication/flows"
REALM_FLOW = REALM_FLOWS + "/{id}"
REALM_FLOWS_ALIAS = BASE_ADMIN_REALMS + "/authentication/flows/{flow_id}"
REALM_FLOWS_COPY = BASE_ADMIN_REALMS + "/authentication/flows/{flow_alias}/copy"
REALM_FLOWS_EXECUTIONS = (
        BASE_ADMIN_REALMS + "/authentication/flows/{flow_alias}/executions"
)
REALM_FLOWS_EXECUTION = BASE_ADMIN_REALMS + "/authentication/executions/{id}"
REALM_FLOWS_EXECUTIONS_EXECUTION = (
        BASE_ADMIN_REALMS + "/authentication/flows/{flow_alias}/executions/execution"
)
REALM_FLOWS_EXECUTIONS_FLOW = (
        BASE_ADMIN_REALMS + "/authentication/flows/{flow_alias}/executions/flow"
)
REALM_AUTHENTICATOR_PROVIDERS = (
        BASE_ADMIN_REALMS + "/authentication/authenticator-providers"
)
REALM_AUTHENTICATOR_CONFIG_DESCRIPTION = (
        BASE_ADMIN_REALMS + "/authentication/config-description/{provider_id}"
)
REALM_AUTHENTICATOR_CONFIG = BASE_ADMIN_REALMS + "/authentication/config/{id}"

# ######################################################################
# Components
# ######################################################################

REALM_COMPONENTS = BASE_ADMIN_REALMS + "/components"
REALM_COMPONENT = BASE_ADMIN_REALMS + "/components/{component_id}"
REALM_KEYS = BASE_ADMIN_REALMS + "/keys"

# ######################################################################
# Federated Identities
# ######################################################################

REALM_USER_FEDERATED_IDENTITIES = (
        BASE_ADMIN_REALMS + "/users/{user_id}/federated-identity"
)
REALM_USER_FEDERATED_IDENTITY = (
        BASE_ADMIN_REALMS + "/users/{user_id}/federated-identity/{provider}"
)

# ######################################################################
# Events
# ######################################################################

REALM_USER_EVENTS = BASE_ADMIN_REALMS + "/events"
REALM_ADMIN_EVENTS = BASE_ADMIN_REALMS + "/admin-events"
REALM_EVENTS_CONFIG = REALM_USER_EVENTS + "/config"
REALM_CLIENT_SESSION_STATS = BASE_ADMIN_REALMS + "/client-session-stats"

# ######################################################################
# Composite Roles
# ######################################################################

REALM_GROUPS_CLIENT_ROLES_COMPOSITE = REALM_GROUPS_CLIENT_ROLES + "/composite"
REALM_REALM_ROLE_COMPOSITES = BASE_ADMIN_REALMS + "/roles-by-id/{role_id}/composites"
REALM_REALM_ROLE_COMPOSITES_REALM = REALM_REALM_ROLE_COMPOSITES + "/realm"
REALM_CLIENT_ROLE_CHILDREN = REALM_REALM_ROLE_COMPOSITES + "/clients/{client_id}"

# ######################################################################
# Certificates
# ######################################################################

REALM_CLIENT_CERT_UPLOAD = REALM_CLIENT_CERTS + "/upload-certificate"

# ######################################################################
# Required Actions
# ######################################################################

REALM_REQUIRED_ACTIONS = BASE_ADMIN_REALMS + "/authentication/required-actions"
REALM_REQUIRED_ACTIONS_ALIAS = REALM_REQUIRED_ACTIONS + "/{action_alias}"

# ######################################################################
# Attack Detection
# ######################################################################

REALM_ATTACK_DETECTION = BASE_ADMIN_REALMS + "/attack-detection/brute-force/users"
REALM_ATTACK_DETECTION_USER = (
        BASE_ADMIN_REALMS + "/attack-detection/brute-force/users/{user_id}"
)

# ######################################################################
# Cache Clearing
# ######################################################################

REALM_CLEAR_KEYS_CACHE = BASE_ADMIN_REALMS + "/clear-keys-cache"
REALM_CLEAR_REALM_CACHE = BASE_ADMIN_REALMS + "/clear-realm-cache"
REALM_CLEAR_USER_CACHE = BASE_ADMIN_REALMS + "/clear-user-cache"
