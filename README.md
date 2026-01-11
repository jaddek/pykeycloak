# PyKeycloak

PyKeycloak is a library for working with Keycloak that provides asynchronous methods for authentication, token management, and permission handling.

## Installation

For local development to install dependencies, use the following command:

```bash
make install
```

## Usage Examples

The library can be used in 3 different ways:

1. Make requests directly through the client
2. Use the provider to get response with content
3. Use the service to get either raw responses or Representation objects corresponding to the data received from Keycloak

### Core Entities

#### Payloads

- `TokenIntrospectionPayload` - Payload for token introspection containing the token.

- `RTPIntrospectionPayload` - Payload for token introspection inherited from `TokenIntrospectionPayload`, containing the token type.

- `ObtainTokenPayload` - Base class for obtaining a token, containing the scope and grant type.

- `UserCredentialsLoginPayload` - Payload for user authentication containing username and password.

- `ClientCredentialsLoginPayload` - Payload for client authentication used to obtain a client token.

- `RefreshTokenPayload` - Payload for refreshing a token containing the refresh token.

- `UMAAuthorizationPayload` - Payload for UMA authorization containing audience, permissions, and other parameters.

#### Providers

- `KeycloakProviderAsync` - Asynchronous provider for working with Keycloak that provides methods for authentication, token refresh, user information retrieval, logout, token introspection, device authentication, and certificate retrieval.

```python
from pykeycloak.providers.providers import KeycloakProviderAsync
from pykeycloak.core.entities import RealmClient

provider = KeycloakProviderAsync(
    realm="kc_realm",
    realm_client=RealmClient.from_env(),
)
```

#### Services

`AuthService` - Service that provides methods for authentication, token refresh, user information retrieval, logout, token introspection, device authentication, and certificate retrieval.

```python
from pykeycloak.services.services import AuthService

auth = AuthService(provider)
```

---

`UmaService` - Service that provides a method for obtaining UMA permissions.

```python
from pykeycloak.services.services import UmaService

uma = UmaService(provider)
```

#### Representations

Representations duplicate the data from Keycloak documentation based on the actual values they return.

`TokenRepresentation` - Representation of a token containing information about the access token, expiration time, scope, and token type.

`UserInfoRepresentation` - Representation of user information containing user data such as first name, last name, email address, and other attributes.

`RealmAccessRepresentation` - Representation of realm access containing user roles in the realm.

`IntrospectRepresentation` - Representation of token introspection result containing token information such as audience, expiration time, token type, and other attributes.

#### Client

`RealmClient` - Entity that stores realm data:

```python
import os
from pykeycloak.core.entities import RealmClient

RealmClient.from_env()

# or
RealmClient(
    client_id=os.getenv("KEYCLOAK_REALM_CLIENT_ID"),
    client_uuid=os.getenv("KEYCLOAK_REALM_CLIENT_UUID"),
    client_secret=os.getenv("KEYCLOAK_REALM_CLIENT_SECRET")
)
```

#### Sanitizer

Processes headers and request/response logs, hiding all critical information and marking it as hidden.

```python
import os
from pykeycloak.core.sanitizer import SensitiveDataSanitizer

SensitiveDataSanitizer.from_env()

SensitiveDataSanitizer(
    sensitive_keys=frozenset(os.getenv("EXTRA_SENSITIVE_KEYS", None))
)
```

### Client Initialization

To get started, you need to initialize the client using environment variables:

### User Authentication

To authenticate a user, use the `user_login_async` method:

```python
from pykeycloak.providers.payloads import UserCredentialsLoginPayload

token = await auth_service.user_login_async(
    payload=UserCredentialsLoginPayload(
        username=username,
        password=password,
    ))
```

### Token Refresh

To refresh a token, use the `refresh_token_async` method:

```python
from pykeycloak.providers.payloads import RefreshTokenPayload

refresh_token = await auth_service.refresh_token_async(
    payload=RefreshTokenPayload(refresh_token=token.refresh_token)
)
```

### Token Introspection

To introspect a token, use the `introspect_async` method:

```python
from pykeycloak.providers.payloads import TokenIntrospectionPayload

introspect = await auth_service.introspect_async(
    payload=TokenIntrospectionPayload(
        token=refresh.access_token,
    )
)
```

### UMA Permission Retrieval

To retrieve UMA permissions, use the `get_uma_permissions_async` method:

```python
from pykeycloak.providers.payloads import UMAAuthorizationPayload

permissions = await uma_service.get_uma_permissions_async(
    access_token=token.access_token, # user token
    payload=UMAAuthorizationPayload(
        audience=client.client_id,
        permissions={'/otago/users': ['view']}
    )
)
```

### User Information Retrieval

To retrieve user information, use the `get_user_info_async` method:

```python
user_info = await auth_service.get_user_info_async(
    access_token=refresh.access_token
)
```

### Logout

To log out, use the `logout_async` method:

```python
await auth_service.logout_async(refresh.refresh_token)
```

### Certificate Retrieval

To retrieve certificates, use the `get_certs_raw_async` method:

```python
certs = await auth_service.get_certs_raw_async()
```

## License

This project is licensed under the MIT License.
