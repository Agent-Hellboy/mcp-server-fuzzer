import base64
from abc import ABC, abstractmethod
from typing import Any


class AuthProvider(ABC):
    @abstractmethod
    def get_auth_headers(self) -> dict[str, str]:
        pass

    @abstractmethod
    def get_auth_params(self) -> dict[str, Any]:
        pass


class APIKeyAuth(AuthProvider):
    """API Key authentication with customizable header and prefix.

    Allows flexible API key formatting:
    - Default: Authorization: Bearer <api_key>
    - Custom header: X-API-Key: Bearer <api_key>
    - Custom prefix: Authorization: Token <api_key>
    - No prefix: X-API-Key: <api_key>
    """

    def __init__(
        self,
        api_key: str,
        header_name: str = "Authorization",
        prefix: str = "Bearer",
    ):
        self.api_key = api_key
        self.header_name = header_name
        self.prefix = prefix

    def get_auth_headers(self) -> dict[str, str]:
        if self.prefix:
            return {self.header_name: f"{self.prefix} {self.api_key}"}
        else:
            return {self.header_name: self.api_key}

    def get_auth_params(self) -> dict[str, Any]:
        return {}


class BasicAuth(AuthProvider):
    def __init__(self, username: str, password: str):
        self.username = username
        self.password = password

    def get_auth_headers(self) -> dict[str, str]:
        credentials = f"{self.username}:{self.password}"
        encoded = base64.b64encode(credentials.encode()).decode()
        return {"Authorization": f"Basic {encoded}"}

    def get_auth_params(self) -> dict[str, Any]:
        return {}


class OAuthTokenAuth(AuthProvider):
    """OAuth token authentication using Authorization header.

    OAuth tokens are always provided via HTTP Authorization header
    following RFC 6750 Bearer Token standard. They are NOT provided
    as URL parameters or request body parameters.

    Example:
        GET /resource HTTP/1.1
        Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
    """

    def __init__(self, token: str, token_type: str = "Bearer"):
        self.token = token
        self.token_type = token_type

    def get_auth_headers(self) -> dict[str, str]:
        """Return OAuth token as Authorization header."""
        return {"Authorization": f"{self.token_type} {self.token}"}

    def get_auth_params(self) -> dict[str, Any]:
        """OAuth tokens are NOT provided as parameters.

        Returns empty dict as per OAuth standard - tokens are always
        transmitted via Authorization header, never as URL/body parameters.
        """
        return {}


class CustomHeaderAuth(AuthProvider):
    def __init__(self, headers: dict[str, str]):
        self.headers = dict(headers)

    def get_auth_headers(self) -> dict[str, str]:
        return dict(self.headers)

    def get_auth_params(self) -> dict[str, Any]:
        return {}


def create_api_key_auth(
    api_key: str,
    header_name: str = "Authorization",
    prefix: str = "Bearer",
) -> APIKeyAuth:
    return APIKeyAuth(api_key, header_name, prefix)


def create_basic_auth(username: str, password: str) -> BasicAuth:
    return BasicAuth(username, password)


def create_oauth_auth(token: str, token_type: str = "Bearer") -> OAuthTokenAuth:
    return OAuthTokenAuth(token, token_type)


def create_custom_header_auth(headers: dict[str, str]) -> CustomHeaderAuth:
    return CustomHeaderAuth(headers)
