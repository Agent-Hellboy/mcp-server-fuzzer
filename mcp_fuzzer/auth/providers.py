import base64
from abc import ABC, abstractmethod
from typing import Any, Dict


class AuthProvider(ABC):
    @abstractmethod
    def get_auth_headers(self) -> Dict[str, str]:
        pass

    @abstractmethod
    def get_auth_params(self) -> Dict[str, Any]:
        pass


class APIKeyAuth(AuthProvider):
    def __init__(self, api_key: str, header_name: str = "Authorization"):
        self.api_key = api_key
        self.header_name = header_name

    def get_auth_headers(self) -> Dict[str, str]:
        return {self.header_name: f"Bearer {self.api_key}"}

    def get_auth_params(self) -> Dict[str, Any]:
        return {}


class BasicAuth(AuthProvider):
    def __init__(self, username: str, password: str):
        self.username = username
        self.password = password

    def get_auth_headers(self) -> Dict[str, str]:
        credentials = f"{self.username}:{self.password}"
        encoded = base64.b64encode(credentials.encode()).decode()
        return {"Authorization": f"Basic {encoded}"}

    def get_auth_params(self) -> Dict[str, Any]:
        return {}


class OAuthTokenAuth(AuthProvider):
    def __init__(self, token: str, token_type: str = "Bearer"):
        self.token = token
        self.token_type = token_type

    def get_auth_headers(self) -> Dict[str, str]:
        return {"Authorization": f"{self.token_type} {self.token}"}

    def get_auth_params(self) -> Dict[str, Any]:
        return {}


class CustomHeaderAuth(AuthProvider):
    def __init__(self, headers: Dict[str, str]):
        self.headers = dict(headers)

    def get_auth_headers(self) -> Dict[str, str]:
        return dict(self.headers)

    def get_auth_params(self) -> Dict[str, Any]:
        return {}


def create_api_key_auth(api_key: str, header_name: str = "Authorization") -> APIKeyAuth:
    return APIKeyAuth(api_key, header_name)


def create_basic_auth(username: str, password: str) -> BasicAuth:
    return BasicAuth(username, password)


def create_oauth_auth(token: str, token_type: str = "Bearer") -> OAuthTokenAuth:
    return OAuthTokenAuth(token, token_type)


def create_custom_header_auth(headers: Dict[str, str]) -> CustomHeaderAuth:
    return CustomHeaderAuth(headers)
