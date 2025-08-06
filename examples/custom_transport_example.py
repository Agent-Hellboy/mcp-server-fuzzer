#!/usr/bin/env python3
"""
Example showing how to implement custom transport protocols for the MCP fuzzer.
"""

import asyncio
from typing import Any, Dict, Optional

from mcp_fuzzer.transport import TransportProtocol


class CustomGRPCTransport(TransportProtocol):
    """Example custom transport using gRPC."""

    def __init__(self, server_address: str, port: int = 50051):
        self.server_address = server_address
        self.port = port
        # You would initialize gRPC client here
        # self.grpc_client = grpc_client_initialization()

    async def send_request(
        self, method: str, params: Optional[Dict[str, Any]] = None
    ) -> Any:
        """Send request via gRPC."""
        # Custom gRPC implementation
        # payload = {
        #     "method": method,
        #     "params": params or {}
        # }

        # Example gRPC call (pseudo-code)
        # response = await self.grpc_client.call(payload)
        # return response

        # For demo purposes, just return a mock response
        return {"result": f"gRPC response for {method}"}


class CustomRedisTransport(TransportProtocol):
    """Example custom transport using Redis pub/sub."""

    def __init__(self, redis_url: str, channel: str = "mcp"):
        self.redis_url = redis_url
        self.channel = channel
        # You would initialize Redis client here
        # self.redis_client = redis_client_initialization()

    async def send_request(
        self, method: str, params: Optional[Dict[str, Any]] = None
    ) -> Any:
        """Send request via Redis pub/sub."""
        # payload = {
        #     "method": method,
        #     "params": params or {}
        # }

        # Example Redis pub/sub implementation
        # await self.redis_client.publish(self.channel, json.dumps(payload))
        # response = await self.redis_client.subscribe(f"response_{method}")
        # return json.loads(response)

        # For demo purposes, just return a mock response
        return {"result": f"Redis response for {method}"}


class CustomWebhookTransport(TransportProtocol):
    """Example custom transport using webhooks."""

    def __init__(self, webhook_url: str, api_key: str):
        self.webhook_url = webhook_url
        self.api_key = api_key
        self.headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json"
        }

    async def send_request(
        self, method: str, params: Optional[Dict[str, Any]] = None
    ) -> Any:
        """Send request via webhook."""
        # payload = {
        #     "method": method,
        #     "params": params or {}
        # }

        # For demo purposes, just return a mock response
        # In real implementation, you would make the HTTP call:
        # async with httpx.AsyncClient() as client:
        #     response = await client.post(
        #         self.webhook_url,
        #         json=payload,
        #         headers=self.headers
        #     )
        #     response.raise_for_status()
        #     return response.json()

        return {"result": f"Webhook response for {method}"}


# Example of extending the factory function
def create_custom_transport(protocol: str, endpoint: str, **kwargs) -> TransportProtocol:
    """Extended factory function with custom transports."""
    if protocol == "grpc":
        return CustomGRPCTransport(endpoint, **kwargs)
    elif protocol == "redis":
        return CustomRedisTransport(endpoint, **kwargs)
    elif protocol == "webhook":
        return CustomWebhookTransport(endpoint, **kwargs)
    else:
        # Fall back to original factory
        from mcp_fuzzer.transport import create_transport
        return create_transport(protocol, endpoint, **kwargs)


async def demo_custom_transports():
    """Demonstrate custom transport usage."""
    print("🚀 Custom Transport Protocol Examples")
    print("=" * 50)

    # Example 1: gRPC Transport
    grpc_transport = CustomGRPCTransport("localhost:50051")
    result = await grpc_transport.send_request("tools/list")
    print(f"gRPC Transport Result: {result}")

    # Example 2: Redis Transport
    redis_transport = CustomRedisTransport("redis://localhost:6379")
    result = await redis_transport.send_request("tools/call", {"name": "test"})
    print(f"Redis Transport Result: {result}")

    # Example 3: Webhook Transport
    webhook_transport = CustomWebhookTransport(
        "https://api.example.com/mcp",
        "your-api-key"
    )
    result = await webhook_transport.send_request("initialize")
    print(f"Webhook Transport Result: {result}")


if __name__ == "__main__":
    asyncio.run(demo_custom_transports())
