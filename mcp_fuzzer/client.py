import json
import uuid
from typing import Any

import httpx


def jsonrpc_request(url: str, method: str, params: dict = None, id: Any = None):
    """Send a JSON-RPC 2.0 request and return the response."""
    if id is None:
        id = str(uuid.uuid4())
    payload = {
        "jsonrpc": "2.0",
        "id": id,
        "method": method,
        "params": params or {},
    }
    headers = {
        "Accept": "application/json, text/event-stream",
        "Content-Type": "application/json",
    }
    resp = httpx.post(url, json=payload, headers=headers)
    resp.raise_for_status()
    try:
        # Try to parse as JSON first (in case server returns plain JSON)
        return resp.json()
    except Exception:
        # Fallback: parse as SSE and extract the JSON from the data: line
        for line in resp.text.splitlines():
            if line.startswith("data:"):
                data_json = line[len("data:") :].strip()
                return json.loads(data_json)
        print("Server response was not valid JSON or SSE with data:")
        print(resp.text)
        raise
