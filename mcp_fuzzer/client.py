import json
import logging
import uuid
from typing import Any, Dict, List, Optional

import httpx


def jsonrpc_request(
    url: str, method: str, params: Optional[Dict[str, Any]] = None
) -> Any:
    """Make a JSON-RPC request to the MCP server."""
    request_id = str(uuid.uuid4())
    payload = {
        "jsonrpc": "2.0",
        "id": request_id,
        "method": method,
        "params": params or {},
    }

    headers = {
        "Accept": "application/json, text/event-stream",
        "Content-Type": "application/json",
    }

    try:
        response = httpx.post(url, json=payload, headers=headers, timeout=30.0)
        response.raise_for_status()

        # Try to parse as JSON first
        try:
            data = response.json()
        except json.JSONDecodeError:
            # If not JSON, try to parse as SSE
            logging.info("Response is not JSON, trying to parse as SSE")
            for line in response.text.splitlines():
                if line.startswith("data:"):
                    try:
                        data = json.loads(line[len("data:") :].strip())
                        break
                    except json.JSONDecodeError:
                        logging.error("Failed to parse SSE data line as JSON")
                        raise
            else:
                logging.error("No valid data: line found in SSE response")
                raise Exception("Invalid SSE response format")

        if "error" in data:
            logging.error("Server returned error: %s", data["error"])
            raise Exception(f"Server error: {data['error']}")
        # If the payload is a full JSON-RPC envelope keep existing behaviour,
        # otherwise fall back to the raw object (covers SSE streams that send
        # only the result).
        return data.get("result", data)
    except httpx.HTTPError:
        logging.error("HTTP error during request")
        raise
    except json.JSONDecodeError:
        logging.error("Raw response: %s", response.text)
        raise


def get_tools_from_server(url: str) -> List[Dict[str, Any]]:
    """Fetch the list of tools and their schemas from the MCP server using JSON-RPC."""
    try:
        response = jsonrpc_request(url, "tools/list")
        logging.info("Raw server response: %s", response)

        if not isinstance(response, dict):
            logging.warning(
                "Server response is not a dictionary. Got type: %s", type(response)
            )
            return []

        if "tools" not in response:
            logging.warning(
                "Server response missing 'tools' key. Keys present: %s",
                list(response.keys()),
            )
            return []

        tools = response["tools"]
        logging.info("Found %d tools from server", len(tools))
        return tools

    except Exception as e:
        logging.exception("Failed to fetch tools from server: %s", e)
        return []
        logging.warning("Error fetching tools list: %s", str(e))
        return []
