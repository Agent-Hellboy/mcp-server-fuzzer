Examples
========

This folder contains runnable examples to try the MCP fuzzer against simple local servers.

Run the basic test server
-------------------------

The server listens on http://localhost:8000 and exposes three tools:

- public `test_tool`
- public `echo_tool`
- protected `secure_tool` (requires Authorization: Bearer secret123)

Start the server:

```
python3 examples/test_server.py
```

You should see log lines like:

```
INFO:__main__:Test server started on http://localhost:8000
INFO:__main__:Available tools: test_tool, echo_tool
Press Ctrl+C to stop
```

Fuzz the server (no auth)
------------------------

Call the fuzzer in tools mode:

```
python3 -m mcp_fuzzer --mode tools --protocol http --endpoint http://localhost:8000 --runs 3 --timeout 5
```

This will fuzz all tools. Public tools succeed; `secure_tool` may return Unauthorized unless you provide auth headers.

Fuzz the protected tool with auth (config file)
----------------------------------------------

Use the provided `examples/auth_config.json` which maps `secure_tool` to an API key provider using the token `secret123`.

```
python3 -m mcp_fuzzer --mode tools --protocol http --endpoint http://localhost:8000 --runs 2 --timeout 5 --auth-config examples/auth_config.json
```

Fuzz the protected tool with auth (environment)
-----------------------------------------------

Set environment variables and run the fuzzer:

```
export MCP_API_KEY=secret123
export MCP_TOOL_AUTH_MAPPING='{"secure_tool":"api_key"}'
python3 -m mcp_fuzzer --mode tools --protocol http --endpoint http://localhost:8000 --runs 2 --timeout 5 --auth-env
```

Fuzz protocol types
-------------------

To fuzz protocol types instead of tools:

```
python3 -m mcp_fuzzer --mode protocol --protocol http --endpoint http://localhost:8000 --runs-per-type 2 --timeout 5
```

Notes
-----

- The example server is intentionally minimal and stateless.
- `secure_tool` requires `Authorization: Bearer secret123`. Use config file or env auth to hit it successfully.
- Stop the server with Ctrl+C.
