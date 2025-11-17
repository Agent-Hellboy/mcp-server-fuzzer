# MCP Fuzzer Error Codes

The MCP Fuzzer surfaces every user-facing failure through numbered error codes.
Each code follows the `CCTTT` format:

- `CC` (two digits) identifies the category (e.g., `10` for Transport, `20` for Auth)
- `TTT` (three digits) identifies the specific error within that category

This keeps diagnostics easy to scan while preserving enough room for future error
types. Refer to the table below for the current registry.

| Code  | Category  | Description                                        |
|-------|-----------|----------------------------------------------------|
| 10001 | Transport | Transport failure                                  |
| 10002 | Transport | Unable to establish connection with the server     |
| 10003 | Transport | Malformed or unexpected server response            |
| 10004 | Transport | Authentication with the server failed              |
| 10005 | Transport | Network connectivity or policy failure             |
| 10006 | Transport | Invalid transport payload                          |
| 10007 | Transport | Transport registration or selection error          |
| 20001 | Auth      | Authentication subsystem error                     |
| 20002 | Auth      | Authentication configuration is invalid            |
| 20003 | Auth      | Authentication provider is misconfigured           |
| 30001 | Timeout   | Operation timed out                                |
| 30002 | Timeout   | Subprocess execution timed out                     |
| 30003 | Timeout   | Network request timed out                          |
| 40001 | Safety    | Safety policy violated                             |
| 40002 | Safety    | Network access blocked by safety policy            |
| 40003 | Safety    | System command blocked by safety policy            |
| 40004 | Safety    | Filesystem access blocked by safety policy         |
| 50001 | Server    | Server returned an error                           |
| 50002 | Server    | Server is unavailable or not responding            |
| 50003 | Server    | Protocol negotiation failed                        |
| 60001 | CLI       | CLI error                                          |
| 60002 | CLI       | Invalid CLI arguments                              |
| 70001 | Reporting | Reporting error                                    |
| 70002 | Reporting | Report validation failed                           |
| 80001 | Config    | Configuration error                                |
| 80002 | Config    | Configuration file could not be read               |
| 80003 | Config    | Configuration validation failed                    |
| 90001 | Fuzzing   | Fuzzing engine error                               |
| 90002 | Fuzzing   | Fuzzing strategy failed                            |
| 90003 | Fuzzing   | Async executor encountered an error                |
| 95001 | Runtime   | Runtime management error                           |
| 95002 | Runtime   | Failed to start managed process                    |
| 95003 | Runtime   | Failed to stop managed process                     |
| 95004 | Runtime   | Failed to send process signal                      |
| 95005 | Runtime   | Process registration failed                        |
| 95006 | Runtime   | Process watchdog failed to start                   |

Each exception class in `mcp_fuzzer/exceptions.py` sets its `code` and
`description` fields so CLI output, logs, and structured reports can reference
these values. Use `MCPError.to_metadata()` or `get_error_registry()` to fetch
the mapping programmatically.
