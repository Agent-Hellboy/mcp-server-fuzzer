# Standardized Output Format

The MCP Fuzzer implements a standardized output format with a mini-protocol for tool communication. This provides machine-readable, structured output that can be easily processed by other tools and integrated into CI/CD pipelines.

## Overview

The standardized output format provides:

- **Structured JSON Schema**: Consistent format across all output types
- **Versioned Protocol**: Protocol versioning for future compatibility
- **Machine Readable**: Easily parseable by scripts and other tools
- **Extensible**: Support for adding new output types without breaking existing parsers
- **Validated**: Schema validation ensures output integrity

## Protocol Structure

All standardized outputs follow this base structure:

```json
{
  "protocol_version": "1.0.0",
  "timestamp": "2024-01-01T00:00:00Z",
  "tool_version": "0.1.6",
  "session_id": "uuid-string",
  "output_type": "fuzzing_results|error_report|safety_summary|performance_metrics|configuration_dump",
  "data": {
    // Type-specific data structure
  },
  "metadata": {
    // Additional context and statistics
  }
}
```

### Field Descriptions

- `protocol_version`: Version of the output protocol (currently "1.0.0")
- `timestamp`: ISO 8601 timestamp when the output was generated
- `tool_version`: Version of the MCP Fuzzer tool
- `session_id`: Unique identifier for the fuzzing session
- `output_type`: Type of output (see [Output Types](#output-types))
- `data`: Type-specific structured data
- `metadata`: Additional context and summary statistics

## Output Types

### Fuzzing Results

Contains comprehensive fuzzing results including tool and protocol test outcomes.

```json
{
  "protocol_version": "1.0.0",
  "timestamp": "2024-01-01T00:00:00Z",
  "tool_version": "0.1.6",
  "session_id": "550e8400-e29b-41d4-a716-446655440000",
  "output_type": "fuzzing_results",
  "data": {
    "mode": "tools|protocol|resources|prompts|all",
    "protocol": "http|sse|stdio|streamablehttp",
    "endpoint": "server_endpoint_url",
    "total_tools": 5,
    "total_protocol_types": 3,
    "tools_tested": [
      {
        "name": "example_tool",
        "runs": 10,
        "successful": 8,
        "exceptions": 2,
        "safety_blocked": 0,
        "success_rate": 80.0,
        "exceptions": [
          {
            "type": "ValueError",
            "message": "Invalid argument format",
            "arguments": {"param": "malformed_data"}
          }
        ]
      }
    ],
    "protocol_types_tested": [
      {
        "type": "InitializeRequest",
        "runs": 5,
        "successful": 5,
        "errors": 0,
        "success_rate": 100.0
      }
    ]
  },
  "metadata": {
    "execution_time": "PT2M30S",
    "total_tests": 50,
    "success_rate": 80.0,
    "safety_enabled": true
  }
}
```

### Error Report

Contains detailed error information and warnings from the fuzzing session.

```json
{
  "protocol_version": "1.0.0",
  "timestamp": "2024-01-01T00:00:00Z",
  "tool_version": "0.1.6",
  "session_id": "550e8400-e29b-41d4-a716-446655440000",
  "output_type": "error_report",
  "data": {
    "total_errors": 2,
    "total_warnings": 1,
    "errors": [
      {
        "type": "tool_error",
        "tool_name": "dangerous_tool",
        "run_number": 1,
        "severity": "high",
        "message": "Command injection detected",
        "arguments": {"cmd": "rm -rf /"}
      }
    ],
    "warnings": [
      {
        "type": "config_warning",
        "message": "Timeout value is very low"
      }
    ],
    "execution_context": {
      "mode": "tools",
      "endpoint": "http://localhost:8000"
    }
  },
  "metadata": {
    "error_severity": "high",
    "has_critical_errors": false
  }
}
```

### Safety Summary

Contains safety system statistics and blocked operations.

```json
{
  "protocol_version": "1.0.0",
  "timestamp": "2024-01-01T00:00:00Z",
  "tool_version": "0.1.6",
  "session_id": "550e8400-e29b-41d4-a716-446655440000",
  "output_type": "safety_summary",
  "data": {
    "safety_system_active": true,
    "total_operations_blocked": 3,
    "blocked_operations": [
      {
        "tool_name": "file_operations",
        "reason": "File system access blocked",
        "arguments": {"path": "/etc/passwd"},
        "timestamp": "2024-01-01T10:00:00Z"
      }
    ],
    "risk_assessment": "medium",
    "safety_statistics": {
      "total_operations_blocked": 3,
      "unique_tools_blocked": 2,
      "most_blocked_tool": "file_operations",
      "most_blocked_tool_count": 2
    }
  },
  "metadata": {
    "safety_enabled": true,
    "total_blocked": 3,
    "unique_tools_blocked": 2
  }
}
```

### Performance Metrics

Contains timing and resource usage data.

```json
{
  "protocol_version": "1.0.0",
  "timestamp": "2024-01-01T00:00:00Z",
  "tool_version": "0.1.6",
  "session_id": "550e8400-e29b-41d4-a716-446655440000",
  "output_type": "performance_metrics",
  "data": {
    "metrics": {
      "total_execution_time": "PT5M30S",
      "average_response_time": "PT0.5S",
      "memory_peak_usage": "150MB",
      "cpu_usage_percent": 75.5
    },
    "benchmarks": {
      "tools_per_second": 2.1,
      "requests_per_second": 45.8
    }
  },
  "metadata": {
    "collection_timestamp": "2024-01-01T00:00:00Z",
    "metrics_count": 4
  }
}
```

### Configuration Dump

Contains the current tool configuration state.

```json
{
  "protocol_version": "1.0.0",
  "timestamp": "2024-01-01T00:00:00Z",
  "tool_version": "0.1.6",
  "session_id": "550e8400-e29b-41d4-a716-446655440000",
  "output_type": "configuration_dump",
  "data": {
    "configuration": {
      "mode": "tools",
      "protocol": "http",
      "endpoint": "http://localhost:8000",
      "timeout": 30.0,
      "runs": 10
    },
    "source": "runtime"
  },
  "metadata": {
    "config_keys_count": 5,
    "dump_timestamp": "2024-01-01T00:00:00Z"
  }
}
```

## CLI Options

### Basic Output Control

```bash
# Generate specific output types
mcp-fuzzer --output-types fuzzing_results,error_report --output-format json

# Use custom output schema
mcp-fuzzer --output-schema ./custom_schema.json

# Compress output files
mcp-fuzzer --output-compress

# Custom session ID
mcp-fuzzer --output-session-id my-session-123
```

### Configuration File

Output settings can be configured via YAML configuration file:

```yaml
output:
  format: json
  directory: ./output
  compression: true
  types:
    - fuzzing_results
    - error_report
    - safety_summary
  schema: ./schemas/output_v1.json
  retention:
    days: 30
    max_size: "1GB"
```

## File Organization

### Directory Structure

```
output/
├── sessions/
│   └── {session_id}/
│       ├── 20240101_000000_fuzzing_results.json
│       ├── 20240101_000001_error_report.json
│       └── 20240101_000002_safety_summary.json
└── reports/
    ├── daily/
    ├── weekly/
    └── monthly/
```

### Naming Conventions

- **Session-based**: `{timestamp}_{session_id}_{type}.{format}`
- **Time-based**: `{date}_{type}_{summary}.{format}`
- **Custom**: User-defined naming patterns

Example filenames:
- `20240101_000000_550e8400-e29b-41d4-a716-446655440000_fuzzing_results.json`
- `2024-01-01_fuzzing_summary.json`

## Schema Validation

All outputs are validated against the protocol schema before saving. Invalid outputs will raise a `ValidationError`.

```python
from mcp_fuzzer.reports.output import OutputProtocol

protocol = OutputProtocol()
output = protocol.create_fuzzing_results_output(...)

if protocol.validate_output(output):
    filepath = protocol.save_output(output, "./output")
```

## Integration Examples

### CI/CD Pipeline Integration

```bash
#!/bin/bash
# Run fuzzing and generate standardized output
mcp-fuzzer --mode all --output-types fuzzing_results,error_report --output-format json

# Parse results in CI/CD
python -c "
import json
with open('output/sessions/*/fuzzing_results.json') as f:
    data = json.load(f)
    success_rate = data['metadata']['success_rate']
    if success_rate < 80:
        exit(1)
"
```

### Python Integration

```python
from mcp_fuzzer.reports.output import OutputManager

# Create output manager
manager = OutputManager("./output")

# Generate and save results
filepath = manager.save_fuzzing_results(
    mode="tools",
    protocol="http",
    endpoint="http://localhost:8000",
    tool_results=tool_results,
    protocol_results=protocol_results,
    execution_time="PT30S",
    total_tests=100,
    success_rate=85.0
)

# Parse results
import json
with open(filepath) as f:
    data = json.load(f)
    print(f"Success rate: {data['metadata']['success_rate']}%")
```

### Monitoring Dashboard

```python
import json
from pathlib import Path

def parse_fuzzing_results(filepath):
    with open(filepath) as f:
        data = json.load(f)

    return {
        "session_id": data["session_id"],
        "timestamp": data["timestamp"],
        "success_rate": data["metadata"]["success_rate"],
        "total_tests": data["metadata"]["total_tests"],
        "tools_tested": len(data["data"]["tools_tested"])
    }

# Process all results
results = []
for file in Path("./output/sessions").rglob("*fuzzing_results.json"):
    results.append(parse_fuzzing_results(file))
```

## Future Enhancements

### Version 2.0 Considerations

- **Streaming Output**: Real-time output streaming
- **Binary Formats**: Protocol buffers, MessagePack
- **Database Integration**: Direct database output
- **API Endpoints**: HTTP API for output retrieval
- **WebSocket Support**: Real-time output streaming

### Plugin System

- **Custom Output Handlers**: User-defined output processors
- **Format Converters**: Convert between output formats
- **Output Filters**: Selective data inclusion/exclusion
- **Custom Schemas**: User-defined output schemas

## Troubleshooting

### Common Issues

1. **Schema Validation Errors**
   - Ensure all required fields are present
   - Check data types match the schema
   - Verify output_type is valid

2. **File Permission Issues**
   - Ensure output directory is writable
   - Check file system permissions

3. **Configuration Not Applied**
   - Verify configuration file syntax
   - Check configuration file path
   - Ensure CLI options take precedence over config file

### Debug Mode

Enable debug logging to troubleshoot output generation:

```bash
mcp-fuzzer --verbose --log-level DEBUG --output-types fuzzing_results
```

## OutputProtocol Schema (External Tooling)

The canonical JSON schema for OutputProtocol lives at:

```
schemas/output_v1.json
```

Top-level fields are:

- `protocol_version` (string, `1.0.0`)
- `timestamp` (RFC 3339 date-time)
- `tool_version` (string)
- `session_id` (string)
- `output_type` (enum: `fuzzing_results`, `error_report`, `safety_summary`, `performance_metrics`, `configuration_dump`)
- `data` (object payload per output type)
- `metadata` (object with execution/run metadata)

Each `output_type` maps to a data payload:

- `fuzzing_results`: mode, protocol, endpoint, tool/protocol summaries, spec summary, and `security_summary` (oracle findings/policy violation counts aggregated per control domain).
- `error_report`: list of errors + warnings, execution context.
- `safety_summary`: blocked operations, safety statistics, risk assessment.
- `performance_metrics`: metrics and benchmarks.
- `configuration_dump`: resolved configuration snapshot.

## API Reference

### OutputProtocol

- `create_base_output(output_type, data, metadata)`: Create base output structure
- `create_fuzzing_results_output(..., security_summary=None)`: Create fuzzing results output with optional security summary
- `create_error_report_output(...)`: Create error report output
- `create_safety_summary_output(...)`: Create safety summary output
- `validate_output(output)`: Validate output against schema
- `save_output(output, output_dir, filename, compress)`: Save output to file

### OutputManager

- `save_fuzzing_results(..., security_summary=None)`: Save fuzzing results with optional security summary
- `save_error_report(...)`: Save error report
- `save_safety_summary(...)`: Save safety summary
- `get_session_directory(session_id)`: Get session directory path
- `list_session_outputs(session_id)`: List output files for session

See the [API documentation](reference.md) for complete method signatures and parameters.
