# Standardized assessment output

The standardized output protocol is the machine-readable snapshot for a run.
Use it when an internal parser, dashboard, or CI job needs a stable envelope;
use `findings.json` and `run_summary.json` for the primary analyst workflow.

## File layout

When standardized output is emitted, the writer creates:

```text
reports/
└── sessions/
    └── <session-id>/
        ├── <timestamp>_fuzzing_results.json
        ├── <timestamp>_safety_summary.json
        └── <timestamp>_error_report.json
```

The exact files depend on the run and selected output types. The CLI currently
emits JSON files even when `--output-format` names another format. Additional
human-facing exports use `--export-csv`, `--export-xml`, `--export-html`, or
`--export-markdown`.

## Envelope

Every standardized output object has this shape:

```json
{
  "protocol_version": "1.0.0",
  "timestamp": "2026-08-06T12:00:00",
  "tool_version": "0.5.0",
  "session_id": "generated-session-id",
  "output_type": "fuzzing_results",
  "data": {},
  "metadata": {}
}
```

Consumers should validate `protocol_version` and branch on `output_type`.
Endpoints, generated inputs, responses, paths, and runtime observations inside
`data` may contain sensitive target information.

## Implemented output types

### `fuzzing_results`

Contains the selected mode and protocol, endpoint, per-tool results,
per-protocol-type results, and spec summary. Metadata includes execution time,
test count, success rate, and whether safety controls were active.

Typical fields:

```json
{
  "output_type": "fuzzing_results",
  "data": {
    "mode": "tools",
    "protocol": "streamablehttp",
    "endpoint": "https://target.example/mcp",
    "total_tools": 3,
    "tools_tested": [],
    "protocol_types_tested": [],
    "spec_summary": {}
  },
  "metadata": {
    "execution_time": "PT10S",
    "total_tests": 30,
    "success_rate": 80.0,
    "safety_enabled": true
  }
}
```

### `error_report`

Contains normalized errors, warnings, execution context, derived severity, and
whether a critical error was present. Error records can include server output
or generated data; restrict access accordingly.

### `safety_summary`

Contains whether the safety system was active, blocked-operation records, the
reported risk assessment, and safety statistics. A blocked operation is an
observation of the fuzzer boundary, not a final vulnerability classification.

## Reserved output types

`performance_metrics` and `configuration_dump` are defined by the protocol
model but are not emitted by the current standardized CLI writer. Do not build
production gates that assume they exist.

## CLI controls

```bash
# Values after --output-types are space-separated
mcp-fuzzer \
  --mode tools \
  --protocol streamablehttp \
  --endpoint https://target.example/mcp \
  --output-types fuzzing_results error_report safety_summary \
  --output-dir reports/standardized
```

The following options are accepted but currently not applied by the
standardized writer: `--output-format`, `--output-schema`, `--output-compress`,
and `--output-session-id`. Treat generated session IDs and JSON file names as
the current behavior.

## Consumer guidance

1. Confirm `protocol_version` and `output_type` before parsing `data`.
2. Treat unknown fields as forward-compatible additions.
3. Preserve `session_id`, target metadata, tool version, and timestamp with
   downstream records.
4. Do not treat `success_rate` as a security score; a rejected attack payload
   may be the expected secure behavior.
5. Keep raw artifacts private until response bodies, arguments, credentials,
   and runtime events are redacted.

For analyst triage, see [Interpret evidence and findings](../getting-started/results.md).

## Python integration

Maintainers and internal tooling can use the implementation modules directly:

```python
from mcp_fuzzer.reports.output_protocol import OutputProtocol

protocol = OutputProtocol(session_id="assessment-123")
output = protocol.create_base_output(
    "error_report",
    {"total_errors": 0, "total_warnings": 0, "errors": [], "warnings": []},
)
assert protocol.validate_output(output)
path = protocol.save_output(output, "reports")
```

The Python API is an implementation contract and may evolve independently of
the CLI envelope. Pin the project version when building a long-lived consumer.
