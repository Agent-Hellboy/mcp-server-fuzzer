# Automate repeatable assessment evidence

CI is useful for repeatable regression evidence when the job owns the target,
credentials, network boundary, and artifact retention. It is not a substitute
for authorization or analyst review.

```mermaid
flowchart LR
    T[Start disposable target] --> F[Run bounded assessment]
    F --> V{Usable target?}
    V -->|No| X[Fail or quarantine job]
    V -->|Yes| A[Upload restricted artifacts]
    A --> R[Review findings policy]
    R --> G[Gate, record, or continue]
```

## A minimal pipeline

Run against a local test target or an endpoint explicitly owned by the job:

```yaml
- name: Assess MCP server
  run: |
    mcp-fuzzer \
      --mode all \
      --protocol streamablehttp \
      --endpoint http://127.0.0.1:8000/mcp \
      --phase aggressive \
      --security-audit \
      --fail-if-no-tools \
      --runs 10 \
      --seed 42 \
      --output-dir reports/mcp-fuzzer

- name: Upload restricted assessment evidence
  uses: actions/upload-artifact@v4
  with:
    name: mcp-fuzzer-evidence
    path: reports/mcp-fuzzer/
    retention-days: 7
```

Use a private artifact store and a retention period appropriate to the
engagement. Do not make raw response artifacts public by default.

## Decide what fails the job

The fuzzer provides exit behavior for target usability, not a universal risk
policy:

- `--fail-if-no-tools` exits non-zero (code 2) when discovery yields no usable
  tools, including an unreachable or auth-blocked target. It is enabled
  automatically when `MCP_FUZZER_CI` or `MCP_FUZZER_IN_DOCKER` is set.
- `--allow-empty-tools` opts out of the automatic CI/Docker behavior when a
  zero-tool fixture is expected.
- Findings never fail the build on their own. There is no severity-threshold
  flag; a findings gate is something the job implements by reading the
  artifacts.
- Keep a blocked assessment distinct from a completed assessment with no
  findings.

Gate on the two fields the artifacts actually expose: `status` and
`findings.by_category` in `run_summary.json`.

```bash
# Fail the job on a blocked target or on a named finding category.
python - <<'PY'
import json, sys
summary = json.load(open("reports/mcp-fuzzer/run_summary.json"))
if summary["status"] != "completed":
    sys.exit(f"blocked assessment: {summary.get('blocked_reason', 'unknown')}")
gated = {"accepted_malformed", "injection_reflection"}
hits = {k: v for k, v in summary["findings"]["by_category"].items() if k in gated}
if hits:
    sys.exit(f"gated findings present: {hits}")
PY
```

Read `findings.json` when the policy needs per-finding `severity` (emitted
lowercase) or the `evidence.check_id` carried by `--security-audit` findings.

Avoid a policy that fails on every server rejection. A correct rejection of a
malformed request is generally validation evidence; accepted malformed input,
unexpected side effects, sensitive output, crashes, and reproducible security
signals need analyst interpretation.

## Local stdio jobs

Run local servers in disposable containers or runners. Add the fuzzer safety
controls as a second boundary:

```bash
mcp-fuzzer \
  --mode tools \
  --protocol stdio \
  --endpoint "python my_server.py" \
  --enable-safety-system \
  --fs-root "$PWD/ci-fuzz-sandbox" \
  --no-network \
  --security-audit \
  --fail-if-no-tools \
  --runs 10 \
  --output-dir reports/mcp-fuzzer
```

Use `--allow-host` only for destinations required by the test. If runtime
behavior is in scope, enable `--runtime-probe` in a Linux runner with explicit
workspace, temporary-directory, executable, and host policies. Runtime probing
is separate from normal fuzzing and does not monitor remote transports.

## Authenticated and intrusive jobs

Use dedicated, short-lived credentials. Prefer a restricted auth file or CI
secret injection; never commit client secrets or tokens to the repository.

Run `--auth-audit` in a read-only job first. Place
`--auth-audit-intrusive` in a separate, explicitly authorized job because it
can create dynamic-registration state and exercise redirect handling. Do not
point that job at production.

## Artifact review checklist

Before a human or downstream system consumes the artifact:

- Confirm `run_summary.json` reports a completed, comparable assessment.
- Review `findings.json` and the exact evidence behind each candidate.
- Preserve `crashes/` only when the target owner permits the captured data.
- Redact credentials, tokens, private paths, personal data, and server secrets.
- Record the target revision, schema version, command line, seed, and
  configuration hash alongside the artifacts. The fuzzer does not write these
  into `run_summary.json` or `findings.json`, so the job must capture them.
- Link the artifact to the assessment scope and reviewer decision.

See [Interpret evidence and findings](getting-started/results.md) for the
analyst-side triage model.
