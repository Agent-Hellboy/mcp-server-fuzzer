# E2E Tests

This directory contains end-to-end (e2e) tests for the MCP Fuzzer. These tests are designed to validate that changes to the fuzzer don't break existing functionality by testing against real MCP servers.

## Overview

The e2e tests automatically:
1. Clone tested MCP server repositories
2. Build and start the servers
3. Run fuzzing tests against them
4. Generate reports and validate results
5. Clean up resources

## Available Tests

### `test_everything_server_docker.sh`
- **Server**: Everything MCP Server (Reference server covering prompts, resources, and tools)
- **Test Type**: Combined tools + protocol fuzzing
- **Expected**: High success rate with broad feature coverage
- **Duration**: ~2-4 minutes
 - **Environment**: Docker

### `test_mcp_server_chart.sh`
- **Server**: MCP Server Chart (Data visualization)
- **Tools**: 25 chart generation tools
- **Test Type**: Combined tools + protocol fuzzing
- **Expected**: Low success rate with comprehensive vulnerability detection
- **Duration**: ~3-5 minutes

## Usage

### Run Individual Tests

```bash
# Test Everything Server (Docker)
./tests/e2e/test_everything_server_docker.sh

# Test MCP Server Chart
./tests/e2e/test_mcp_server_chart.sh
```

### Run All E2E Tests

```bash
# From project root
./tests/e2e/run_all_e2e_tests.sh
```

## CI Integration

These tests are designed to run in CI environments. They include:

- **Automatic cleanup**: Resources are cleaned up even if tests fail
- **Exit codes**: Return appropriate exit codes for CI systems
- **Logging**: Comprehensive logging for debugging
- **Timeout handling**: Built-in timeouts to prevent hanging
- **Isolated execution**: Each test runs in isolation

## Test Results

### Expected Behavior

- **Everything MCP Server**: Should pass with high success rate
- **MCP Server Chart**: Should detect multiple vulnerabilities and exceptions

### Output

Each test generates:
- JSON reports in `/tmp/[server]_fuzz_[timestamp]/`
- Console output with test progress
- Success/failure indicators
- Performance metrics

## Adding New E2E Tests

To add a new MCP server to the e2e tests:

1. Create a new shell script: `test_[server_name].sh`
2. Follow the existing pattern:
   - Clone repository
   - Install dependencies
   - Build server
   - Start in background
   - Run fuzzing tests
   - Validate results
   - Clean up
3. Update this README
4. Add to `run_all_e2e_tests.sh`

## Requirements

- Node.js 18+
- npm
- git
- Python 3.13+
- MCP Fuzzer installed (`pip install -e .`)

## Troubleshooting

### Common Issues

1. **Server fails to start**: Check Node.js version and dependencies
2. **Fuzzing hangs**: Tests include timeout handling
3. **Permission issues**: Ensure proper file permissions
4. **Network issues**: Tests work offline after initial clone

### Debug Mode

Run with verbose output:
```bash
bash -x ./tests/e2e/test_everything_server_docker.sh
```

## Contributing

When modifying e2e tests:
- Keep tests isolated and independent
- Include proper error handling
- Update documentation
- Test in CI environment
- Follow existing patterns
