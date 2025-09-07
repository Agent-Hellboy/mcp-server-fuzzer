# System Tests

This directory contains end-to-end system tests for the MCP Fuzzer. These tests are designed to validate that changes to the fuzzer don't break existing functionality by testing against real MCP servers.

## Overview

The system tests automatically:
1. Clone tested MCP server repositories
2. Build and start the servers
3. Run fuzzing tests against them
4. Generate reports and validate results
5. Clean up resources

## Available Tests

### `test_desktop_commander_mcp.sh`
- **Server**: DesktopCommanderMCP (File system and process management)
- **Tools**: 23 file system and process management tools
- **Test Type**: Tool fuzzing only
- **Expected**: High success rate (96.5%)
- **Duration**: ~2-3 minutes

### `test_mcp_server_chart.sh`
- **Server**: MCP Server Chart (Data visualization)
- **Tools**: 25 chart generation tools
- **Test Type**: Combined tools + protocol fuzzing
- **Expected**: Low success rate with comprehensive vulnerability detection
- **Duration**: ~3-5 minutes

## Usage

### Run Individual Tests

```bash
# Test DesktopCommanderMCP
./tests/system/test_desktop_commander_mcp.sh

# Test MCP Server Chart
./tests/system/test_mcp_server_chart.sh
```

### Run All System Tests

```bash
# From project root
./tests/system/run_all_system_tests.sh
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

- **DesktopCommanderMCP**: Should pass with high success rate
- **MCP Server Chart**: Should detect multiple vulnerabilities and exceptions

### Output

Each test generates:
- JSON reports in `/tmp/[server]_fuzz_[timestamp]/`
- Console output with test progress
- Success/failure indicators
- Performance metrics

## Adding New System Tests

To add a new MCP server to the system tests:

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
4. Add to `run_all_system_tests.sh`

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
bash -x ./tests/system/test_desktop_commander_mcp.sh
```

## Contributing

When modifying system tests:
- Keep tests isolated and independent
- Include proper error handling
- Update documentation
- Test in CI environment
- Follow existing patterns