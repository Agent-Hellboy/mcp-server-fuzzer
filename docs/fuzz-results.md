# Famous Open Source MCP Server Fuzz Results

This section documents fuzzing results for popular open source MCP servers to help developers understand common vulnerabilities and security issues.

## DesktopCommanderMCP Server

**Repository:** [https://github.com/wonderwhy-er/DesktopCommanderMCP](https://github.com/wonderwhy-er/DesktopCommanderMCP)

**Description:** A comprehensive MCP server for terminal operations and file editing with advanced process management capabilities.

### Setup and Installation

```bash
# Clone the repository
git clone https://github.com/wonderwhy-er/DesktopCommanderMCP.git
cd DesktopCommanderMCP

# Install dependencies
npm install
### Fuzzing Commands Used

**Note:** The `--output-dir /tmp` flag should redirect output files to prevent workspace clutter, but there may be an implementation issue where some files still go to the default "reports" directory. As a workaround, you can manually clean up the reports directory after fuzzing:

```bash
# Clean up after fuzzing
rm -rf reports/
```

#### Basic Fuzzing (Without Safety System)
### Fuzzing Commands Used

**Note:** All commands include `--output-dir /tmp` to prevent creating unnecessary files and folders in your current directory. The fuzzer will still generate reports, but they'll be stored in the temporary directory instead of cluttering your workspace.

#### Basic Fuzzing (Without Safety System)

# Build the server
npm run build

# Verify the build
#### Clean Fuzzing (No File Creation)
```bash
# Run fuzzing without creating any files (redirects output to /tmp)
mcp-fuzzer --mode tools --protocol stdio --endpoint "node DesktopCommanderMCP/dist/index.js" --runs 5 --verbose --enable-safety-system --output-dir /tmp

# Run fuzzing with minimal output (no exports)
mcp-fuzzer --mode tools --protocol stdio --endpoint "node DesktopCommanderMCP/dist/index.js" --runs 5 --verbose --enable-safety-system --output-dir /tmp
```

#### Quick Test Commands (No Files Created)
#### Advanced Fuzzing (With Safety System Enabled)
```bash
# Run fuzzing with safety system enabled (recommended)
mcp-fuzzer --mode tools --protocol stdio --endpoint "node DesktopCommanderMCP/dist/index.js" --runs 5 --verbose --enable-safety-system --output-dir /tmp
```

#### Additional Fuzzing Options for Experimentation
```bash
# Fuzz with different phases
mcp-fuzzer --mode tools --protocol stdio --endpoint "node DesktopCommanderMCP/dist/index.js" --runs 10 --phase realistic --enable-safety-system --output-dir /tmp

# Fuzz with aggressive testing
mcp-fuzzer --mode tools --protocol stdio --endpoint "node DesktopCommanderMCP/dist/index.js" --runs 10 --phase aggressive --enable-safety-system --output-dir /tmp

# Generate detailed safety reports
mcp-fuzzer --mode tools --protocol stdio --endpoint "node DesktopCommanderMCP/dist/index.js" --runs 5 --enable-safety-system --safety-report --export-safety-data --output-dir /tmp
```
```bash
# Quick test without any file output
mcp-fuzzer --mode tools --protocol stdio --endpoint "node DesktopCommanderMCP/dist/index.js" --runs 1 --enable-safety-system --output-dir /tmp
**Test Environment:**
- **OS:** macOS Sequoia
- **Node.js:** v18+
- **MCP Fuzzer:** Latest version
- **Safety System:** Enabled with command blocking

**Known Issues:**
- The `--output-dir` flag may not fully redirect all output files (some may still go to default "reports" directory)
- Some process management tools may have connection issues that require investigation
- Workaround: Clean up reports directory after fuzzing with `rm -rf reports/`

# Silent fuzzing (no verbose output, no files)
mcp-fuzzer --mode tools --protocol stdio --endpoint "node DesktopCommanderMCP/dist/index.js" --runs 5 --enable-safety-system --output-dir /tmp
```
ls -la dist/
```

### Fuzzing Commands Used

#### Basic Fuzzing (Without Safety System)
```bash
# Install MCP Fuzzer
pip install mcp-fuzzer

# Run basic fuzzing without safety system
mcp-fuzzer --mode tools --protocol stdio --endpoint "node DesktopCommanderMCP/dist/index.js" --runs 5 --verbose
```

#### Advanced Fuzzing (With Safety System Enabled)
```bash
# Run fuzzing with safety system enabled (recommended)
mcp-fuzzer --mode tools --protocol stdio --endpoint "node DesktopCommanderMCP/dist/index.js" --runs 5 --verbose --enable-safety-system
```

#### Additional Fuzzing Options
```bash
# Fuzz with different phases
mcp-fuzzer --mode tools --protocol stdio --endpoint "node DesktopCommanderMCP/dist/index.js" --runs 10 --phase realistic --enable-safety-system

# Fuzz with aggressive testing
mcp-fuzzer --mode tools --protocol stdio --endpoint "node DesktopCommanderMCP/dist/index.js" --runs 10 --phase aggressive --enable-safety-system

# Generate detailed safety reports
mcp-fuzzer --mode tools --protocol stdio --endpoint "node DesktopCommanderMCP/dist/index.js" --runs 5 --enable-safety-system --safety-report --export-safety-data
```

### Prerequisites

- **Node.js:** v18.0.0 or higher
- **Python:** 3.8 or higher
- **MCP Fuzzer:** Latest version (`pip install mcp-fuzzer`)

**Server Details:**
- **Name:** DesktopCommanderMCP
- **Version:** 0.2.11
- **Protocol:** Stdio
- **Tools:** 23
- **Test Date:** 2025-09-07

**Fuzzing Configuration:**
- **Mode:** Tools
- **Runs per Tool:** 5
- **Safety System:** Enabled
- **Total Runs:** 115
# Famous Open Source MCP Server Fuzz Results

This section documents fuzzing results for popular open source MCP servers to help developers understand common vulnerabilities and security issues.

## DesktopCommanderMCP Server

**Server Details:**
- **Name:** DesktopCommanderMCP
- **Version:** 0.2.11
- **Protocol:** Stdio
- **Tools:** 23
- **Test Date:** 2025-09-07

**Fuzzing Configuration:**
- **Mode:** Tools
- **Runs per Tool:** 5
- **Safety System:** Enabled
- **Total Runs:** 115

**Results Summary:**

| Tool | Success Rate | Exceptions | Status |
|------|-------------|------------|--------|
| get_config | 100.0% | 0 | ✅ |
| set_config_value | 100.0% | 0 | ✅ |
| read_file | 100.0% | 0 | ✅ |
| read_multiple_files | 100.0% | 0 | ✅ |
| write_file | 100.0% | 0 | ✅ |
| create_directory | 100.0% | 0 | ✅ |
| list_directory | 100.0% | 0 | ✅ |
| move_file | 100.0% | 0 | ✅ |
| start_search | 100.0% | 0 | ✅ |
| get_more_search_results | 100.0% | 0 | ✅ |
| stop_search | 100.0% | 0 | ✅ |
| list_searches | 100.0% | 0 | ✅ |
| get_file_info | 100.0% | 0 | ✅ |
| edit_block | 100.0% | 0 | ✅ |
| start_process | 40.0% | 3 | ⚠️ |
| read_process_output | 80.0% | 1 | ⚠️ |
| interact_with_process | 100.0% | 0 | ✅ |
| force_terminate | 100.0% | 0 | ✅ |
| list_sessions | 100.0% | 0 | ✅ |
| list_processes | 100.0% | 0 | ✅ |
| kill_process | 100.0% | 0 | ✅ |
| get_usage_stats | 100.0% | 0 | ✅ |
| give_feedback_to_desktop_commander | 100.0% | 0 | ✅ |

**Overall Statistics:**
- **Total Tools Tested:** 23
- **Total Fuzzing Runs:** 115
- **Total Exceptions:** 4
- **Overall Success Rate:** 96.5%
- **Vulnerabilities Found:** 2

**Key Findings:**
1. **Process Management Issues:** `start_process` (60% failure rate) and `read_process_output` (20% failure rate) show connection-related issues
2. **Safety System Effectiveness:** The safety system successfully prevented dangerous operations and improved reliability
3. **File System Operations:** All file system tools performed flawlessly (100% success rate)
4. **Search Functionality:** All search-related tools worked perfectly

**Recommendations:**
- Investigate connection handling in process management tools
- Consider implementing retry mechanisms for connection-related failures
- The safety system significantly improves overall reliability

**Test Environment:**
- **OS:** macOS Sequoia
- **Node.js:** v18+
- **MCP Fuzzer:** Latest version
- **Safety System:** Enabled with command blocking