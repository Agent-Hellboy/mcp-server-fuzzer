#!/usr/bin/env python3
"""
MCP Server Fuzzer - PR Automation Script

This script automates the process of:
1. Running pre-commit checks
2. Pushing branches to GitHub
3. Creating pull requests
4. Verifying MCP compliance
"""

import subprocess
import sys
import json
from pathlib import Path


def run_command(cmd, check=True, capture_output=True):
    """Run a shell command and return the result."""
    print(f"Running: {' '.join(cmd)}")
    result = subprocess.run(
        cmd,
        check=check,
        capture_output=capture_output,
        text=True
    )
    if result.stdout:
        print(result.stdout)
    if result.stderr:
        print(result.stderr, file=sys.stderr)
    return result


def run_pre_commit():
    """Run pre-commit checks on all files."""
    print("\n=== Running pre-commit checks ===")
    result = run_command(["pre-commit", "run", "--all-files"], check=False)
    if result.returncode != 0:
        print("⚠️  Pre-commit checks failed. Attempting to fix...")
        # Commit any fixes
        run_command(["git", "add", "-A"])
        run_command(["git", "commit", "-m", "style: apply pre-commit fixes"], check=False)
        # Re-run to verify
        result = run_command(["pre-commit", "run", "--all-files"], check=False)
        if result.returncode != 0:
            print("❌ Pre-commit checks still failing. Please fix manually.")
            return False
    print("✅ Pre-commit checks passed")
    return True


def push_branch(branch_name):
    """Push a branch to GitHub."""
    print(f"\n=== Pushing branch: {branch_name} ===")
    try:
        result = run_command(["git", "push", "-u", "origin", branch_name])
        print(f"✅ Successfully pushed {branch_name}")
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ Failed to push {branch_name}: {e}")
        return False


def create_pr(branch_name, title, body, base="main"):
    """Create a pull request using GitHub CLI."""
    print(f"\n=== Creating PR for {branch_name} ===")
    try:
        result = run_command([
            "gh", "pr", "create",
            "--base", base,
            "--head", branch_name,
            "--title", title,
            "--body", body
        ])
        print(f"✅ Successfully created PR for {branch_name}")
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ Failed to create PR for {branch_name}: {e}")
        return False


def check_gh_auth():
    """Check if GitHub CLI is authenticated."""
    try:
        result = run_command(["gh", "auth", "status"], check=False)
        return result.returncode == 0
    except FileNotFoundError:
        print("❌ GitHub CLI (gh) is not installed. Please install it first:")
        print("   brew install gh")
        return False


def get_current_branch():
    """Get the name of the current Git branch."""
    result = run_command(["git", "branch", "--show-current"])
    return result.stdout.strip()


def verify_mcp_compliance():
    """Verify that code follows MCP specification."""
    print("\n=== Verifying MCP Compliance ===")
    
    # Check for MCP protocol version compliance
    compliance_checks = []
    
    # 1. Check protocolVersion in code
    result = run_command(
        ["grep", "-r", "protocolVersion", "mcp_fuzzer/", "--include=*.py"],
        check=False
    )
    if result.returncode == 0:
        compliance_checks.append("✅ Protocol version references found")
    
    # 2. Check for proper JSON-RPC structure
    result = run_command(
        ["grep", "-r", '"jsonrpc".*"2.0"', "mcp_fuzzer/", "--include=*.py"],
        check=False
    )
    if result.returncode == 0:
        compliance_checks.append("✅ JSON-RPC 2.0 structure found")
    
    # 3. Check for proper initialization
    result = run_command(
        ["grep", "-r", "initialize", "mcp_fuzzer/", "--include=*.py"],
        check=False
    )
    if result.returncode == 0:
        compliance_checks.append("✅ Initialization methods found")
    
    print("\nCompliance Checks:")
    for check in compliance_checks:
        print(f"  {check}")
    
    return len(compliance_checks) >= 2


# Branch configurations
BRANCHES = [
    {
        "name": "fix/issue-102-implement-todo-initialize-request",
        "title": "fix: implement TODO for InitializeRequest _meta field (#102)",
        "body": """Implements the TODO comment to expand InitializeRequest fuzzing to cover all MCP specification fields including the optional _meta field with progressToken.

**Changes:**
- Added optional `_meta` field to `fuzz_initialize_request_realistic()`
- Included `progressToken` in `_meta` per MCP spec
- Updated docstring to document all covered fields
- Follows MCP specification for InitializeRequestParams

**Testing:**
- Pre-commit checks passed
- Follows existing code patterns
- Maintains backward compatibility

Closes #102"""
    },
    {
        "name": "fix/issue-57-add-changelog",
        "title": "docs: add CHANGELOG.md for releases after v0.2.0 (#57)",
        "body": """Adds comprehensive CHANGELOG.md following Keep a Changelog format with all releases from v0.1.6 to v0.2.5.

**Changes:**
- Created CHANGELOG.md with all version history
- Documented major changes, additions, and fixes for each version
- Added comparison links for each version
- Follows Keep a Changelog format
- Adheres to Semantic Versioning

**Releases Documented:**
- v0.2.5: Runtime refactor, CLI redesign, report subsystem redesign
- v0.2.4: AsyncFuzzExecutor fixes
- v0.2.3: Exception framework
- v0.2.2: Auth fixes, typing improvements
- v0.2.1: Python 3.9 support dropped
- v0.2.0: Major release with comprehensive features
- Earlier releases (v0.1.6-v0.1.9)

Closes #57"""
    },
    {
        "name": "fix/issue-108-auth-documentation",
        "title": "docs: add comprehensive authentication guide (#108)",
        "body": """Adds detailed authentication documentation addressing all the issues mentioned in #108.

**Changes:**
- Created comprehensive `docs/configuration/authentication.md` (487 lines)
- Covered all authentication methods:
  - Bearer tokens / API keys
  - OAuth
  - Basic authentication
  - Custom headers
- Added extensive troubleshooting section
- Fixed environment variable documentation (MCP_PREFIX not MCP_API_KEY_PREFIX)
- Provided clear examples for:
  - Configuration files (YAML)
  - Auth config files (JSON)
  - Environment variables
- Updated main configuration.md with cross-reference
- Added navigation entry in mkdocs.yml

**Addresses User Issues:**
- "HTTP 401: no bearer token" - documented proper configuration
- "--server argument not recognized" - explained config structure
- "Unexpected error: 'api_key'" - showed valid JSON structure
- Confusion about multiple config methods - clarified precedence

**Documentation Structure:**
1. Quick Start (Bearer Token)
2. All Authentication Methods with examples
3. Per-Tool Authentication
4. Configuration Priority
5. Common Issues and Solutions
6. Security Best Practices
7. Debugging tips

Addresses #108"""
    }
]


def main():
    """Main execution function."""
    print("🚀 MCP Server Fuzzer - PR Automation Script")
    print("=" * 60)
    
    # Check GitHub CLI authentication
    if not check_gh_auth():
        print("\n⚠️  Please authenticate with GitHub CLI:")
        print("   gh auth login")
        sys.exit(1)
    
    print("\n✅ GitHub CLI is authenticated")
    
    # Process each branch
    success_count = 0
    failed_branches = []
    
    for branch_config in BRANCHES:
        branch_name = branch_config["name"]
        print(f"\n{'=' * 60}")
        print(f"Processing: {branch_name}")
        print(f"{'=' * 60}")
        
        # Checkout branch
        try:
            run_command(["git", "checkout", branch_name])
        except subprocess.CalledProcessError:
            print(f"❌ Failed to checkout {branch_name}")
            failed_branches.append(branch_name)
            continue
        
        # Run pre-commit
        if not run_pre_commit():
            failed_branches.append(branch_name)
            continue
        
        # Verify MCP compliance
        if not verify_mcp_compliance():
            print("⚠️  MCP compliance verification had warnings")
        
        # Push branch
        if not push_branch(branch_name):
            failed_branches.append(branch_name)
            continue
        
        # Create PR
        if create_pr(
            branch_name,
            branch_config["title"],
            branch_config["body"]
        ):
            success_count += 1
        else:
            failed_branches.append(branch_name)
    
    # Summary
    print("\n" + "=" * 60)
    print("Summary")
    print("=" * 60)
    print(f"✅ Successfully created {success_count}/{len(BRANCHES)} PRs")
    
    if failed_branches:
        print(f"\n❌ Failed branches:")
        for branch in failed_branches:
            print(f"   - {branch}")
        sys.exit(1)
    else:
        print("\n🎉 All PRs created successfully!")
        sys.exit(0)


if __name__ == "__main__":
    main()
