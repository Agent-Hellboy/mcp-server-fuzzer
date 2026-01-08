#!/bin/bash
set -e

echo "🚀 MCP Server Fuzzer - Push Branches Script"
echo "=========================================="
echo ""

# Check if gh is authenticated
if ! gh auth status > /dev/null 2>&1; then
    echo "⚠️  GitHub CLI not authenticated. Please run:"
    echo "   gh auth login"
    echo ""
    exit 1
fi

echo "✅ GitHub CLI authenticated"
echo ""

# Array of branches to push
branches=(
    "fix/issue-102-implement-todo-initialize-request"
    "fix/issue-57-add-changelog"
    "fix/issue-108-auth-documentation"
)

# Push each branch
for branch in "${branches[@]}"; do
    echo "📤 Pushing branch: $branch"
    if git push -u origin "$branch"; then
        echo "✅ Successfully pushed $branch"
    else
        echo "❌ Failed to push $branch"
        exit 1
    fi
    echo ""
done

echo "=========================================="
echo "✅ All branches pushed successfully!"
echo ""
echo "Next steps:"
echo "1. Run: python3 scripts/create_prs.py"
echo "   OR"
echo "2. Visit: https://github.com/Agent-Hellboy/mcp-server-fuzzer/pulls"
echo "   to create PRs manually"
echo ""
