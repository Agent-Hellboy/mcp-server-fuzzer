# Documentation Structure

This directory contains all documentation for the MCP Server Fuzzer project, organized into logical categories:

## Directory Structure

```
docs/
├── getting-started/          # Getting started guides and examples
│   ├── index.md             # Main project index
│   ├── getting-started.md   # Quick start guide
│   └── examples.md          # Usage examples
├── architecture/            # System architecture documentation
│   ├── architecture.md      # Overall architecture
│   ├── client-architecture.md
│   └── async-executor.md
├── components/              # Core component documentation
│   ├── process-management.md
│   ├── process-management-guide.md
│   ├── runtime-management.md
│   └── safety.md
├── configuration/           # Configuration and setup docs
│   ├── configuration.md
│   └── network-policy.md
├── transport/               # Transport layer documentation
│   ├── custom-transports.md
│   └── transport-improvements.md
├── development/             # Development and contribution docs
│   ├── contributing.md
│   ├── exceptions.md
│   ├── reference.md
│   └── standardized-output.md
├── testing/                 # Testing and quality assurance
│   └── fuzz-results.md      # Fuzzing test results
└── assets/                  # Static assets
    └── javascripts/
```

## Quick Navigation

- **New to the project?** Start with `getting-started/index.md`
- **Want to contribute?** Check `development/contributing.md`
- **Need configuration help?** See `configuration/configuration.md`
- **Looking for test results?** Check `testing/fuzz-results.md`

## Contributing to Documentation

When adding new documentation:
1. Choose the appropriate category directory
2. Follow the existing naming conventions
3. Update this README if adding new categories
4. Ensure proper cross-references between documents
