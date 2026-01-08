# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.5] - 2025-11-30

### Changed
- Refactored runtime management system (#132)
  - Improved process lifecycle management
  - Enhanced watchdog and monitoring capabilities
- Redesigned CLI and client architecture (#135)
  - Better separation of concerns
  - Improved dependency injection
  - Enhanced modularity
- Redesigned report subsystem (#128)
  - Modular formatters architecture
  - Better output management
  - Improved report collection

### Added
- Design pattern review references to README and contributing guide (#127)

## [0.2.4] - 2025-11-28

### Fixed
- AsyncFuzzExecutor documentation to match implementation (#116)
- Blocking issues in async executor

### Changed
- Updated project documentation

## [0.2.3] - 2025-11-25

### Added
- Exception framework for better error reporting (#114)
  - Structured exception hierarchy
  - Improved error messages
  - Better error tracking

## [0.2.2] - 2025-11-23

### Fixed
- Authentication configuration issues (#108, #111)
  - Improved bearer token handling
  - Better error messages for auth failures
  - Enhanced auth documentation
- Critical typing issues causing import failures
- HTTP transport typing issues
- Optional dict parameter annotations
- Process status return type annotation

### Added
- Dynamic version fetching from package metadata (#106)
- Project icon to README

### Changed
- Improved overall code maintainability (#109)
- Updated typing annotations for Python 3.10+ compatibility

## [0.2.1] - 2025-11-20

### Removed
- Python 3.9 support (#99)
  - Minimum Python version is now 3.10

### Changed
- Updated dependencies for Python 3.10+

## [0.2.0] - 2025-11-18

### Major Release
This release represents a significant milestone in the project with comprehensive improvements to architecture, testing, and safety systems.

### Added
- Multi-protocol transport support (HTTP, SSE, Stdio, StreamableHTTP)
- Built-in safety system with pattern-based filtering
- Two-phase fuzzing (realistic + aggressive)
- Comprehensive reporting with multiple output formats (JSON, CSV, HTML, Markdown, XML)
- Asynchronous execution engine with configurable concurrency
- Process watchdog and timeout handling
- Authentication support (API keys, basic auth, OAuth)
- Configuration file support (YAML/TOML)
- Environment variable configuration
- Performance metrics and benchmarking
- Schema validation for MCP protocol compliance

### Changed
- Complete architectural redesign with modular components
- Improved CLI interface with better argument handling
- Enhanced error handling and reporting
- Better resource management and cleanup

### Fixed
- Various stability and reliability improvements
- Memory leak fixes
- Connection handling improvements

## [0.1.9] - 2025-11-10

### Changed
- Pre-release improvements
- Bug fixes and stability enhancements

## [0.1.8] - 2025-11-05

### Added
- Additional fuzzing strategies
- Enhanced test coverage

## [0.1.7] - 2025-11-01

### Fixed
- Bug fixes and performance improvements

## [0.1.6] - 2025-10-28

### Added
- Initial protocol fuzzing support
- Basic transport implementations

[Unreleased]: https://github.com/Agent-Hellboy/mcp-server-fuzzer/compare/v0.2.5...HEAD
[0.2.5]: https://github.com/Agent-Hellboy/mcp-server-fuzzer/compare/v0.2.4...v0.2.5
[0.2.4]: https://github.com/Agent-Hellboy/mcp-server-fuzzer/compare/v0.2.3...v0.2.4
[0.2.3]: https://github.com/Agent-Hellboy/mcp-server-fuzzer/compare/v0.2.2...v0.2.3
[0.2.2]: https://github.com/Agent-Hellboy/mcp-server-fuzzer/compare/v0.2.1...v0.2.2
[0.2.1]: https://github.com/Agent-Hellboy/mcp-server-fuzzer/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/Agent-Hellboy/mcp-server-fuzzer/compare/v0.1.9...v0.2.0
[0.1.9]: https://github.com/Agent-Hellboy/mcp-server-fuzzer/compare/v0.1.8...v0.1.9
[0.1.8]: https://github.com/Agent-Hellboy/mcp-server-fuzzer/compare/v0.1.7...v0.1.8
[0.1.7]: https://github.com/Agent-Hellboy/mcp-server-fuzzer/compare/v0.1.6...v0.1.7
[0.1.6]: https://github.com/Agent-Hellboy/mcp-server-fuzzer/releases/tag/v0.1.6
