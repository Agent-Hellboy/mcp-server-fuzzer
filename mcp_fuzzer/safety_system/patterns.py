"""Safety patterns and configurations for MCP Fuzzer."""

# Default patterns for detecting dangerous content
DEFAULT_DANGEROUS_URL_PATTERNS = [
    r"https?://",  # Any HTTP/HTTPS URL - CRITICAL to block
    r"ftp://",  # FTP URLs
    r"file://",  # File URLs
    r"www\.",  # Common web URLs
    r"[a-zA-Z0-9-]+\.(com|org|net|edu|gov|mil|int|co\.uk|de|fr|jp|cn)",
]

DEFAULT_DANGEROUS_COMMAND_PATTERNS = [
    # Browser/app launching commands
    r"xdg-open",  # Linux open command
    r"open\s+",  # macOS open command
    r"start\s+",  # Windows start command
    r"cmd\s+/c\s+start",  # Windows cmd start
    r"explorer\.exe",  # Windows explorer
    r"rundll32",  # Windows rundll32
    # Browser executables
    r"(firefox|chrome|chromium|safari|edge|opera|brave)\.exe",
    r"(firefox|chrome|chromium|safari|edge|opera|brave)$",
    # System executables that could launch apps
    r"\.exe\s*$",
    r"\.app/Contents/MacOS/",
    r"\.app\s*$",
    r"\.dmg\s*$",
    r"\.msi\s*$",
    # System modification commands
    r"sudo\s+",
    r"rm\s+-rf",
    r"format\s+",
    r"del\s+/[sq]",
    r"shutdown",
    r"reboot",
    r"halt",
]

DEFAULT_DANGEROUS_ARGUMENT_NAMES = [
    "url",
    "link",
    "uri",
    "href",
    "website",
    "webpage",
    "browser",
    "application",
    "app",
    "executable",
    "exec",
    "path",
    "file_path",
    "filepath",
    "command",
    "cmd",
]
