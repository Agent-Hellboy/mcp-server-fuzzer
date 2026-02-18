"""Lightweight icon/text helpers used across CLI and reporters."""

# Markdown and terminal render well with these Unicode markers; tests rely on them.
CHECK = "✔"
CROSS = "❌"
ALERT = "[alert]"
SHIELD = "[shield]"
BLOCKED = "[blocked]"
UNLOCKED = "[unlocked]"
TARGET = "[target]"
ROCKET = "[rocket]"
STATS = "[stats]"

__all__ = [
    "CHECK",
    "CROSS",
    "ALERT",
    "SHIELD",
    "BLOCKED",
    "UNLOCKED",
    "TARGET",
    "ROCKET",
    "STATS",
]
