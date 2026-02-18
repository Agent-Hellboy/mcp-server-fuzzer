"""Lightweight icon/text helpers used across CLI and reporters.

All values are plain ASCII to avoid emoji rendering differences and keep
outputs consistent across terminals and Rich/markdown renderers.
"""

CHECK = "OK"
CROSS = "X"
ALERT = "ALERT"
SHIELD = "SHIELD"
BLOCKED = "BLOCKED"
UNLOCKED = "UNLOCKED"
TARGET = "TARGET"
ROCKET = "ROCKET"
STATS = "STATS"

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
