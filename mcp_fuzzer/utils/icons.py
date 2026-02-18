"""
Lightweight icon/text helpers used to avoid heavy emoji dependency.
Using simple ASCII-ish tokens keeps output readable in all environments.
"""

CHECK = "[ok]"
CROSS = "[x]"
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
