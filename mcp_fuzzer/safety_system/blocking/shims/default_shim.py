#!/usr/bin/env python3
import sys
import os
import json
from datetime import datetime

try:
    import emoji

    HAS_EMOJI = True
except ImportError:
    HAS_EMOJI = False

LOG_FILE = "<<<LOG_FILE>>>"


def main() -> None:
    command_name = os.path.basename(sys.argv[0])
    args = " ".join(sys.argv[1:]) if len(sys.argv) > 1 else ""

    if HAS_EMOJI:
        prohibited = emoji.emojize(":prohibited:")
        shield = emoji.emojize(":shield:")
    else:
        prohibited = "[X]"
        shield = "[*]"

    print(
        f"{prohibited} [FUZZER BLOCKED] {command_name} {args}",
        file=sys.stderr,
    )
    print(
        (
            f"{shield} Command '{command_name}' was blocked to "
            "prevent external app launch during fuzzing. This is a safety feature."
        )
    )

    if LOG_FILE:
        try:
            log_entry = {
                "timestamp": datetime.now().isoformat(),
                "command": command_name,
                "args": args,
                "full_command": f"{command_name} {args}".strip(),
            }
            with open(LOG_FILE, "a") as fh:
                fh.write(json.dumps(log_entry) + "\n")
        except Exception:
            pass

    sys.exit(0)


if __name__ == "__main__":
    main()
