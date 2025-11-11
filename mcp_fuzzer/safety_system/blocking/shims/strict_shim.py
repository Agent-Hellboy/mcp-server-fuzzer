#!/usr/bin/env python3
import sys
import os
import json
from datetime import datetime

LOG_FILE = "<<<LOG_FILE>>>"


def main() -> None:
    command_name = os.path.basename(sys.argv[0])
    args = sys.argv[1:]
    entry = {
        "command": command_name,
        "args": args,
        "timestamp": datetime.now().isoformat(),
    }

    if LOG_FILE:
        try:
            with open(LOG_FILE, "a") as fh:
                fh.write(json.dumps(entry) + "\n")
        except Exception:
            pass

    print(
        f"[BLOCKED] Command '{command_name}' was blocked by MCP Fuzzer safety system",
        file=sys.stderr,
    )
    sys.exit(1)


if __name__ == "__main__":
    main()
