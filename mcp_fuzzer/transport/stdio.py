import asyncio
import json
import uuid
import logging
import os
import shlex
import subprocess
import signal as _signal
import sys
from typing import Any, Dict, Optional

from .base import TransportProtocol


class StdioTransport(TransportProtocol):
    def __init__(self, command: str, timeout: float = 30.0):
        self.command = command
        self.timeout = timeout

    async def send_request(
        self, method: str, params: Optional[Dict[str, Any]] = None
    ) -> Any:
        payload = {
            "jsonrpc": "2.0",
            "id": str(uuid.uuid4()),
            "method": method,
            "params": params or {},
        }
        process = await asyncio.create_subprocess_exec(
            *shlex.split(self.command),
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            preexec_fn=os.setsid if sys.platform != "win32" else None,
            creationflags=(
                subprocess.CREATE_NEW_PROCESS_GROUP if sys.platform == "win32" else 0
            ),
        )
        stdin_data = json.dumps(payload).encode() + b"\n"
        try:
            stdout, stderr = await asyncio.wait_for(
                process.communicate(stdin_data), timeout=self.timeout
            )
        except (KeyboardInterrupt, asyncio.CancelledError, asyncio.TimeoutError):
            try:
                if sys.platform == "win32":
                    try:
                        process.send_signal(_signal.CTRL_BREAK_EVENT)  # type: ignore[attr-defined]
                    except (AttributeError, ValueError):
                        process.kill()
                else:
                    pgid = os.getpgid(process.pid)
                    os.killpg(pgid, _signal.SIGKILL)
            except OSError:
                pass
            try:
                await process.wait()
            except Exception:
                pass
            raise

        if process.returncode != 0:
            logging.error(
                "Process failed with return code %d: %s",
                process.returncode,
                stderr.decode(),
            )
            raise Exception(f"Process failed: {stderr.decode()}")

        stdout_text = stdout.decode()
        try:
            lines = stdout_text.strip().split("\n")
            main_response = None
            for line in lines:
                line = line.strip()
                if not line:
                    continue
                try:
                    json_obj = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if isinstance(json_obj, dict) and (
                    "result" in json_obj or "error" in json_obj
                ):
                    main_response = json_obj
                    break
            if main_response is None:
                raise json.JSONDecodeError("No main response found", stdout_text, 0)
            if "error" in main_response:
                raise Exception(f"Server error: {main_response['error']}")
            return main_response.get("result", main_response)
        except json.JSONDecodeError:
            logging.error("Failed to parse response as JSON: %s", stdout_text)
            raise

    async def send_raw(self, payload: Dict[str, Any]) -> Any:
        process = await asyncio.create_subprocess_exec(
            *shlex.split(self.command),
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            preexec_fn=os.setsid if sys.platform != "win32" else None,
            creationflags=(
                subprocess.CREATE_NEW_PROCESS_GROUP if sys.platform == "win32" else 0
            ),
        )
        stdin_data = json.dumps(payload).encode() + b"\n"
        try:
            stdout, stderr = await asyncio.wait_for(
                process.communicate(stdin_data), timeout=self.timeout
            )
        except (KeyboardInterrupt, asyncio.CancelledError, asyncio.TimeoutError):
            try:
                if sys.platform == "win32":
                    try:
                        process.send_signal(_signal.CTRL_BREAK_EVENT)  # type: ignore[attr-defined]
                    except (AttributeError, ValueError):
                        process.kill()
                else:
                    pgid = os.getpgid(process.pid)
                    os.killpg(pgid, _signal.SIGKILL)
            except OSError:
                pass
            try:
                await process.wait()
            except Exception:
                pass
            raise
        if process.returncode != 0:
            logging.error(
                "Process failed with return code %d: %s",
                process.returncode,
                stderr.decode(),
            )
            raise Exception(f"Process failed: {stderr.decode()}")
        stdout_text = stdout.decode()
        try:
            lines = stdout_text.strip().split("\n")
            main_response = None
            for line in lines:
                line = line.strip()
                if not line:
                    continue
                try:
                    json_obj = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if isinstance(json_obj, dict) and (
                    "result" in json_obj or "error" in json_obj
                ):
                    main_response = json_obj
                    break
            if main_response is None:
                raise json.JSONDecodeError("No main response found", stdout_text, 0)
            if "error" in main_response:
                raise Exception(f"Server error: {main_response['error']}")
            return main_response.get("result", main_response)
        except json.JSONDecodeError:
            logging.error("Failed to parse response as JSON: %s", stdout_text)
            raise

    async def send_notification(
        self, method: str, params: Optional[Dict[str, Any]] = None
    ) -> None:
        payload = {"jsonrpc": "2.0", "method": method, "params": params or {}}
        process = await asyncio.create_subprocess_exec(
            *shlex.split(self.command),
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            preexec_fn=os.setsid if sys.platform != "win32" else None,
            creationflags=(
                subprocess.CREATE_NEW_PROCESS_GROUP if sys.platform == "win32" else 0
            ),
        )
        stdin_data = json.dumps(payload).encode() + b"\n"
        try:
            stdout, stderr = await asyncio.wait_for(
                process.communicate(stdin_data), timeout=self.timeout
            )
        except (KeyboardInterrupt, asyncio.CancelledError, asyncio.TimeoutError):
            try:
                if sys.platform == "win32":
                    try:
                        process.send_signal(_signal.CTRL_BREAK_EVENT)  # type: ignore[attr-defined]
                    except (AttributeError, ValueError):
                        process.kill()
                else:
                    pgid = os.getpgid(process.pid)
                    os.killpg(pgid, _signal.SIGKILL)
            except OSError:
                pass
            try:
                await process.wait()
            except Exception:
                pass
            raise
        if process.returncode != 0:
            logging.error(
                "Notification subprocess failed with return code %d: %s",
                process.returncode,
                (stderr or b"").decode(),
            )
            raise Exception(f"Notification process failed: {(stderr or b'').decode()}")
