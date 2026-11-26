"""Measure WAN throughput for a UniFi gateway speed test."""

import json
import math
import os
from pathlib import Path
from selectors import DefaultSelector, EVENT_READ
import signal
import stat
import subprocess
import time


_MAX_OUTPUT = 4096
_MEASUREMENT_FIELDS = {"download_bps", "upload_bps", "latency_ms", "timestamp"}
_PHASES = ("download", "upload")


class SpeedTestError(ValueError):
    """The approved command did not yield a verifiable measurement."""


def _unique_fields(pairs):
    fields = dict(pairs)
    if len(fields) != len(pairs):
        raise ValueError("Duplicate measurement field")
    return fields


def _parse_measurement(raw, phase=None):
    try:
        value = json.loads(raw, object_pairs_hook=_unique_fields)
        fields = _MEASUREMENT_FIELDS - {"upload_bps"} if phase == "download" else _MEASUREMENT_FIELDS
        if type(value) is not dict or (phase and value.pop("phase", None) != phase) or value.keys() != fields:
            raise ValueError
        latency = value["latency_ms"]
        timestamp = value["timestamp"]
        if (type(timestamp) is not int or not 0 < timestamp < 1 << 53
                or type(latency) not in (int, float) or not 0 < latency < 1 << 31):
            raise ValueError
        result = {"ping": latency, "lastrun": timestamp}
        for direction in _PHASES:
            key = direction + "_bps"
            if key in value:
                rate = value[key]
                if type(rate) not in (int, float) or not math.isfinite(rate) or not 0 < rate < (1 << 31) * 1_000_000:
                    raise ValueError
                mbps = rate / 1_000_000
                if mbps == 0:
                    raise ValueError
                result[direction] = mbps
    except (OverflowError, ValueError, RecursionError):
        raise SpeedTestError("The WAN speed test returned an invalid measurement") from None
    return result


def _read_output(pipe, deadline):
    size = 0
    with DefaultSelector() as selector:
        selector.register(pipe, EVENT_READ)
        while selector.select(max(0, deadline - time.monotonic())):
            chunk = os.read(pipe.fileno(), _MAX_OUTPUT + 1 - size)
            if not chunk:
                return
            size += len(chunk)
            if size > _MAX_OUTPUT:
                raise SpeedTestError("The WAN speed test exceeded its output limit")
            yield chunk
    raise SpeedTestError("The WAN speed test timed out")


def _read_measurement(chunks, on_progress):
    output = bytearray()
    progress_count = 0
    run_at = None
    streaming = None
    for chunk in chunks:
        output.extend(chunk)
        while streaming is not False and progress_count < len(_PHASES):
            line, newline, rest = output.partition(b"\n")
            if not newline:
                break
            if streaming is None:
                if not line.strip():
                    output = rest
                    continue
                try:
                    first = json.loads(line)
                except (ValueError, RecursionError):
                    first = None
                streaming = isinstance(first, dict) and "phase" in first
                if not streaming:
                    break
            phase = _PHASES[progress_count]
            measurement = _parse_measurement(line, phase)
            if run_at is not None and run_at != measurement["lastrun"]:
                raise SpeedTestError("The WAN speed test changed its run timestamp")
            run_at = measurement["lastrun"]
            progress_count += 1
            output = rest
            if on_progress is not None:
                on_progress(phase, measurement)
    return output, progress_count, run_at


class WanSpeedTest:
    """Obtain a real measurement from a single fixed, no-argument executable."""

    def __init__(self, command, *, timeout=45):
        if type(timeout) not in (int, float) or not 0 < timeout <= 120:
            raise SpeedTestError("The WAN speed test timeout must be greater than 0 and at most 120 seconds")
        self._command = Path(command)
        self._timeout = timeout
        self._verify_command()

    def _verify_command(self):
        command = self._command
        owners = {0, os.geteuid()}
        if not command.is_absolute():
            raise SpeedTestError("The WAN speed test needs an absolute executable path")
        try:
            info = command.lstat()
            if (command.resolve(strict=True) != command or not stat.S_ISREG(info.st_mode)
                    or info.st_uid not in owners or info.st_mode & 0o022 or not os.access(command, os.X_OK)):
                raise SpeedTestError("The WAN speed test needs an owned executable with restricted permissions")
            for parent in command.parents:
                info = parent.stat()
                if info.st_uid not in owners or (info.st_mode & 0o022 and not info.st_mode & stat.S_ISVTX):
                    raise SpeedTestError("The WAN speed test executable directory is not trusted")
        except (OSError, RuntimeError):
            raise SpeedTestError("The WAN speed test executable is unavailable") from None

    def measure(self, *, on_progress=None):
        self._verify_command()
        deadline = time.monotonic() + self._timeout
        try:
            with subprocess.Popen([str(self._command)], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                  stderr=subprocess.DEVNULL, start_new_session=True) as process:
                try:
                    chunks = _read_output(process.stdout, deadline)
                    try:
                        output, progress_count, run_at = _read_measurement(chunks, on_progress)
                    finally:
                        chunks.close()
                    returncode = process.wait(timeout=max(0, deadline - time.monotonic()))
                except (TimeoutError, subprocess.TimeoutExpired, SpeedTestError, OSError):
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    except PermissionError:
                        if process.poll() is None:
                            raise
                    raise
        except subprocess.TimeoutExpired:
            raise SpeedTestError("The WAN speed test timed out") from None
        except OSError:
            raise SpeedTestError("The WAN speed test executable could not run") from None
        if returncode:
            raise SpeedTestError("The WAN speed test executable failed")
        result = _parse_measurement(output)
        if progress_count and (progress_count != len(_PHASES) or result["lastrun"] != run_at):
            raise SpeedTestError("The WAN speed test returned inconsistent progress and final results")
        return result
