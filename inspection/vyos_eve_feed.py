"""Bounded, verified records from the stock engine's private EVE append file."""

import json
import os
import re
from dataclasses import dataclass, replace
from uuid import uuid4

from inspection.eve_source import (
    MAX_RECORD_BYTES,
    _ALERT_HEADER,
    _clean_alert,
    _completed_flow,
    _flow_key,
    _invalid_constant,
    _unique_fields,
)
from inspection.supervisor import InspectionControlError
from inspection.suricata import decode_eve_event

EVE_FILE = "eve.json"
MAX_GENERATIONS = 8
RESPONSE_LIMIT = 4096
_MAX_OFFSET = (1 << 63) - 1
_MAX_SCAN_BYTES = 2 * MAX_RECORD_BYTES
_MAX_ROWS = 128
_GENERATION_ID = re.compile(r"[0-9a-f]{32}", re.ASCII)
_MARKER_RULE = (1, 1000043, 1, "UXG isolated post-policy marker")


def _position(value):
    return type(value) is int and 0 <= value <= _MAX_OFFSET


def _id(value):
    return type(value) is str and _GENERATION_ID.fullmatch(value) is not None


def valid_cursor(value):
    return value is None or (
        type(value) is dict
        and value.keys() == {"generation", "offset"}
        and _id(value["generation"])
        and _position(value["offset"])
    )


@dataclass(frozen=True, slots=True)
class EveGeneration:
    id: str
    mode: str
    device: int
    inode: int
    offset: int
    end: int | None = None

    def __post_init__(self):
        if (
            not _id(self.id) or self.mode not in ("block", "notify")
            or not _position(self.device) or type(self.inode) is not int or self.inode <= 0
            or not _position(self.offset)
            or self.end is not None and (not _position(self.end) or self.end < self.offset)
        ):
            raise ValueError("Invalid inspection EVE generation")

    def owns(self, info):
        return (self.device, self.inode) == (info.st_dev, info.st_ino)


def read_generations(items):
    if type(items) is not list or len(items) > MAX_GENERATIONS:
        raise ValueError("Invalid inspection EVE generation history")
    generations = tuple(EveGeneration(**item) for item in items)
    if len({item.id for item in generations}) != len(generations):
        raise ValueError("Duplicate inspection EVE generation")
    for older, newer in zip(generations, generations[1:]):
        if (
            older.end is None
            or (older.device, older.inode) == (newer.device, newer.inode)
            and older.end > newer.offset
        ):
            raise ValueError("Overlapping inspection EVE generations")
    return generations


def _file_info(files):
    descriptor = files.open(EVE_FILE, os.O_RDONLY)
    try:
        return os.fstat(descriptor)
    finally:
        os.close(descriptor)


def start_generation(files, history, mode):
    try:
        info = _file_info(files)
    except FileNotFoundError:
        files.write(EVE_FILE, b"")
        info = _file_info(files)
    if history and history[-1].end is None:
        history = _seal(history, info)
    history = tuple(item for item in history if not item.owns(info) or item.end <= info.st_size)
    return (*history[-(MAX_GENERATIONS - 1):], EveGeneration(
        uuid4().hex, mode, info.st_dev, info.st_ino, info.st_size,
    ))


def _seal(history, info):
    last = history[-1]
    end = info.st_size if info is not None and last.owns(info) else last.offset
    return (*history[:-1], replace(last, end=max(last.offset, end)))


def seal_generation(files, history):
    if not history or history[-1].end is not None:
        return history
    try:
        info = _file_info(files)
    except (OSError, InspectionControlError):
        info = None
    return _seal(history, info)


def feed_response(status, generation=None, offset=0, record=None):
    return {"schema": 1, "phase": "read-events", "status": status,
            "generation": generation, "offset": offset, "record": record}


def _record(raw, scope, mode):
    try:
        event = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_fields,
                           parse_constant=_invalid_constant)
        if type(event) is not dict:
            return None
        _, protocol, source, sport, destination, port = _flow_key(event)
        if (
            protocol != "TCP" or sport == 0 or str(source) != scope.initiator.host
            or str(destination) != scope.responder.host or port != scope.server_port
        ):
            return None
        if event["event_type"] == "flow":
            flow, _, _ = _completed_flow(event)
            return event, {
                **{name: event[name] for name in _ALERT_HEADER},
                "flow": {**flow, "end": event["flow"]["end"], "alerted": True},
            }
        decoded = decode_eve_event(event)
        verdict, action = ("drop", "blocked") if mode == "block" else ("alert", "allowed")
        if decoded is None or decoded.verdict != verdict or event.get("verdict", {}).get("action") != verdict:
            return None
        rule = event["alert"]
        if (
            (rule["gid"], rule["signature_id"], rule["rev"], rule.get("signature")) != _MARKER_RULE
            or rule.get("action") != action or rule.get("category") != ""
        ):
            return None
        return event, _clean_alert(event, decoded)
    except (ValueError, KeyError, OverflowError, RecursionError):
        return None


def _usable(generation, info):
    return (
        generation.owns(info)
        and info.st_size >= (generation.end if generation.end is not None else generation.offset)
    )


def _read_at(stream, generation, offset, end, advance, scope, notify_proof):
    def idle():
        if offset == end and generation.end is not None and advance is not None:
            return advance
        return feed_response("idle", generation.id, offset)

    if not generation.offset <= offset <= end:
        return feed_response("gap")
    if offset > generation.offset:
        stream.seek(offset - 1)
        if stream.read(1) != b"\n":
            return feed_response("gap")
    stream.seek(offset)
    remaining = _MAX_SCAN_BYTES
    for _ in range(_MAX_ROWS):
        if offset == end:
            return idle()
        room = min(remaining, end - offset)
        if room == 0:
            break
        data = stream.readline(min(room, MAX_RECORD_BYTES + 1))
        if len(data) > MAX_RECORD_BYTES:
            return feed_response("gap")
        if not data.endswith(b"\n"):
            if generation.end is not None and offset + len(data) == end:
                if advance is not None:
                    return {**advance, "status": "gap"}
                return feed_response("gap")
            break
        item = _record(data, scope, generation.mode)
        if item is not None:
            raw, record = item
            forwarded = False
            if generation.mode == "notify" and record["event_type"] == "alert":
                forwarded = notify_proof(generation, raw)
                if forwarded is None:
                    return idle()
            if generation.mode == "block" or record["event_type"] == "flow" or forwarded is True:
                result = feed_response("records", generation.id, offset + len(data), record)
                if forwarded is True:
                    result["forwarding_observed"] = True
                if len(json.dumps(result, separators=(",", ":"), allow_nan=False).encode()) < RESPONSE_LIMIT:
                    return result
        offset += len(data)
        remaining -= len(data)
    return idle()


def read_events(files, generations, cursor, *, scope, notify_proof=None):
    """Read up to one sanitized record while keeping byte positions opaque to callers."""
    if not valid_cursor(cursor):
        raise ValueError("Invalid inspection EVE cursor")
    readable = tuple(item for item in generations if item.mode == "block" or notify_proof is not None)
    if not readable:
        return feed_response("idle" if cursor is None else "gap")
    try:
        descriptor = files.open(EVE_FILE, os.O_RDONLY)
    except (OSError, InspectionControlError):
        return feed_response("gap")
    with os.fdopen(descriptor, "rb") as stream:
        info = os.fstat(stream.fileno())
        latest = readable[-1]
        latest_available = _usable(latest, info)
        gap = feed_response("gap", latest.id, latest.offset) if latest_available else feed_response("gap")
        if cursor is None:
            if not latest_available:
                return gap
            index, offset = len(readable) - 1, latest.offset
        else:
            index = next((i for i, item in enumerate(readable) if item.id == cursor["generation"]), None)
            if index is None or not _usable(readable[index], info):
                return gap
            offset = cursor["offset"]
        current = readable[index]
        advance = None
        if index + 1 < len(readable):
            following = readable[index + 1]
            advance = feed_response("idle", following.id, following.offset) if _usable(following, info) else gap
        end = current.end if current.end is not None else info.st_size
        return _read_at(stream, current, offset, end, advance, scope, notify_proof)
