"""Poll the owned EVE source and publish verified inspection events serially."""

import json
import logging
import os
import re
import sqlite3
import stat
import subprocess
from pathlib import Path
from threading import Lock

from inspection.controller import event_feed_forwarding_proof, is_passive_alert
from inspection.eve_source import _clean_alert, _completed_flow, _flow_key, _time, _unique_fields
from inspection.event_delivery import project_observation, publish_once
from inspection.suricata import decode_eve_event
from inspection.unifi_broker import BrokerPublishError
from tools import atomic_write


logger = logging.getLogger(__name__)
_GENERATION = re.compile(r"[0-9a-f]{32}")
_MAX_ALERTS = 128
_MAX_CHECKPOINT = 1 << 20


def _cursor(generation, offset):
    if type(offset) is not int or not 0 <= offset < 1 << 63:
        raise ValueError("Invalid EVE source offset")
    if generation is None and offset == 0:
        return None
    if type(generation) is not str or _GENERATION.fullmatch(generation) is None:
        raise ValueError("Invalid EVE source generation")
    return {"generation": generation, "offset": offset}


def _response(value, prior):
    forwarded = event_feed_forwarding_proof(value)
    status, record = value["status"], value["record"]
    cursor = _cursor(value["generation"], value["offset"])
    if status == "records":
        if cursor is None or type(record) is not dict or (prior is not None and (
            cursor["generation"] != prior["generation"] or cursor["offset"] <= prior["offset"]
        )):
            raise ValueError("Invalid EVE record cursor")
    elif record is not None:
        raise ValueError("Only records responses may contain an EVE record")
    elif status == "idle" and prior is not None and (
        cursor is None or (cursor["generation"] == prior["generation"] and cursor["offset"] < prior["offset"])
    ):
        raise ValueError("Invalid idle EVE cursor")
    return status, cursor, record, forwarded


def _verified_alert(record, forwarded):
    verdict = record.get("verdict")
    if forwarded:
        if not is_passive_alert(record):
            raise ValueError("EVE forwarding proof requires a passive alert")
    elif type(verdict) is not dict or verdict.get("action") != "drop":
        raise ValueError("EVE observation lacks a final drop verdict or forwarding proof")
    decoded = decode_eve_event(record)
    if decoded is None:
        raise ValueError("EVE record is not a supported alert")
    _flow_key(record)
    return decoded.event_id, {"eve": _clean_alert(record, decoded), "forwarding_observed": forwarded}


def _pair(record, pending, forwarded):
    if record.get("event_type") == "alert":
        if forwarded and "flow" in record:
            # The completed flow supplies real counters after the passive alert.
            record = {key: value for key, value in record.items() if key != "flow"}
        event_id, observation = _verified_alert(record, forwarded)
        if "flow" in observation["eve"]:
            pending.pop(event_id, None)
            return [observation]
        if event_id not in pending and len(pending) == _MAX_ALERTS:
            del pending[next(iter(pending))]
            logger.warning("Inspection reached its unpaired alert limit")
        pending[event_id] = observation
        return []

    if record.get("event_type") != "flow":
        raise ValueError("Unsupported EVE event type")
    key = _flow_key(record)
    flow, start, end = _completed_flow(record)
    ready = []
    for event_id, observation in tuple(pending.items()):
        alert = observation["eve"]
        if _flow_key(alert) == key and start <= _time(alert["timestamp"]) <= end:
            ready.append({**observation, "eve": {**alert, "flow": flow}})
            del pending[event_id]
    return ready


def _private_parent(path):
    info = path.parent.stat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
        raise ValueError("Inspection event state requires an owned private directory")


def _read_checkpoint(path, site, gateway):
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except FileNotFoundError:
        return None, {}, []
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
            raise ValueError("Inspection checkpoint must be an owned private file")
        raw = stream.read(_MAX_CHECKPOINT + 1)
    if len(raw) > _MAX_CHECKPOINT:
        raise ValueError("Inspection checkpoint exceeded its limit")
    state = json.loads(raw, object_pairs_hook=_unique_fields)
    if (
        type(state) is not dict or state.keys() != {"schema", "site", "gateway", "cursor", "pending", "ready"}
        or type(state["schema"]) is not int or state["schema"] not in (1, 2)
        or type(state["pending"]) is not list or type(state["ready"]) is not list
        or len(state["pending"]) > _MAX_ALERTS or len(state["ready"]) > _MAX_ALERTS
    ):
        raise ValueError("Invalid inspection checkpoint")
    if state["site"] != site or state["gateway"] != gateway:
        raise ValueError("Inspection checkpoint belongs to another site or gateway")
    cursor = state["cursor"]
    if cursor is not None and (
        type(cursor) is not dict or cursor.keys() != {"generation", "offset"}
        or _cursor(cursor["generation"], cursor["offset"]) is None
    ):
        raise ValueError("Invalid inspection checkpoint cursor")
    pending, ready = {}, []
    for records, with_flow in ((state["pending"], False), (state["ready"], True)):
        for item in records:
            if type(item) is not dict or cursor is None:
                raise ValueError("Invalid inspection checkpoint alert")
            if state["schema"] == 1:
                item = {"eve": item, "forwarding_observed": False}
            if (item.keys() != {"eve", "forwarding_observed"} or type(item["eve"]) is not dict
                    or type(item["forwarding_observed"]) is not bool):
                raise ValueError("Invalid inspection checkpoint observation")
            event_id, observation = _verified_alert(item["eve"], item["forwarding_observed"])
            if item != observation or ("flow" in observation["eve"]) != with_flow:
                raise ValueError("Invalid inspection checkpoint alert")
            if with_flow:
                ready.append(observation)
            else:
                pending[event_id] = observation
    return cursor, pending, ready


class EventWorker:
    """Process one source record or one queued publication per poll."""

    def __init__(self, source, broker, journal_path, state_path, *, drop_enabled=True, notify_enabled=False):
        self._source = source
        self._broker = broker
        self._journal = Path(journal_path).absolute()
        self._state = Path(state_path).absolute()
        self._drop_enabled = drop_enabled
        self._notify_enabled = notify_enabled
        if self._state.resolve() == self._journal.resolve():
            raise ValueError("Inspection source checkpoint and delivery journal must use distinct files")
        self._lock = Lock()
        self._waiting_for_broker = False

    def _enabled(self, forwarded):
        return self._notify_enabled if forwarded else self._drop_enabled

    def _save(self, site, gateway, cursor, pending, ready):
        state = {"schema": 2, "site": site, "gateway": gateway,
                 "cursor": cursor, "pending": list(pending.values()), "ready": ready}
        wire = json.dumps(state, ensure_ascii=False, separators=(",", ":"), allow_nan=False)
        if len(wire.encode("utf-8")) > _MAX_CHECKPOINT:
            raise ValueError("Inspection checkpoint exceeded its limit")
        atomic_write(self._state, lambda stream: stream.write(wire), mode=0o600)

    def poll(self):
        """Return whether the worker made progress during this poll."""
        with self._lock:
            active = self._broker()
            if active is None:
                return False
            trust, publisher = active
            scope = trust.site_id, trust.gateway_mac
            _private_parent(self._state)
            _private_parent(self._journal)
            cursor, pending, ready = _read_checkpoint(self._state, *scope)
            pending_count = len(pending)
            pending = {key: value for key, value in pending.items() if self._enabled(value["forwarding_observed"])}
            pruned = len(pending) != pending_count
            if ready:
                observation = ready[0]
                event = project_observation(observation, trust=trust) if self._enabled(observation["forwarding_observed"]) else None
                if event is not None:
                    try:
                        publish_once(self._journal, publisher, *event)
                    except BrokerPublishError as error:
                        if error.definitely_unsent:
                            if not self._waiting_for_broker:
                                logger.warning("Inspection broker is unavailable before publication")
                            self._waiting_for_broker = True
                            return False
                        logger.warning("Inspection event delivery needs broker verification")
                self._waiting_for_broker = False
                self._save(*scope, cursor, pending, ready[1:])
                return True

            status, following, record, forwarded = _response(self._source(cursor), cursor)
            abandoned = False
            if status == "gap" or (cursor is not None and following is not None
                                   and cursor["generation"] != following["generation"]):
                abandoned = bool(pending)
                if status == "gap" and (abandoned or following != cursor):
                    logger.warning("Inspection event source reported a gap")
                elif abandoned:
                    logger.warning("%d unpaired alerts expired at the inspection engine rollover", len(pending))
                pending.clear()
            if record is not None and (record.get("event_type") != "alert" or self._enabled(forwarded)):
                try:
                    ready = _pair(record, pending, forwarded)
                except (ValueError, KeyError, OverflowError, RecursionError):
                    logger.warning("Inspection discarded an unsupported EVE record")
            if following == cursor and record is None and not abandoned and not pruned:
                return False
            self._save(*scope, following, pending, ready)
            return True

    def run(self, stop):
        """Poll through temporary errors and stop between bounded operations."""
        reported = False
        while not stop.is_set():
            try:
                progress = self.poll()
                reported = False
            except (ValueError, KeyError, OSError, RecursionError, sqlite3.Error, subprocess.SubprocessError):
                if not reported:
                    logger.warning("Inspection event worker could not verify its source or checkpoint")
                    reported = True
                progress = False
            if not progress:
                stop.wait(1)
