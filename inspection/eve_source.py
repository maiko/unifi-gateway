"""Stream measured Suricata observations to the UniFi delivery companion."""

import argparse
import json
import re
import sys
from collections import Counter, OrderedDict
from collections.abc import Callable, Collection, Iterator
from datetime import datetime
from ipaddress import ip_address
from typing import BinaryIO

from inspection.suricata import SecurityEvent, decode_eve_event

MAX_RECORD_BYTES = 65_536
_JAVA_LONG_MAX = (1 << 63) - 1
_JAVA_INT_MAX = (1 << 31) - 1
_MAX_PENDING_FLOWS = 128
_MAX_PENDING_ALERTS_PER_FLOW = 16
_MAX_FORWARDING_IDS = 128
_EVENT_ID = re.compile(r"[0-9a-f]{64}", re.ASCII)
_ALERT_FIELDS = (
    "gid",
    "signature_id",
    "rev",
    "signature",
    "severity",
    "category",
    "action",
)
_FLOW_COUNTERS = ("bytes_toclient", "bytes_toserver", "pkts_toclient", "pkts_toserver")
_ALERT_HEADER = (
    "event_type",
    "timestamp",
    "flow_id",
    "src_ip",
    "src_port",
    "dest_ip",
    "dest_port",
    "proto",
)
_ALERT_IDENTIFIERS = ("sensor_id", "tx_id", "pcap_cnt")
_TIMESTAMP = re.compile(
    r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:?\d{2})",
    re.ASCII,
)


def _uint(value: object, maximum: int, *, minimum: int = 0) -> bool:
    return type(value) is int and minimum <= value <= maximum


def _unique_fields(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate field in EVE record")
        result[key] = value
    return result


def _invalid_constant(_value):
    raise ValueError("Non-JSON numeric constant in EVE record")


def _time(value: object) -> datetime:
    if not isinstance(value, str) or not _TIMESTAMP.fullmatch(value):
        raise ValueError("Invalid EVE timestamp")
    return datetime.fromisoformat(value)


def _rule_text(value: object, *, allow_empty: bool = False) -> bool:
    return (
        type(value) is str
        and len(value.encode("utf-8")) <= 1024
        and ((allow_empty and not value) or bool(value.strip()) and value.isprintable())
    )


def _clean_flow(flow: object) -> tuple[dict, datetime]:
    if type(flow) is not dict:
        raise ValueError("Missing EVE flow")
    start = _time(flow.get("start"))
    if not all(_uint(flow.get(name), _JAVA_LONG_MAX) for name in _FLOW_COUNTERS):
        raise ValueError("Missing or invalid EVE flow counters")
    return {name: flow[name] for name in ("start", *_FLOW_COUNTERS)}, start


def _clean_alert(event: dict, decoded: SecurityEvent) -> dict:
    if _time(event["timestamp"]) != decoded.timestamp:
        raise ValueError("Invalid EVE alert time")
    alert = event["alert"]
    if (
        not _uint(alert["gid"], _JAVA_INT_MAX)
        or not _uint(alert["rev"], _JAVA_INT_MAX)
        or not _uint(alert["signature_id"], _JAVA_INT_MAX, minimum=1)
        or not _uint(alert.get("severity"), 4, minimum=1)
        or not _rule_text(alert.get("signature"))
        or not _rule_text(alert.get("category"), allow_empty=True)
    ):
        raise ValueError("Missing or invalid EVE rule metadata")

    clean = {name: event[name] for name in _ALERT_HEADER}
    clean.update({name: event[name] for name in _ALERT_IDENTIFIERS if name in event})
    clean.update(
        alert={name: alert[name] for name in _ALERT_FIELDS},
        verdict={"action": decoded.verdict},
    )
    if "flow" in event:
        clean["flow"], start = _clean_flow(event["flow"])
        if start > decoded.timestamp:
            raise ValueError("EVE flow starts after its alert")
    return clean


def _flow_key(event: dict) -> tuple:
    flow_id = event.get("flow_id")
    proto = event.get("proto")
    source, destination = event.get("src_ip"), event.get("dest_ip")
    sport, dport = event.get("src_port"), event.get("dest_port")
    if (
        not _uint(flow_id, _JAVA_LONG_MAX, minimum=1)
        or proto not in ("TCP", "UDP")
        or not all(
            type(address) is str and "%" not in address
            for address in (source, destination)
        )
        or not all(_uint(port, 65535) for port in (sport, dport))
    ):
        raise ValueError("Invalid EVE flow identity")
    source, destination = ip_address(source), ip_address(destination)
    if source.version != destination.version:
        raise ValueError("Mixed EVE address families")
    return flow_id, proto, source, sport, destination, dport


def _completed_flow(event: dict) -> tuple[dict, datetime, datetime]:
    flow = event["flow"]
    clean, start = _clean_flow(flow)
    end = _time(flow.get("end"))
    if (
        not start <= end <= _time(event.get("timestamp"))
        or flow.get("alerted") is not True
    ):
        raise ValueError("Flow does not establish an alerted time interval")
    return clean, start, end


def iter_eve_observations(
    stream: BinaryIO,
    *,
    same_engine_flows: bool = False,
    forwarded_event_ids: Collection[str] = (),
    on_rejection: Callable[[str], None] | None = None,
) -> Iterator[dict]:
    """Read EVE JSON lines and emit native delivery observations.

    Enable flow pairing only for a trusted slice of one Suricata process, in
    which completed flow records follow their alerts. EVE lacks a process
    generation in the fixed helper's append file. The caller must delimit each
    engine's byte range before calling this iterator. Supply an alert ID only
    after independently observing forwarding of the traffic that produced it.
    """
    if len(forwarded_event_ids) > _MAX_FORWARDING_IDS or any(
        type(value) is not str or not _EVENT_ID.fullmatch(value)
        for value in forwarded_event_ids
    ):
        raise ValueError("Forwarding proof requires bounded SHA-256 alert identities")
    forwarded = frozenset(forwarded_event_ids)
    pending = OrderedDict()

    def reject(reason: str) -> None:
        if on_rejection is not None:
            on_rejection(reason)

    while raw := stream.readline(MAX_RECORD_BYTES + 1):
        if len(raw) > MAX_RECORD_BYTES:
            reject("oversized")
            while raw and not raw.endswith(b"\n"):
                raw = stream.readline(MAX_RECORD_BYTES + 1)
            continue
        if not raw.endswith(b"\n"):
            reject("unterminated")
            break
        try:
            event = json.loads(
                raw.decode("utf-8"),
                object_pairs_hook=_unique_fields,
                parse_constant=_invalid_constant,
            )
            if type(event) is not dict:
                raise ValueError("Expected an EVE object")
        except (ValueError, RecursionError):
            reject("malformed")
            continue
        kind = event.get("event_type")
        if same_engine_flows and kind == "flow":
            try:
                key = _flow_key(event)
                alerts = pending.get(key)
                if not alerts:
                    continue
                flow, start, end = _completed_flow(event)
            except (ValueError, KeyError, OverflowError):
                reject("invalid-flow")
                continue
            del raw, event
            for event_id, (timestamp, observation) in tuple(alerts.items()):
                if start <= timestamp <= end:
                    del alerts[event_id]
                    yield {
                        **observation,
                        "eve": {**observation["eve"], "flow": flow.copy()},
                    }
            if not alerts:
                del pending[key]
            continue
        verdict = event.get("verdict")
        action = verdict.get("action") if type(verdict) is dict else None
        if kind != "alert" or (
            action != "drop" and (action != "alert" or not forwarded)
        ):
            continue
        try:
            decoded = decode_eve_event(event)
            if decoded is None:
                raise ValueError("Unsupported EVE alert")
            forwarding_observed = decoded.event_id in forwarded
            if action == "alert" and not forwarding_observed:
                continue
            if action == "drop" and forwarding_observed:
                reject("forwarding-conflict")
                continue
            key = _flow_key(event)
            alert = _clean_alert(event, decoded)
            if "flow" not in alert and not same_engine_flows:
                raise ValueError("Missing EVE flow")
        except (ValueError, KeyError, OverflowError):
            reject("invalid-drop" if action == "drop" else "invalid-alert")
            continue
        del raw, event, verdict
        observation = {"eve": alert, "forwarding_observed": forwarding_observed}
        if "flow" in alert:
            yield observation
            continue
        if key not in pending and len(pending) == _MAX_PENDING_FLOWS:
            pending.popitem(last=False)
            reject("pending-flow-limit")
        alerts = pending.setdefault(key, {})
        if (
            decoded.event_id not in alerts
            and len(alerts) == _MAX_PENDING_ALERTS_PER_FLOW
        ):
            reject("pending-alert-limit")
            continue
        alerts[decoded.event_id] = (decoded.timestamp, observation)
    for alerts in pending.values():
        for _ in alerts:
            reject("unpaired-alert")


def iter_drop_observations(
    stream: BinaryIO, *, on_rejection: Callable[[str], None] | None = None
) -> Iterator[dict]:
    """Read legacy final-drop records with their counters embedded."""
    yield from iter_eve_observations(stream, on_rejection=on_rejection)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Read Suricata EVE from stdin and emit verified observations."
    )
    parser.add_argument(
        "--same-engine-flows",
        action="store_true",
        help="Pair alerts with subsequent flow records from one trusted engine run",
    )
    parser.add_argument(
        "--forwarded-event-id",
        action="append",
        default=[],
        help="Allow one alert whose forwarding was independently verified (repeatable)",
    )
    args = parser.parse_args(argv)
    if len(args.forwarded_event_id) > _MAX_FORWARDING_IDS or any(
        not _EVENT_ID.fullmatch(value) for value in args.forwarded_event_id
    ):
        parser.error("Forwarding proof requires bounded SHA-256 alert identities")
    rejected = Counter()

    def report(reason: str) -> None:
        rejected[reason] += 1
        if rejected[reason] == 1 or rejected[reason] % 256 == 0:
            print(
                f"EVE rejected {reason}={rejected[reason]}", file=sys.stderr, flush=True
            )

    try:
        for observation in iter_eve_observations(
            sys.stdin.buffer,
            same_engine_flows=args.same_engine_flows,
            forwarded_event_ids=args.forwarded_event_id,
            on_rejection=report,
        ):
            print(json.dumps(observation, separators=(",", ":")), flush=True)
    except BrokenPipeError:
        # Close the failed stream so interpreter shutdown does not flush it again.
        try:
            sys.stdout.close()
        except BrokenPipeError:
            pass
        print("EVE stream stopped because delivery closed its input", file=sys.stderr)
        return 1
    except OSError:
        print("EVE stream stopped because input or output failed", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
