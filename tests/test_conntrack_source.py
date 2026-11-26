"""Validate source observations against raw captures and the existing flow compiler."""

from copy import deepcopy
from io import BytesIO
import json
from pathlib import Path

import pytest

from inspection.connection_flow import project_connection_flow
from inspection.conntrack_source import (
    MAX_RECORD_BYTES,
    FlowScope,
    decode_capture_window,
    iter_conntrack_observations,
)

SITE = "f86e2468-0000-4000-8000-000000000001"
MAC = "02:00:00:00:00:01"
FIXTURES = Path(__file__).parent / "fixtures" / "uxg_pro"


@pytest.fixture
def record():
    return json.loads((FIXTURES / "conntrack-source-window.json").read_text())["record"]


@pytest.fixture
def scope():
    return FlowScope(
        "192.168.110.2", 18685, "192.168.120.2", 18686, "eth3.120", "eth3.110"
    )


def _lines(*events):
    return BytesIO("".join(json.dumps(event) + "\n" for event in events).encode())


def test_source_normalizes_actual_capture_to_the_existing_completed_event(
    record, scope
):
    observation = decode_capture_window(record, scope=scope)
    known = json.loads((FIXTURES / "conntrack-completed-tcp.json").read_text())

    assert observation == known
    expected = project_connection_flow(known, site_id=SITE, gateway_mac=MAC)
    assert (
        project_connection_flow(observation, site_id=SITE, gateway_mac=MAC) == expected
    )
    assert expected.event["stats"] == {
        "txBytes": 352,
        "txPackets": 6,
        "rxBytes": 266,
        "rxPackets": 4,
    }


@pytest.mark.parametrize(
    ("path", "before", "after"),
    [
        ("conntrack", "<src>192.168.120.2</src>", "<src>192.168.120.3</src>"),
        ("conntrack", "<dport>18685</dport>", "<dport>28000</dport>"),
        ("conntrack", "<assured/>", "<assured/><userspace/>"),
        ("conntrack", 'type="destroy"', 'type="update"'),
        ("conntrack", "<stop>1795533952877374043</stop>", "<stop>0</stop>"),
        ("conntrack", "<packets>6</packets>", "<packets>5</packets>"),
        ("conntrack", "<bytes>352</bytes>", "<bytes>351</bytes>"),
        ("conntrack", "<conntrack>", "<!DOCTYPE conntrack><conntrack>"),
        ("conntrack", "1 flow events", "2 flow events"),
        ("conntrack", "</conntrack>", ""),
        ("original_capture", "listening on eth3.120", "listening on eth3.210"),
        ("original_capture", "0 packets dropped", "1 packets dropped"),
        ("original_capture", "6 packets received", "7 packets received"),
        ("original_capture", "Flags [P.]", "Flags [S.]"),
        ("original_capture", "Flags [F.]", "Flags [R.]"),
        ("reply_capture", "192.168.110.2.18685: Flags", "192.168.110.2.18684: Flags"),
        ("reply_capture", "offset 0, flags [DF]", "offset 1, flags [+]"),
    ],
)
def test_refuses_translated_or_incomplete_source_evidence(
    record, scope, path, before, after
):
    assert before in record[path]
    record[path] = record[path].replace(before, after, 1)
    with pytest.raises(ValueError):
        decode_capture_window(record, scope=scope)


def test_refuses_multiple_destroy_records_for_a_reused_tuple(record, scope):
    raw = record["conntrack"]
    flow = raw[raw.index("<flow ") : raw.index("</flow>") + len("</flow>")]
    record["conntrack"] = raw.replace("</conntrack>", flow + "\n</conntrack>")
    with pytest.raises(ValueError):
        decode_capture_window(record, scope=scope)


@pytest.mark.parametrize("field", ["collector_run_id", "router_boot_id"])
def test_refuses_a_restart_between_capture_open_and_close(record, scope, field):
    record["end"][field] = "33333333-3333-4333-8333-333333333333"
    with pytest.raises(ValueError):
        decode_capture_window(record, scope=scope)


def test_refuses_replayed_or_overlapping_windows_in_a_stream(record, scope):
    reader = iter_conntrack_observations(_lines(record, record), scope=scope)
    assert next(reader)["tracking"]["conntrack_flow_id"] == 3949867120
    with pytest.raises(ValueError, match="overlap"):
        next(reader)


def test_stream_accepts_a_complete_new_capture_after_router_restart(record, scope):
    later = deepcopy(record)
    step_ns = 20_000_000_000
    for key in ("begin", "end"):
        later[key]["collector_run_id"] = "33333333-3333-4333-8333-333333333333"
        later[key]["router_boot_id"] = "44444444-4444-4444-8444-444444444444"
        later[key]["unix_ns"] += step_ns
    for role in ("initiator", "responder"):
        later["verified_application"][role]["time_ns"] += step_ns
    for stamp in (1795533947875988169, 1795533952877374043):
        later["conntrack"] = later["conntrack"].replace(
            str(stamp), str(stamp + step_ns)
        )
    for direction in ("original_capture", "reply_capture"):
        later[direction] = later[direction].replace("1795533947.", "1795533967.")

    original, new = iter_conntrack_observations(_lines(record, later), scope=scope)
    old_event = project_connection_flow(original, site_id=SITE, gateway_mac=MAC)
    new_event = project_connection_flow(new, site_id=SITE, gateway_mac=MAC)

    assert old_event.event_id != new_event.event_id
    assert old_event.event["stats"] == new_event.event["stats"]


def test_refuses_capture_started_after_the_flow_and_late_endpoint_receipts(
    record, scope
):
    stale = deepcopy(record)
    stale["begin"]["unix_ns"] = 1795533947876000000
    with pytest.raises(ValueError):
        decode_capture_window(stale, scope=scope)

    record["verified_application"]["initiator"]["time_ns"] = (
        record["end"]["unix_ns"] + 1
    )
    with pytest.raises(ValueError):
        decode_capture_window(record, scope=scope)


def test_refuses_contradictory_endpoint_eof_and_payload_evidence(record, scope):
    record["verified_application"]["initiator"]["observed_server_eof"] = False
    with pytest.raises(ValueError):
        decode_capture_window(record, scope=scope)

    record["verified_application"]["initiator"]["observed_server_eof"] = True
    record["verified_application"]["responder"]["received_bytes"] += 1
    with pytest.raises(ValueError):
        decode_capture_window(record, scope=scope)


def test_refuses_unscoped_tuple_and_shared_egress(record, scope):
    other = FlowScope(
        "192.168.110.2", 18685, "192.168.120.3", 18686, "eth3.120", "eth3.110"
    )
    with pytest.raises(ValueError):
        decode_capture_window(record, scope=other)
    with pytest.raises(ValueError):
        FlowScope(
            "192.168.110.2", 18685, "192.168.120.2", 18686, "eth3.120", "eth3.120"
        )


@pytest.mark.parametrize(
    "wire", [b'{"begin":{},"begin":{}}\n', b" " * (MAX_RECORD_BYTES + 1)]
)
def test_cli_reader_refuses_duplicate_json_fields_and_unbounded_records(scope, wire):
    with pytest.raises(ValueError):
        next(iter_conntrack_observations(BytesIO(wire), scope=scope))
