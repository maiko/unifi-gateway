import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

from inspection.suricata import (
    SecurityEvent,
    decode_eve_event,
    decode_inspection_intent,
)


@pytest.fixture
def inspection_snapshots():
    path = Path(__file__).parent / "fixtures" / "uxg_pro" / "ids-native-snapshots.json"
    return json.loads(path.read_text())


@pytest.mark.parametrize("mode", ["off", "notify", "block"])
def test_decodes_native_inspection_modes(inspection_snapshots, mode):
    intent = decode_inspection_intent(inspection_snapshots[mode])

    assert intent.mode == mode
    assert intent.networks == (() if mode == "off" else ("br120", "br110"))


@pytest.mark.parametrize(
    "change",
    [
        {"mode": "nfq-high"},
        {"interfaces": []},
        {"interfaces": ["br120", "br120"]},
        {"interfaces": ["br120", "any"]},
        {"interfaces": ["br120", 110]},
        {"suppress": [{"unmapped": "rule"}]},
        {"enabled": 1},
    ],
)
def test_rejects_unmapped_inspection_semantics(inspection_snapshots, change):
    doc = json.loads(inspection_snapshots["block"])
    doc["udapi"]["services"]["idsIps"].update(change)

    with pytest.raises(ValueError):
        decode_inspection_intent(json.dumps(doc))


def test_rejects_incomplete_and_ambiguous_inspection_snapshots(inspection_snapshots):
    snapshot = inspection_snapshots["off"]
    duplicate = snapshot.replace('"enabled":false', '"enabled":true,"enabled":false')
    for invalid in (
        "{}",
        duplicate,
        snapshot.replace('"services/idsIps":8', '"services/idsIps":4'),
    ):
        with pytest.raises(ValueError):
            decode_inspection_intent(invalid)


@pytest.fixture
def eve_alert():
    return {
        "timestamp": "2026-11-24T14:33:37.123456+0100",
        "event_type": "alert",
        "flow_id": 435420620258,
        "tx_id": 0,
        "src_ip": "192.0.2.110",
        "src_port": 50123,
        "dest_ip": "198.51.100.120",
        "dest_port": 8080,
        "proto": "TCP",
        "alert": {
            "action": "allowed",
            "gid": 1,
            "signature_id": 1000001,
            "rev": 1,
            "signature": "Lab marker",
            "category": "",
            "severity": 3,
        },
    }


def test_decodes_a_passive_ipv4_alert(eve_alert):
    event = decode_eve_event(eve_alert)

    assert isinstance(event, SecurityEvent)
    assert event.timestamp == datetime(
        2026, 11, 24, 13, 33, 37, 123456, tzinfo=timezone.utc
    )
    assert event.timestamp.tzinfo is timezone.utc
    assert event.signature_id == 1000001
    assert (event.source, event.source_port) == ("192.0.2.110", 50123)
    assert (event.destination, event.destination_port) == ("198.51.100.120", 8080)
    assert event.protocol == "TCP"
    assert event.verdict == "alert"


@pytest.mark.parametrize(
    ("rule_action", "final_verdict", "expected"),
    [
        ("allowed", {"action": "drop"}, "drop"),
        ("blocked", {"action": "alert", "reject-target": "to_client"}, "alert"),
        ("allowed", {"action": "pass"}, "alert"),
        ("blocked", None, "unknown"),
    ],
)
def test_classifies_the_final_packet_verdict(
    eve_alert, rule_action, final_verdict, expected
):
    eve_alert["alert"]["action"] = rule_action
    if final_verdict is not None:
        eve_alert["verdict"] = final_verdict

    assert decode_eve_event(eve_alert).verdict == expected


def test_decodes_ipv6_without_inventing_icmp_ports(eve_alert):
    eve_alert.update(
        src_ip="2001:0DB8:0:0::110", dest_ip="2001:db8::120", proto="IPv6-ICMP"
    )
    del eve_alert["src_port"], eve_alert["dest_port"]

    event = decode_eve_event(eve_alert)

    assert (event.source, event.destination) == ("2001:db8::110", "2001:db8::120")
    assert (event.source_port, event.destination_port) == (None, None)
    assert event.protocol == "IPv6-ICMP"


@pytest.mark.parametrize(
    "invalid_fields",
    [
        {"event_type": "flow"},
        {"event_type": "drop"},
        {"timestamp": "not-a-date"},
        {"timestamp": "2026-11-24T13:33:37.123456"},
        {"src_ip": 1},
        {"src_ip": "2001:db8::110%private-marker", "dest_ip": "2001:db8::120"},
        {"dest_ip": "not-an-ip"},
        {"dest_ip": "2001:db8::120"},
        {"src_port": None},
        {"dest_port": 65536},
        {"dest_port": True},
        {"alert": ["blocked"]},
        {"alert": {"action": "allowed", "gid": 1, "rev": 1, "signature_id": True}},
        {"alert": {"action": "allowed", "gid": 1, "rev": 1}},
        {
            "alert": {
                "action": "unsupported",
                "gid": 1,
                "rev": 1,
                "signature_id": 1000001,
            }
        },
        {"verdict": None},
        {"verdict": {"action": "blocked"}},
        {"flow_id": "435420620258"},
        {"proto": "fake protocol"},
    ],
)
def test_ignores_malformed_and_unsupported_records(eve_alert, invalid_fields):
    assert decode_eve_event(eve_alert | invalid_fields) is None


def test_event_id_survives_a_new_process_and_ignores_payload(eve_alert):
    original = decode_eve_event(eve_alert)
    replay = eve_alert | {
        "timestamp": "2026-11-24T13:33:37.123456+0000",
        "payload_printable": "private-marker",
        "http": {
            "request_headers": [{"name": "Authorization", "value": "private-marker"}]
        },
    }
    replay_id = subprocess.check_output(
        [
            sys.executable,
            "-B",
            "-c",
            "import json, sys; from inspection.suricata import decode_eve_event; "
            "print(decode_eve_event(json.load(sys.stdin)).event_id)",
        ],
        env={**os.environ, "PYTHONHASHSEED": "101"},
        input=json.dumps(replay, sort_keys=True),
        text=True,
    ).strip()

    assert replay_id == original.event_id
    assert decode_eve_event(replay) == original
    assert "private-marker" not in repr(decode_eve_event(replay))


def test_event_id_distinguishes_transactions_and_rules_in_the_same_flow(eve_alert):
    original = decode_eve_event(eve_alert)
    other_transaction = decode_eve_event(eve_alert | {"tx_id": 1})
    other_rule = decode_eve_event(
        eve_alert | {"alert": eve_alert["alert"] | {"signature_id": 1000002}}
    )

    assert (
        len({original.event_id, other_transaction.event_id, other_rule.event_id}) == 3
    )
