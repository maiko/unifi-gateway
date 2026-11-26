from dataclasses import replace
from datetime import datetime, timezone

import pytest

from inspection.suricata import decode_eve_event
from inspection.unifi_event import (
    FlowObservation,
    SignatureMetadata,
    project_suricata_event,
)


@pytest.fixture
def eve_alert():
    return {
        "event_type": "alert",
        "timestamp": "2026-11-24T14:33:37.123456+0100",
        "src_ip": "192.0.2.110",
        "src_port": 50123,
        "dest_ip": "198.51.100.120",
        "dest_port": 8080,
        "proto": "TCP",
        "alert": {
            "action": "allowed",
            "gid": 1,
            "signature_id": 1000001,
            "rev": 2,
        },
        "payload_printable": "private-marker",
        "http": {
            "request_headers": [{"name": "Authorization", "value": "private-marker"}]
        },
    }


@pytest.fixture
def observation():
    return {
        "site_id": "000000000000000000000001",
        "gateway_mac": "02:00:00:00:00:01",
        "flow": FlowObservation(
            flow_id=16123,
            session_id=435420620258,
            started_at=datetime(2026, 11, 24, 13, 33, 36, tzinfo=timezone.utc),
            bytes_to_client=70,
            bytes_to_server=195,
            packets_to_client=1,
            packets_to_server=3,
        ),
        "signature": SignatureMetadata(
            gid=1, revision=2, severity=3, signature="Lab marker", category=""
        ),
    }


def test_projects_a_confirmed_drop_using_the_network_11_dto(eve_alert, observation):
    event = decode_eve_event(eve_alert | {"verdict": {"action": "drop"}})

    assert project_suricata_event(event, **observation) == {
        "type": "SuricataEvent",
        "site_id": "000000000000000000000001",
        "gateway_mac": "02:00:00:00:00:01",
        "timestamp": "2026-11-24T13:33:37.123456+00:00",
        "action": "DROP",
        "flow_id": 16123,
        "ip": {
            "saddr": "192.0.2.110",
            "sport": 50123,
            "daddr": "198.51.100.120",
            "dport": 8080,
            "protocol": 6,
        },
        "flow": {
            "flow_id": 435420620258,
            "start": "2026-11-24T13:33:36+00:00",
            "bytes_toclient": 70,
            "bytes_toserver": 195,
            "pkts_toclient": 1,
            "pkts_toserver": 3,
        },
        "alert": {
            "signature_id": 1000001,
            "signature": "Lab marker",
            "gid": 1,
            "rev": 2,
            "severity": 3,
            "category": "",
        },
        "ubnt": {},
    }


def test_alert_projects_as_accept_only_with_an_observed_forward(eve_alert, observation):
    event = decode_eve_event(
        eve_alert
        | {"proto": "UDP", "src_ip": "2001:db8::110", "dest_ip": "2001:db8::120"}
    )

    assert project_suricata_event(event, **observation) is None
    message = project_suricata_event(event, forwarding_observed=True, **observation)
    assert message["action"] == "ACCEPT"
    assert message["ip"] == {
        "saddr": "2001:db8::110",
        "sport": 50123,
        "daddr": "2001:db8::120",
        "dport": 8080,
        "protocol": 17,
    }


def test_unknown_verdict_is_not_projected(eve_alert, observation):
    eve_alert["alert"]["action"] = "blocked"
    event = decode_eve_event(eve_alert)

    assert event.verdict == "unknown"
    assert (
        project_suricata_event(event, forwarding_observed=True, **observation) is None
    )


def test_conflicting_forward_and_drop_evidence_is_not_projected(eve_alert, observation):
    event = decode_eve_event(eve_alert | {"verdict": {"action": "drop"}})

    assert (
        project_suricata_event(event, forwarding_observed=True, **observation) is None
    )


@pytest.mark.parametrize(
    ("field", "bad_value"),
    [("session_id", 1 << 63), ("flow_id", True), ("bytes_to_server", -1)],
)
def test_rejects_unrepresentable_flow_observations(
    eve_alert, observation, field, bad_value
):
    event = decode_eve_event(eve_alert | {"verdict": {"action": "drop"}})
    observation["flow"] = replace(observation["flow"], **{field: bad_value})

    with pytest.raises(ValueError, match=field):
        project_suricata_event(event, **observation)


def test_rejects_severity_outside_the_network_11_enum(eve_alert, observation):
    event = decode_eve_event(eve_alert | {"verdict": {"action": "drop"}})
    observation["signature"] = replace(observation["signature"], severity=0)

    with pytest.raises(ValueError, match="severity"):
        project_suricata_event(event, **observation)


def test_rejects_broker_origin_values_in_gateway_mac(eve_alert, observation):
    event = decode_eve_event(eve_alert | {"verdict": {"action": "drop"}})
    observation["gateway_mac"] = "amqps://private-marker@example.invalid/"

    with pytest.raises(ValueError, match="gateway_mac") as exc:
        project_suricata_event(event, **observation)
    assert "private-marker" not in str(exc.value)
