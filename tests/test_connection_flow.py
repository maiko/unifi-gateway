import json
from pathlib import Path

import pytest


SITE = "f86e2468-0000-4000-8000-000000000001"
MAC = "02:00:00:00:00:01"


@pytest.fixture
def evidence():
    path = (
        Path(__file__).parent / "fixtures" / "uxg_pro" / "conntrack-completed-tcp.json"
    )
    return json.loads(path.read_text())


def project(evidence, site_id=SITE, gateway_mac=MAC):
    from inspection.connection_flow import project_connection_flow

    return project_connection_flow(evidence, site_id=site_id, gateway_mac=gateway_mac)


def test_projects_observed_completed_ipv4_flow_with_directional_counters(evidence):
    result = project(evidence)

    assert result.event == {
        "type": "FLOW_POLICY",
        "site_id": SITE,
        "gateway_mac": MAC,
        "timestamp": "2026-11-24T15:25:47.877657000Z",
        "action": "ACCEPT",
        "flow_id": 3949867120,
        "ip": {
            "saddr": "192.168.110.2",
            "sport": 18685,
            "daddr": "192.168.120.2",
            "dport": 18686,
            "protocol": 6,
        },
        "flow_start": "2026-11-24T15:25:47.875988169Z",
        "flow_end": "2026-11-24T15:25:47.877657000Z",
        "stats": {"txBytes": 352, "txPackets": 6, "rxBytes": 266, "rxPackets": 4},
    }
    assert result.kernel_expiry_ns == 1795533952877374043


def test_replay_id_is_stable_scoped_and_excludes_payload(evidence):
    result = project(evidence)
    replay = json.loads(json.dumps(evidence, sort_keys=True))
    replay["payload"] = {"secret": "must never leave the source"}
    replay["tracking"]["kernel_expiry_ns"] += 1_000
    replay["directions"]["original"]["packet_headers"][2]["payload"] = (
        "arbitrary secret"
    )

    assert project(replay).event_id == result.event_id
    assert project(replay).event == result.event
    assert len(result.event_id) == 64
    assert project(evidence, site_id=SITE[:-1] + "2").event_id != result.event_id
    assert project(evidence, gateway_mac=MAC[:-1] + "2").event_id != result.event_id


@pytest.mark.parametrize(
    ("path", "invalid"),
    [
        (("directions", "reply", "tuple", 0), "192.168.120.3"),
        (("directions", "reply", "tuple", 1), 443),
        (("directions", "original", "tuple", 4), 17),
        (("directions", "original", "conntrack_l3_bytes"), 351),
        (("directions", "reply", "conntrack_packets"), 5),
        (("directions", "reply", "captured_packets"), True),
        (("directions", "reply", "packet_headers", 3, "flags"), "."),
        (("directions", "original", "packet_headers", 5, "flags"), "P."),
        (("directions", "original", "packet_headers", 0, "flags"), "."),
        (("directions", "original", "packet_headers", 2, "tcp_payload_bytes"), 35),
        (("verified_application", "initiator", "observed_server_eof"), False),
        (("verified_application", "responder", "peer", 1), 4321),
        (("verified_application", "responder", "reply_bytes"), 48),
        (("tracking", "last_egress_packet_ns"), 1795533947877657001),
        (("tracking", "kernel_expiry_ns"), 1795533947877000000),
        (("tracking", "kernel_start_ns"), "1795533947875988169"),
        (("tracking", "conntrack_flow_id"), True),
        (("tracking", "assured"), False),
        (("tracking", "state"), "ESTABLISHED"),
    ],
)
def test_rejects_unproven_or_inconsistent_observations(evidence, path, invalid):
    target = evidence
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = invalid

    with pytest.raises(ValueError):
        project(evidence)


def test_rejects_missing_metadata_and_invalid_scope(evidence):
    with pytest.raises(ValueError):
        project(evidence, site_id="default")
    with pytest.raises(ValueError):
        project(evidence, gateway_mac="not-a-mac")
    with pytest.raises(ValueError):
        project({})
