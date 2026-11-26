"""A local delivery journal prevents duplicate native events after restart."""

from hashlib import sha256
from types import SimpleNamespace

import pytest

from inspection.event_delivery import project_observation, publish_once
from inspection.unifi_broker import BrokerPublishError, BrokerTrust


EVENT_ID = "a" * 64
EVENT = {"site_id": "lab-site", "gateway_mac": "02:00:00:00:00:03"}


def test_worker_reads_only_the_verified_private_broker_snapshot(tmp_path, monkeypatch):
    from inspection import event_delivery

    trust = BrokerTrust("192.0.2.2", 5671, EVENT["site_id"], "mq.example", "a" * 64, EVENT["gateway_mac"])
    path = tmp_path / "gateway.conf"
    digest = sha256(b"approved").hexdigest()
    snapshot = f"""[gateway]
device = UXGENT
platform = vyos
lan_mac = {trust.gateway_mac}
is_adopted = true
[provisioned]
cfgversion = intended
system_cfg = approved
[vyos_applied]
cfgversion = intended
system_cfg_sha256 = {digest}
"""
    calls = []
    monkeypatch.setattr(event_delivery, "decode_broker_provisioning",
                        lambda raw, **options: calls.append((raw, options)) or "verified config")
    monkeypatch.setattr(event_delivery, "UniFiBrokerPublisher", lambda value: ("publisher", value))
    path.write_text(snapshot)
    path.chmod(0o600)
    assert event_delivery.verified_broker_from_state(path, trust) == (trust, ("publisher", "verified config"))
    assert calls == [("approved", {"trust": trust, "required_event_state": "ipsIds"})]

    path.write_text(snapshot.replace("system_cfg = approved", "system_cfg = changed"))
    assert event_delivery.verified_broker_from_state(path, trust) is None
    path.write_text(snapshot.replace("[vyos_applied]", "[unused]"))
    assert event_delivery.verified_broker_from_state(path, trust) is None

    path.write_text(snapshot)
    alias = tmp_path / "linked.conf"
    alias.symlink_to(path)
    with pytest.raises(OSError):
        event_delivery.verified_broker_from_state(alias, trust)
    path.chmod(0o640)
    with pytest.raises(ValueError, match="private"):
        event_delivery.verified_broker_from_state(path, trust)
    assert len(calls) == 1


def test_confirmed_event_is_not_sent_twice(tmp_path):
    sent = []
    publisher = SimpleNamespace(
        publish=lambda event_id, event: sent.append((event_id, event))
    )
    path = tmp_path / "delivery.sqlite"

    assert publish_once(path, publisher, EVENT_ID, EVENT)
    assert not publish_once(path, publisher, EVENT_ID, EVENT)
    assert sent == [(EVENT_ID, EVENT)]
    assert path.stat().st_mode & 0o777 == 0o600


def test_uncertain_delivery_remains_pending(tmp_path):
    def publish(_event_id, _event):
        raise BrokerPublishError("Could not verify broker acknowledgement")

    publisher = SimpleNamespace(publish=publish)
    path = tmp_path / "delivery.sqlite"
    with pytest.raises(BrokerPublishError, match="acknowledgement"):
        publish_once(path, publisher, EVENT_ID, EVENT)
    with pytest.raises(BrokerPublishError, match="pending"):
        publish_once(path, publisher, EVENT_ID, EVENT)


def test_positive_confirmation_survives_disconnect_failure(tmp_path):
    def publish(_event_id, _event):
        raise BrokerPublishError(
            "Could not close the connection", delivery_confirmed=True
        )

    publisher = SimpleNamespace(publish=publish)
    path = tmp_path / "delivery.sqlite"
    assert publish_once(path, publisher, EVENT_ID, EVENT)
    assert not publish_once(path, publisher, EVENT_ID, EVENT)


@pytest.fixture
def observed_flow():
    return {
        "forwarding_observed": True,
        "eve": {
            "event_type": "alert",
            "timestamp": "2026-11-24T14:23:23.671542+0000",
            "flow_id": 904881766631735,
            "tx_id": 0,
            "src_ip": "192.0.2.110",
            "src_port": 46290,
            "dest_ip": "198.51.100.120",
            "dest_port": 18443,
            "proto": "TCP",
            "alert": {
                "gid": 1,
                "signature_id": 1000001,
                "rev": 1,
                "signature": "Lab marker",
                "severity": 3,
                "category": "",
                "action": "allowed",
            },
            "verdict": {"action": "alert"},
            "flow": {
                "start": "2026-11-24T14:23:23.669436+0000",
                "bytes_toclient": 456,
                "bytes_toserver": 457,
                "pkts_toclient": 5,
                "pkts_toserver": 5,
            },
        },
    }


def test_event_companion_projects_real_flow_without_packet_content(observed_flow):
    trust = BrokerTrust(
        "192.0.2.2",
        5671,
        EVENT["site_id"],
        "mq.example",
        "a" * 64,
        EVENT["gateway_mac"],
    )
    observed_flow["eve"]["payload_printable"] = "never send"

    event_id, body = project_observation(observed_flow, trust=trust)

    assert len(event_id) == 64
    assert body["action"] == "ACCEPT"
    assert body["flow"]["bytes_toserver"] == 457
    assert body["flow"]["flow_id"] == body["flow_id"]
    assert "never send" not in repr(body)
    observed_flow["forwarding_observed"] = False
    assert project_observation(observed_flow, trust=trust) is None


def test_companion_refuses_unmeasured_flow_statistics(observed_flow):
    trust = BrokerTrust(
        "192.0.2.2",
        5671,
        EVENT["site_id"],
        "mq.example",
        "a" * 64,
        EVENT["gateway_mac"],
    )
    del observed_flow["eve"]["flow"]["bytes_toserver"]

    with pytest.raises(ValueError, match="flow"):
        project_observation(observed_flow, trust=trust)
