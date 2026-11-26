import base64
import hashlib
import json
import ssl
import stat
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

from inspection import unifi_broker as broker
from provisioners.vyos import unmanaged_config_fingerprint


def pem(kind, data):
    return (
        b"-----BEGIN "
        + kind
        + b"-----\n"
        + base64.b64encode(data)
        + b"\n-----END "
        + kind
        + b"-----\n"
    )


def encoded(value):
    return base64.b64encode(value).decode()


@pytest.fixture
def provisioning():
    ca = b"lab synthetic CA bytes"
    trust = broker.BrokerTrust(
        host="192.0.2.4",
        port=5671,
        site_id="f86e2468-0000-4000-8000-000000000001",
        tls_hostname="mq.example.test",
        ca_sha256=hashlib.sha256(ca).hexdigest(),
        gateway_mac="02:00:00:00:00:01",
    )
    settings = {
        "enabled": True,
        "extended": True,
        "siteID": trust.site_id,
        "flowConfiguration": {"eventState": ["ipsIds"]},
        "rabbitMq": {
            "host": trust.host,
            "port": trust.port,
            "authentication": {
                "username": "test-user-secret",
                "password": "test-password-secret",
            },
            "tls": {
                "enabled": True,
                "verifyPeer": True,
                "verifyHostname": False,
                "caCertificate": {"crt": encoded(pem(b"CERTIFICATE", ca))},
                "clientCertificate": {
                    "crt": encoded(pem(b"CERTIFICATE", b"lab synthetic client bytes")),
                    "key": encoded(pem(b"PRIVATE KEY", b"test-key-secret")),
                },
            },
        },
    }
    snapshot = {
        "udapi": {
            "version": 48,
            "versionFormat": "v2",
            "versionDetail": {"services/messageBroker": 3},
            "services": {"messageBroker": settings},
        },
    }
    return trust, snapshot


def test_only_pinned_broker_credentials_may_rotate_in_approved_baseline(provisioning):
    trust, broker_snapshot = provisioning
    fixtures = Path(__file__).parent / "fixtures" / "uxg_pro"
    snapshots = json.loads((fixtures / "zbf-native-snapshots.json").read_text())["snapshots"]
    base = json.loads(snapshots["baseline"]["system_cfg"])
    extra = broker_snapshot["udapi"]
    base["udapi"]["versionDetail"].update(extra["versionDetail"])
    base["udapi"]["services"] = extra["services"]
    original = json.dumps(base)

    original_digest = unmanaged_config_fingerprint(original, revision="original", broker_trust=trust)
    rabbit = base["udapi"]["services"]["messageBroker"]["rabbitMq"]
    rabbit["authentication"]["password"] = "rotated-test-password"
    assert unmanaged_config_fingerprint(json.dumps(base), revision="rotated", broker_trust=trust) == original_digest

    with pytest.raises(ValueError, match="firewall schema"):
        unmanaged_config_fingerprint(original, revision="without-broker")
    rabbit["host"] = "192.0.2.5"
    with pytest.raises(ValueError, match="pinned endpoint"):
        unmanaged_config_fingerprint(json.dumps(base), revision="different-host", broker_trust=trust)


@pytest.fixture
def event(provisioning):
    trust, _ = provisioning
    return {
        "type": "SuricataEvent",
        "site_id": trust.site_id,
        "gateway_mac": trust.gateway_mac,
        "timestamp": "2026-11-24T14:23:58.130493+00:00",
        "action": "DROP",
        "flow_id": 1234,
        "ip": {
            "saddr": "192.0.2.1",
            "sport": 51000,
            "daddr": "192.0.2.2",
            "dport": 18443,
            "protocol": 6,
        },
        "flow": {
            "flow_id": 781,
            "start": "2026-11-24T14:23:58+00:00",
            "bytes_toclient": 60,
            "bytes_toserver": 1019,
            "pkts_toclient": 1,
            "pkts_toserver": 8,
        },
        "alert": {
            "signature_id": 1000001,
            "signature": "Lab marker",
            "gid": 1,
            "rev": 1,
            "severity": 3,
            "category": "",
        },
        "ubnt": {},
    }


class Ack:
    delivery_tag = 1
    multiple = False


class Nack(Ack):
    pass


class FakeTransport:
    def __init__(self):
        self.calls = []
        self.channel_error = None
        self.close_error = None
        self.outcome = "ack"
        self.pika = SimpleNamespace(
            ConnectionParameters=lambda **kwargs: kwargs,
            PlainCredentials=lambda *args, **kwargs: (args, kwargs),
            SSLOptions=lambda context, hostname: (context, hostname),
            BasicProperties=lambda **kwargs: kwargs,
            spec=SimpleNamespace(Basic=SimpleNamespace(Ack=Ack, Nack=Nack)),
        )

    def connect(self, params, *, timeout):
        self.calls.append(("connect", params, timeout))
        return self

    def close(self, *, timeout):
        self.calls.append(("close", timeout))
        if self.outcome == "late-ack":
            self.confirmed(SimpleNamespace(method=Ack()))
        if self.close_error is not None:
            raise self.close_error

    def channel(self, *, timeout):
        self.calls.append(("channel", timeout))
        if self.channel_error is not None:
            raise self.channel_error
        return self

    def add_on_return_callback(self, callback):
        self.returned = callback

    def confirm_delivery(self, callback, *, timeout):
        self.calls.append(("confirm", timeout))
        self.confirmed = callback

    def basic_publish(self, **kwargs):
        self.calls.append(("publish", kwargs))
        if self.outcome == "return":
            self.returned(self, None, kwargs["properties"], kwargs["body"])
        if self.outcome not in ("timeout", "late-ack"):
            method = Nack() if self.outcome == "nack" else Ack()
            self.confirmed(SimpleNamespace(method=method))


@pytest.fixture
def transport(monkeypatch):
    fake = FakeTransport()
    monkeypatch.setattr(broker, "_load_pika", lambda: (fake.pika, fake.connect))
    return fake


@pytest.fixture
def mock_tls(monkeypatch):
    class Context:
        verify_mode = ssl.CERT_REQUIRED
        check_hostname = True

        def __init__(self, protocol):
            assert protocol == ssl.PROTOCOL_TLS_CLIENT

        def load_verify_locations(self, *, cadata):
            self.ca = cadata

        def load_cert_chain(self, certfile, keyfile, password):
            self.files = (Path(certfile), Path(keyfile))
            assert password == ""
            for path in self.files:
                assert stat.S_IMODE(path.stat().st_mode) == 0o600
                assert stat.S_IMODE(path.parent.stat().st_mode) == 0o700
            assert b"BEGIN CERTIFICATE" in self.files[0].read_bytes()
            assert b"BEGIN PRIVATE KEY" in self.files[1].read_bytes()

    monkeypatch.setattr(broker.ssl, "SSLContext", Context)


def test_requires_separate_exact_trust_and_redacts_config(provisioning):
    trust, snapshot = provisioning
    config = broker.decode_broker_provisioning(json.dumps(snapshot), trust=trust)
    assert config.trust == trust
    assert "test-user-secret" not in repr(config)
    assert "test-password-secret" not in repr(config)
    assert "test-key-secret" not in repr(config)


@pytest.mark.parametrize("field", ["host", "port", "site_id", "ca_sha256"])
def test_rejects_a_controller_change_to_pinned_scope(provisioning, field):
    trust, snapshot = provisioning
    other = {
        "host": "192.0.2.5",
        "port": 5672,
        "site_id": "f86e2468-0000-4000-8000-000000000002",
        "ca_sha256": "0" * 64,
    }
    with pytest.raises(broker.BrokerConfigError):
        broker.decode_broker_provisioning(
            json.dumps(snapshot), trust=replace(trust, **{field: other[field]})
        )


def test_rejects_a_supplied_bundle_containing_an_extra_ca(provisioning):
    trust, snapshot = provisioning
    tls = snapshot["udapi"]["services"]["messageBroker"]["rabbitMq"]["tls"]
    tls["caCertificate"]["crt"] = encoded(
        base64.b64decode(tls["caCertificate"]["crt"]) + pem(b"CERTIFICATE", b"other CA")
    )
    with pytest.raises(broker.BrokerConfigError):
        broker.decode_broker_provisioning(json.dumps(snapshot), trust=trust)


def test_rejects_disabled_peer_verification_and_unrecognized_version(provisioning):
    trust, snapshot = provisioning
    snapshot["udapi"]["services"]["messageBroker"]["rabbitMq"]["tls"]["verifyPeer"] = (
        False
    )
    with pytest.raises(broker.BrokerConfigError):
        broker.decode_broker_provisioning(json.dumps(snapshot), trust=trust)
    snapshot["udapi"]["versionDetail"]["services/messageBroker"] = 2
    with pytest.raises(broker.BrokerConfigError, match="version"):
        broker.decode_broker_provisioning(json.dumps(snapshot), trust=trust)


def test_invalid_material_and_json_errors_hide_input(provisioning):
    trust, snapshot = provisioning
    tls = snapshot["udapi"]["services"]["messageBroker"]["rabbitMq"]["tls"]
    tls["clientCertificate"]["key"] = "bad-test-key-secret"
    with pytest.raises(broker.BrokerConfigError) as exc:
        broker.decode_broker_provisioning(json.dumps(snapshot), trust=trust)
    assert "test-key-secret" not in str(exc.value)
    assert exc.value.__cause__ is None
    with pytest.raises(broker.BrokerConfigError) as exc:
        broker.decode_broker_provisioning(
            '{"password": "test-password-secret"', trust=trust
        )
    assert "test-password-secret" not in str(exc.value)


def test_publishes_one_confirmed_utf8_text_body_with_pinned_tls(
    provisioning, event, transport, mock_tls
):
    trust, snapshot = provisioning
    publisher = broker.UniFiBrokerPublisher(
        broker.decode_broker_provisioning(json.dumps(snapshot), trust=trust)
    )
    message_id = "a" * 64

    publisher.publish(message_id, event)

    assert [call[0] for call in transport.calls] == [
        "connect",
        "channel",
        "confirm",
        "publish",
        "close",
    ]
    params = transport.calls[0][1]
    assert (params["host"], params["port"], params["virtual_host"]) == (
        trust.host,
        trust.port,
        "/",
    )
    assert params["connection_attempts"] == 1
    context, hostname = params["ssl_options"]
    assert hostname == trust.tls_hostname
    assert context.verify_mode == ssl.CERT_REQUIRED and context.check_hostname
    assert context.minimum_version == ssl.TLSVersion.TLSv1_2
    assert all(not path.parent.exists() for path in context.files)
    publish = transport.calls[3][1]
    assert publish["exchange"] == "" and publish["routing_key"] == "unifi_flow_queue"
    assert publish["mandatory"] is True
    assert publish["properties"] == {
        "content_type": "text/plain",
        "content_encoding": "utf-8",
        "message_id": message_id,
    }
    assert json.loads(publish["body"]) == event


@pytest.mark.parametrize("outcome", ["return", "nack", "timeout"])
def test_unconfirmed_or_unroutable_publish_fails_without_retry(
    provisioning, event, transport, mock_tls, monkeypatch, outcome
):
    trust, snapshot = provisioning
    publisher = broker.UniFiBrokerPublisher(
        broker.decode_broker_provisioning(json.dumps(snapshot), trust=trust)
    )
    transport.outcome = outcome
    monkeypatch.setattr(broker, "_CONFIRM_TIMEOUT", 0)

    with pytest.raises(broker.BrokerPublishError) as exc:
        publisher.publish("a" * 64, event)

    assert not exc.value.definitely_unsent
    assert [call[0] for call in transport.calls].count("publish") == 1
    assert transport.calls[-1][0] == "close"


@pytest.mark.parametrize(
    "field",
    [
        "type",
        "site_id",
        "gateway_mac",
        "unknown",
        "payload",
        "nested_payload",
        "event_id",
    ],
)
def test_invalid_event_is_rejected_before_connecting(
    provisioning, event, transport, field
):
    trust, snapshot = provisioning
    publisher = broker.UniFiBrokerPublisher(
        broker.decode_broker_provisioning(json.dumps(snapshot), trust=trust)
    )
    message_id = "a" * 64
    if field == "event_id":
        message_id = "bad-message-id"
    elif field == "unknown":
        event["action"] = "UNKNOWN"
    elif field == "nested_payload":
        event["alert"]["signature"] = {"payload": "not-for-wire"}
    else:
        event[field] = "not-for-wire"
    with pytest.raises(broker.BrokerPublishError):
        publisher.publish(message_id, event)
    assert transport.calls == []


def test_transport_failure_is_redacted_and_closed(
    provisioning, event, transport, mock_tls
):
    trust, snapshot = provisioning
    publisher = broker.UniFiBrokerPublisher(
        broker.decode_broker_provisioning(json.dumps(snapshot), trust=trust)
    )
    transport.channel_error = RuntimeError("test-password-secret")
    with pytest.raises(broker.BrokerPublishError) as exc:
        publisher.publish("a" * 64, event)
    assert "test-password-secret" not in str(exc.value)
    assert exc.value.__cause__ is None
    assert exc.value.definitely_unsent
    assert transport.calls[-1][0] == "close"


def test_late_confirmation_does_not_turn_timeout_into_success(
    provisioning, event, transport, mock_tls, monkeypatch
):
    trust, snapshot = provisioning
    publisher = broker.UniFiBrokerPublisher(
        broker.decode_broker_provisioning(json.dumps(snapshot), trust=trust)
    )
    transport.outcome = "late-ack"
    monkeypatch.setattr(broker, "_CONFIRM_TIMEOUT", 0)

    with pytest.raises(broker.BrokerPublishError, match="timed out") as exc:
        publisher.publish("a" * 64, event)

    assert not exc.value.delivery_confirmed


def test_cleanup_failure_preserves_an_observed_confirmation(
    provisioning, event, transport, mock_tls
):
    trust, snapshot = provisioning
    publisher = broker.UniFiBrokerPublisher(
        broker.decode_broker_provisioning(json.dumps(snapshot), trust=trust)
    )
    transport.close_error = RuntimeError("test-password-secret")

    with pytest.raises(broker.BrokerPublishError, match="cleanup failed") as exc:
        publisher.publish("a" * 64, event)

    assert exc.value.delivery_confirmed
    assert "test-password-secret" not in str(exc.value)


@pytest.fixture
def completed_flow(provisioning):
    from inspection.connection_flow import project_connection_flow

    trust, _ = provisioning
    directory = Path(__file__).parent / "fixtures" / "uxg_pro"
    evidence = json.loads((directory / "conntrack-completed-tcp.json").read_text())
    return project_connection_flow(
        evidence, site_id=trust.site_id, gateway_mac=trust.gateway_mac
    )


def test_conntrack_requires_its_exact_provisioned_event_state(provisioning):
    trust, snapshot = provisioning
    state = snapshot["udapi"]["services"]["messageBroker"]["flowConfiguration"]
    state["eventState"] = ["ipsIds", "Conntrack"]

    with pytest.raises(broker.BrokerConfigError, match="conntrack"):
        broker.decode_broker_provisioning(
            json.dumps(snapshot), trust=trust, required_event_state="conntrack"
        )


def test_provisioned_flow_is_confirmed_with_the_pinned_event_id(
    provisioning, completed_flow, transport, mock_tls
):
    trust, snapshot = provisioning
    state = snapshot["udapi"]["services"]["messageBroker"]["flowConfiguration"]
    state["eventState"] = ["conntrack"]
    config = broker.decode_broker_provisioning(
        json.dumps(snapshot), trust=trust, required_event_state="conntrack"
    )

    broker.UniFiBrokerPublisher(config).publish(
        completed_flow.event_id, completed_flow.event
    )

    publish = transport.calls[3][1]
    assert publish["routing_key"] == "unifi_flow_queue"
    assert publish["mandatory"]
    assert publish["properties"]["content_type"] == "text/plain"
    assert publish["properties"]["message_id"] == completed_flow.event_id
    assert json.loads(publish["body"]) == completed_flow.event


def test_rejects_events_without_their_own_provisioned_state(
    provisioning, completed_flow, event, transport
):
    trust, snapshot = provisioning
    state = snapshot["udapi"]["services"]["messageBroker"]["flowConfiguration"]
    ips_config = broker.decode_broker_provisioning(json.dumps(snapshot), trust=trust)
    state["eventState"] = ["conntrack"]
    conntrack_config = broker.decode_broker_provisioning(
        json.dumps(snapshot), trust=trust, required_event_state="conntrack"
    )

    with pytest.raises(broker.BrokerPublishError, match="conntrack"):
        broker.UniFiBrokerPublisher(ips_config).publish(
            completed_flow.event_id, completed_flow.event
        )
    with pytest.raises(broker.BrokerPublishError, match="ipsIds"):
        broker.UniFiBrokerPublisher(conntrack_config).publish("a" * 64, event)
    assert transport.calls == []


@pytest.mark.parametrize(
    ("path", "invalid"),
    [
        (("site_id",), "f86e2468-0000-4000-8000-000000000009"),
        (("gateway_mac",), "02:00:00:00:00:04"),
        (("action",), "DROP"),
        (("flow_id",), 1 << 63),
        (("expiry",), 1795533952877374043),
        (("stats", "txPackets"), False),
        (("stats", "rxBytes"), -1),
        (("stats", "payload"), "no"),
        (("ip", "dport"), "18686"),
        (("ip", "daddr"), "::1"),
        (("ip", "protocol"), 17),
        (("timestamp",), "2026-11-24T15:25:47.877657000"),
        (("flow_end",), "2026-11-24T15:25:47.875000000Z"),
    ],
)
def test_rejects_invalid_completed_metadata_before_connecting(
    provisioning, completed_flow, transport, path, invalid
):
    trust, snapshot = provisioning
    state = snapshot["udapi"]["services"]["messageBroker"]["flowConfiguration"]
    state["eventState"] = ["conntrack", "ipsIds"]
    config = broker.decode_broker_provisioning(json.dumps(snapshot), trust=trust)
    bad = completed_flow.event
    target = bad
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = invalid

    with pytest.raises(broker.BrokerPublishError):
        broker.UniFiBrokerPublisher(config).publish(completed_flow.event_id, bad)
    assert transport.calls == []


def test_rejects_arbitrary_hash_for_valid_completed_flow(
    provisioning, completed_flow, transport
):
    trust, snapshot = provisioning
    snapshot["udapi"]["services"]["messageBroker"]["flowConfiguration"][
        "eventState"
    ].append("conntrack")
    config = broker.decode_broker_provisioning(json.dumps(snapshot), trust=trust)
    with pytest.raises(broker.BrokerPublishError, match="identity"):
        broker.UniFiBrokerPublisher(config).publish("a" * 64, completed_flow.event)
    assert transport.calls == []
