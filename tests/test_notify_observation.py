from dataclasses import replace
from datetime import datetime, timedelta, timezone

import pytest


_BOOT = "a263fe32-0e42-4b9d-9852-cacab4122303"
_CAPTURE = "a91af55d6ff14861b6fcb40bb112abfd"
_OTHER_CAPTURE = "29bed5f0615f43018c73d9dbb7b38054"
_TIME = 1_764_002_381_094_495_000
_VIFS = ("eth3.110", "eth3.120")
_HOSTS = ("192.168.110.2", "192.168.120.2")
_PORTS = (41873, 18743)


@pytest.fixture
def observation():
    from inspection.notify_observation import forwarding_observed
    from inspection.notify_capture import (
        APPROVED_NOTIFY_SCOPE,
        NotifyCapture,
        TcpObservation,
    )

    def ingress(timestamp_ns, *, seq, flags, payload_len, ip_id):
        return TcpObservation(
            timestamp_ns=timestamp_ns,
            interface=_VIFS[0],
            direction="ingress",
            src_ip=_HOSTS[0],
            dst_ip=_HOSTS[1],
            src_port=_PORTS[0],
            dst_port=_PORTS[1],
            seq=seq,
            ack=0 if flags == 2 else 16,
            flags=flags,
            payload_len=payload_len,
            ip_id=ip_id,
            ttl=64,
        )

    def egress(packet):
        return replace(
            packet,
            timestamp_ns=packet.timestamp_ns + 2_000,
            interface=_VIFS[1],
            direction="egress",
            ttl=63,
        )

    syn = ingress(_TIME - 1_600_337, seq=31, flags=2, payload_len=0, ip_id=100)
    earlier = ingress(_TIME - 500_900, seq=32, flags=24, payload_len=5, ip_id=101)
    target = ingress(_TIME + 175, seq=37, flags=24, payload_len=26, ip_id=102)
    timestamp = datetime(1970, 1, 1, tzinfo=timezone.utc) + timedelta(
        microseconds=_TIME // 1000
    )
    eve = {
        "event_type": "alert",
        "timestamp": timestamp.strftime("%Y-%m-%dT%H:%M:%S.%f%z"),
        "flow_id": 1_524_521_128_064_194,
        "src_ip": _HOSTS[0],
        "src_port": _PORTS[0],
        "dest_ip": _HOSTS[1],
        "dest_port": _PORTS[1],
        "proto": "TCP",
        "in_iface": _VIFS[0],
        "pkt_src": "wire/pcap",
        "direction": "to_server",
        "alert": {"gid": 1, "signature_id": 1_000_043, "rev": 1, "action": "allowed"},
        "verdict": {"action": "alert"},
    }
    capture = NotifyCapture(
        boot_id=_BOOT,
        capture_id=_CAPTURE,
        start_ns=_TIME - 2_000_000,
        end_ns=_TIME + 100_000,
        observations=(
            syn,
            egress(syn),
            earlier,
            egress(earlier),
            target,
            egress(target),
        ),
        dropped=0,
        complete=True,
    )

    def check(record=eve, **overrides):
        options = {
            "scope": APPROVED_NOTIFY_SCOPE,
            "capture": capture,
            "boot_id": _BOOT,
            "capture_id": _CAPTURE,
        }
        return forwarding_observed(record, **{**options, **overrides})

    return check, eve, capture


def test_wire_alert_matches_one_original_routed_segment(observation):
    check, _, _ = observation
    assert check() is True


def test_earlier_forwarded_data_cannot_prove_the_alerted_segment(observation):
    check, _, capture = observation
    assert (
        check(capture=replace(capture, observations=capture.observations[:-1])) is False
    )


@pytest.mark.parametrize(
    "changed",
    [
        {"interface": "eth3.140"},
        {"direction": "ingress"},
        {"src_port": 49152},
        {"seq": 38},
        {"ack": 17},
        {"flags": 16},
        {"payload_len": 25},
        {"ip_id": 999},
        {"ttl": 64},
    ],
)
def test_egress_must_match_the_exact_alert_segment(observation, changed):
    check, _, capture = observation
    *preceding, output = capture.observations
    edited = replace(capture, observations=(*preceding, replace(output, **changed)))
    assert check(capture=edited) is False


@pytest.mark.parametrize(
    "changed",
    [
        {"in_iface": "eth3.120"},
        {"pkt_src": "stream/stream"},
        {"direction": "to_client"},
        {"flow_id": False},
        {"proto": "UDP"},
        {"dest_port": 18744},
        {"src_ip": "192.168.110.3"},
        {"verdict": {"action": "pass"}},
        {"verdict": {"action": "drop"}},
        {"alert": {"gid": 1, "signature_id": 1_000_044, "rev": 1, "action": "allowed"}},
    ],
)
def test_only_the_pinned_passive_wire_alert_can_receive_proof(observation, changed):
    check, eve, _ = observation
    assert check({**eve, **changed}) is False


def test_requires_exact_microsecond_eve_timestamp(observation):
    check, eve, _ = observation
    assert (
        check({**eve, "timestamp": eve["timestamp"].replace(".094495", ".094496")})
        is False
    )
    assert (
        check({**eve, "timestamp": eve["timestamp"].replace(".094495", ".0944951")})
        is False
    )
    utc_record = {**eve, "timestamp": eve["timestamp"].replace("+0000", "Z")}
    assert check(utc_record) is True


def test_ambiguous_microsecond_and_repeated_fingerprints_are_rejected(observation):
    check, _, capture = observation
    *preceding, target, output = capture.observations
    same_microsecond = replace(target, timestamp_ns=target.timestamp_ns + 1, ip_id=103)
    delayed_duplicate = replace(target, timestamp_ns=target.timestamp_ns - 1_500)
    for events in (
        (*preceding, target, same_microsecond, output),
        (*preceding, delayed_duplicate, target, output),
        (
            *preceding,
            target,
            output,
            replace(output, timestamp_ns=output.timestamp_ns + 1),
        ),
    ):
        assert check(capture=replace(capture, observations=events)) is False


def test_requires_one_forwarded_connection_incarnation_within_capture(observation):
    check, _, capture = observation
    syn_in, syn_out, *data = capture.observations
    assert check(capture=replace(capture, observations=tuple(data))) is False
    assert check(capture=replace(capture, observations=(syn_in, *data))) is False
    new_syn = replace(
        syn_in, timestamp_ns=syn_out.timestamp_ns + 200, seq=50, ip_id=200
    )
    assert (
        check(capture=replace(capture, observations=(syn_in, syn_out, new_syn, *data)))
        is False
    )


def test_does_not_use_ingress_egress_out_of_capture_order_or_after_close(observation):
    check, _, capture = observation
    *preceding, target, output = capture.observations
    preceding_output = replace(output, timestamp_ns=target.timestamp_ns - 1)
    closing = replace(
        target, timestamp_ns=target.timestamp_ns - 3, flags=17, payload_len=0
    )
    for events in (
        (*preceding, preceding_output, target),
        (*preceding, output, target),
        (*preceding, closing, target, output),
    ):
        assert check(capture=replace(capture, observations=events)) is False


def test_independently_scoped_client_ports_do_not_collide(observation):
    check, _, capture = observation
    *preceding, target, output = capture.observations
    adjacent_conn = replace(
        target, timestamp_ns=target.timestamp_ns + 1, src_port=49152
    )
    assert check(
        capture=replace(
            capture, observations=(*preceding, target, adjacent_conn, output)
        )
    )


def test_egress_outside_the_maximum_transit_cannot_prove_the_alert(observation):
    check, _, capture = observation
    *preceding, target, output = capture.observations
    output = replace(output, timestamp_ns=target.timestamp_ns + 1_000_000_001)
    assert (
        check(
            capture=replace(
                capture,
                end_ns=output.timestamp_ns,
                observations=(*preceding, target, output),
            )
        )
        is False
    )


def test_capture_must_be_complete_loss_free_and_from_the_bound_generation(observation):
    check, _, capture = observation
    for changes in (
        {"complete": False},
        {"dropped": 1},
        {"boot_id": "cda36f8b-8ca3-4671-9c16-2b4e8634e7eb"},
        {"capture_id": _OTHER_CAPTURE},
        {"start_ns": capture.observations[0].timestamp_ns + 1},
        {"end_ns": capture.observations[-1].timestamp_ns - 1},
    ):
        assert check(capture=replace(capture, **changes)) is False
    assert check(capture_id=_OTHER_CAPTURE) is False
