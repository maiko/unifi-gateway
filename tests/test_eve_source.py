import io
import json
import selectors
import subprocess
import sys
from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace

import pytest

from inspection.event_delivery import project_observation
from inspection.suricata import decode_eve_event


@pytest.fixture
def drop():
    path = Path(__file__).parent / "fixtures" / "uxg_pro" / "eve-inline-drop.json"
    return json.loads(path.read_text())


@pytest.fixture
def passive():
    path = Path(__file__).parent / "fixtures" / "uxg_pro" / "eve-passive-alert.json"
    return json.loads(path.read_text())


def line(record):
    return json.dumps(record).encode() + b"\n"


def test_verified_final_drop_becomes_existing_delivery_input(drop):
    from inspection.eve_source import iter_drop_observations

    drop["alert"]["action"] = "allowed"
    drop["sensor_id"] = 5
    drop["pcap_cnt"] = 27
    clean = deepcopy(drop)
    drop["payload_printable"] = "secret payload"
    drop["flow"]["http"] = {"authorization": "secret header"}
    drop["alert"]["metadata"] = {"token": ["secret rule value"]}
    drop["verdict"]["reject-target"] = "server"

    [observation] = iter_drop_observations(io.BytesIO(line(drop)))
    assert observation == {"eve": clean, "forwarding_observed": False}
    trust = SimpleNamespace(site_id="lab", gateway_mac="02:00:00:00:00:01")
    event_id, event = project_observation(observation, trust=trust)
    assert event["action"] == "DROP"
    assert event_id == decode_eve_event(drop).event_id
    assert event["flow"]["bytes_toserver"] == 1019
    assert "secret" not in repr(observation)


def test_never_promotes_a_rule_action_or_inline_pass_to_forwarding_evidence(drop):
    from inspection.eve_source import iter_drop_observations

    stream = io.BytesIO(
        b"".join(
            line(record)
            for record in (
                {"event_type": "flow"},
                {k: v for k, v in drop.items() if k != "verdict"},
                {**drop, "verdict": {"action": "pass"}},
                {**drop, "verdict": {"action": "alert"}},
                {**drop, "verdict": {"action": "unknown"}},
            )
        )
    )
    reject = []
    assert list(iter_drop_observations(stream, on_rejection=reject.append)) == []
    assert reject == []


@pytest.mark.parametrize(
    ("path", "invalid"),
    [
        (("flow",), {}),
        (("flow", "start"), "2026-11-24T14:25:58.129323+0000"),
        (("flow", "start"), "2026-11-24T14:23:58.129323"),
        (("flow", "pkts_toserver"), False),
        (("flow", "bytes_toserver"), 1 << 63),
        (("flow_id",), 0),
        (("alert", "signature"), ""),
        (("alert", "signature"), "x" * 1025),
        (("alert", "category"), "\ud800"),
        (("alert", "severity"), 5),
        (("alert", "gid"), 1 << 31),
        (("src_ip",), "invalid-address"),
        (("proto",), "SCTP"),
    ],
)
def test_malformed_final_drop_is_reported_and_following_drop_survives(
    drop, path, invalid
):
    from inspection.eve_source import iter_drop_observations

    bad = deepcopy(drop)
    target = bad
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = invalid
    rejected = []
    stream = io.BytesIO(line(bad) + line(drop))

    assert list(iter_drop_observations(stream, on_rejection=rejected.append)) == [
        {"eve": drop, "forwarding_observed": False}
    ]
    assert rejected == ["invalid-drop"]


def test_framing_resyncs_and_never_reads_unbounded_lines(drop):
    from inspection.eve_source import MAX_RECORD_BYTES, iter_drop_observations

    class BoundedStream(io.BytesIO):
        def readline(self, size):
            assert 0 < size <= MAX_RECORD_BYTES + 1
            return super().readline(size)

    rejects = []
    stream = BoundedStream(
        b"X" * (MAX_RECORD_BYTES * 3)
        + b"\n"
        + b'{"invalid":"\xff"}\n'
        + b'{"flow_id":1,"flow_id":2}\n'
        + b'{"sensor_id":NaN}\n'
        + line(drop)
        + line(drop)[:-1]
    )
    assert list(iter_drop_observations(stream, on_rejection=rejects.append)) == [
        {"eve": drop, "forwarding_observed": False}
    ]
    assert rejects == [
        "oversized",
        "malformed",
        "malformed",
        "malformed",
        "unterminated",
    ]


def test_streaming_cli_flushes_verified_drop_before_input_closes(drop):
    first = line(drop)
    with subprocess.Popen(
        [sys.executable, "-m", "inspection.eve_source"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    ) as process:
        with selectors.DefaultSelector() as ready:
            ready.register(process.stdout, selectors.EVENT_READ)
            process.stdin.write(first[:-1])
            process.stdin.flush()
            assert not ready.select(0.15)
            process.stdin.write(b"\n")
            process.stdin.flush()
            assert ready.select(3)
            assert json.loads(process.stdout.readline()) == {
                "eve": drop,
                "forwarding_observed": False,
            }
        process.stdin.write(b"malformed\n" + first)
        process.stdin.flush()
        output, errors = process.communicate(timeout=3)
        assert process.returncode == 0
        assert json.loads(output)["eve"] == drop
        assert b"malformed=1" in errors
        assert b"isolated broker test marker" not in errors


def test_stream_exits_cleanly_when_delivery_closes_its_input(drop):
    with subprocess.Popen(
        [sys.executable, "-m", "inspection.eve_source"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    ) as process:
        process.stdout.close()
        process.stdin.write(line(drop))
        process.stdin.flush()

        assert process.wait(timeout=3) == 1
        assert process.stderr.read().splitlines() == [
            b"EVE stream stopped because delivery closed its input"
        ]


@pytest.fixture
def paired_capture(drop):
    return split_capture(
        drop,
        end="2026-11-24T14:24:00.110000+0000",
        logged_at="2026-11-24T14:24:03.000000+0000",
    )


def split_capture(observed, *, end, logged_at):
    # The alert header and counters came from the same recorded 7.0.10 flow.
    # The original extractor omitted end and log time. Fixture values fill in
    # those fields to exercise the completed-flow interval checks.
    alert = deepcopy(observed)
    counts = alert.pop("flow")
    flow = {
        key: alert[key]
        for key in ("flow_id", "src_ip", "src_port", "dest_ip", "dest_port", "proto")
    }
    flow.update(
        event_type="flow",
        timestamp=logged_at,
        flow={
            **counts,
            "end": end,
            "alerted": True,
        },
    )
    return alert, flow


def test_same_engine_pair_projects_real_counters_and_preserves_replay_identity(
    drop, paired_capture
):
    from inspection.eve_source import iter_eve_observations

    alert, flow = paired_capture
    alert["payload_printable"] = "private request body"
    flow["flow"]["metadata"] = {"private": "request header"}
    stream = io.BytesIO(line(alert) + line(flow) + line(alert) + line(flow))

    outputs = list(iter_eve_observations(stream, same_engine_flows=True))

    assert outputs == [{"eve": drop, "forwarding_observed": False}] * 2
    trust = SimpleNamespace(site_id="lab", gateway_mac="02:00:00:00:00:01")
    event_id, event = project_observation(outputs[0], trust=trust)
    assert event_id == decode_eve_event(alert).event_id
    assert event["action"] == "DROP"
    assert event["flow"]["pkts_toclient"] == 1
    assert event["flow"]["bytes_toserver"] == 1019


def test_passive_pair_needs_explicit_independent_proof_for_exact_alert(passive):
    from inspection.eve_source import iter_eve_observations

    alert, flow = split_capture(
        passive,
        end="2026-11-24T14:23:23.680000+0000",
        logged_at="2026-11-24T14:23:28.000000+0000",
    )
    data = line(alert) + line(flow)
    event_id = decode_eve_event(alert).event_id

    assert list(iter_eve_observations(io.BytesIO(data), same_engine_flows=True)) == []
    neighbors = [event_id[:-1] + ("a" if event_id[-1] != "a" else "b")]
    assert (
        list(
            iter_eve_observations(
                io.BytesIO(data), same_engine_flows=True, forwarded_event_ids=neighbors
            )
        )
        == []
    )
    [observation] = list(
        iter_eve_observations(
            io.BytesIO(data), same_engine_flows=True, forwarded_event_ids=[event_id]
        )
    )
    trust = SimpleNamespace(site_id="lab", gateway_mac="02:00:00:00:00:01")
    event = project_observation(observation, trust=trust)[1]
    assert event["action"] == "ACCEPT"
    assert event["flow"]["bytes_toclient"] == 456


@pytest.mark.parametrize(
    ("changed", "value"),
    [
        ("src_port", 49999),
        ("flow_id", 99999),
        ("end", "2026-11-24T14:23:58.129323+0000"),
        ("alerted", False),
        ("start", "2026-11-24T14:23:58.131323+0000"),
        ("bytes_toserver", False),
        ("timestamp", "2026-11-24T14:23:58.130493+0000"),
    ],
)
def test_never_pairs_wrong_tuple_or_unobserved_flow_values(
    paired_capture, changed, value
):
    from inspection.eve_source import iter_eve_observations

    alert, flow = paired_capture
    if changed in flow:
        flow[changed] = value
    else:
        flow["flow"][changed] = value

    assert (
        list(
            iter_eve_observations(
                io.BytesIO(line(alert) + line(flow)), same_engine_flows=True
            )
        )
        == []
    )


def test_pending_alerts_have_bounded_cache_and_flow_replay_is_opt_in(
    paired_capture, monkeypatch
):
    from inspection import eve_source

    alert, flow = paired_capture
    two = {**alert, "flow_id": alert["flow_id"] + 1}
    three = {**alert, "flow_id": alert["flow_id"] + 2}
    third_flow = {**flow, "flow_id": three["flow_id"]}
    data = b"".join(line(record) for record in (alert, two, three, flow, third_flow))
    monkeypatch.setattr(eve_source, "_MAX_PENDING_FLOWS", 2)
    rejected = []

    assert list(eve_source.iter_drop_observations(io.BytesIO(data))) == []
    observations = list(
        eve_source.iter_eve_observations(
            io.BytesIO(data), same_engine_flows=True, on_rejection=rejected.append
        )
    )
    assert [row["eve"]["flow_id"] for row in observations] == [three["flow_id"]]
    assert rejected == ["pending-flow-limit", "unpaired-alert"]


def test_split_flow_cli_waits_for_completion_and_accepts_only_named_passive_alert(
    passive,
):
    alert, flow = split_capture(
        passive,
        end="2026-11-24T14:23:23.680000+0000",
        logged_at="2026-11-24T14:23:28.000000+0000",
    )
    event_id = decode_eve_event(alert).event_id
    command = [
        sys.executable,
        "-m",
        "inspection.eve_source",
        "--same-engine-flows",
        "--forwarded-event-id",
        event_id,
    ]
    with subprocess.Popen(
        command,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    ) as process:
        with selectors.DefaultSelector() as ready:
            ready.register(process.stdout, selectors.EVENT_READ)
            process.stdin.write(line(alert))
            process.stdin.flush()
            assert not ready.select(0.15)
            process.stdin.write(line(flow))
            process.stdin.flush()
            assert ready.select(3)
            assert json.loads(process.stdout.readline()) == {
                "eve": passive,
                "forwarding_observed": True,
            }

        output, errors = process.communicate(timeout=3)
        assert process.returncode == 0
        assert output == b""
        assert errors == b""


def test_split_records_cannot_pair_across_separate_engine_streams(paired_capture):
    from inspection.eve_source import iter_eve_observations

    alert, flow = paired_capture
    assert (
        list(iter_eve_observations(io.BytesIO(line(alert)), same_engine_flows=True))
        == []
    )
    assert (
        list(iter_eve_observations(io.BytesIO(line(flow)), same_engine_flows=True))
        == []
    )
