import json
from pathlib import Path

import pytest

from inspection.vyos_control import _PLAN, _PrivateFiles


@pytest.fixture
def feed(tmp_path):
    from inspection import vyos_eve_feed

    path = tmp_path / "private"
    path.mkdir(mode=0o700)
    return vyos_eve_feed, _PrivateFiles(path)


def alert(**changes):
    event = json.loads(
        (Path(__file__).parent / "fixtures/uxg_pro/eve-inline-drop.json").read_bytes()
    )
    event["dest_port"] = 18743
    event["alert"]["signature_id"] = 1000043
    event["alert"]["signature"] = "UXG isolated post-policy marker"
    return {**event, **changes}


def flow():
    event = alert(event_type="flow")
    event["flow"].update(end=event["timestamp"], alerted=True)
    event.pop("alert")
    return event


def append(files, *records):
    with (files.root / "eve.json").open("ab") as stream:
        for value in records:
            stream.write(json.dumps(value).encode() + b"\n")
        return stream.tell()


def read(module, files, generations, cursor=None):
    return module.read_events(files, generations, cursor, scope=_PLAN.scope)


def position(response):
    return {"generation": response["generation"], "offset": response["offset"]}


def test_cut_excludes_old_bytes_and_final_drop_is_strictly_sanitized(feed):
    module, files = feed
    files.write("eve.json", b"")
    prior = append(files, alert(timestamp="2028-11-24T14:23:58.130493+0000"))
    generations = module.start_generation(files, (), "block")
    assert generations[-1].offset == prior

    event = alert(payload="secret", app_proto="secret")
    event["alert"]["metadata"] = {"secret": "value"}
    event["flow"]["secret"] = "value"
    end = append(files, alert(verdict={"action": "alert"}), alert(dest_port=8443), event)
    result = read(module, files, generations)
    assert result == {
        "schema": 1, "phase": "read-events", "status": "records",
        "generation": generations[-1].id, "offset": end, "record": alert(),
    }
    assert len(json.dumps(result).encode()) < 4096


def test_drains_sealed_block_and_crosses_notify_without_exporting_it(feed):
    module, files = feed
    generations = module.start_generation(files, (), "block")
    first = append(files, alert())
    old = read(module, files, generations)
    assert old["offset"] == first
    finished = append(files, flow())
    generations = module.seal_generation(files, generations)
    remaining = read(module, files, generations, position(old))
    assert remaining["record"]["event_type"] == "flow"
    assert remaining["record"]["flow"]["alerted"] is True
    assert "verdict" not in remaining["record"]
    assert remaining["offset"] == finished

    generations = module.start_generation(files, generations, "notify")
    append(files, alert(), flow())
    generations = module.seal_generation(files, generations)
    generations = module.start_generation(files, generations, "block")
    end = append(files, alert(flow_id=42))

    transition = read(module, files, generations, position(remaining))
    assert transition["status"] == "idle" and transition["record"] is None
    assert position(transition) == {"generation": generations[-1].id, "offset": generations[-1].offset}
    current = read(module, files, generations, position(transition))
    assert current["record"]["flow_id"] == 42 and current["offset"] == end


def test_notify_waits_for_scoped_proof_and_exports_only_a_verified_forward(feed):
    module, files = feed
    generation, = module.start_generation(files, (), "notify")
    sample = alert(verdict={"action": "alert"}, in_iface="eth3.110", pkt_src="wire/pcap")
    sample["alert"]["action"] = "allowed"
    first = append(files, sample)
    end = append(files, flow())

    def reply(check):
        def verify(item, event):
            assert item == generation and event["in_iface"] == "eth3.110"
            return check
        return verify

    scope = _PLAN.scope
    initial = module.read_events(files, (generation,), None, scope=scope, notify_proof=reply(None))
    assert initial == module.feed_response("idle", generation.id, generation.offset)
    verified = module.read_events(files, (generation,), position(initial), scope=scope, notify_proof=reply(True))
    assert verified["forwarding_observed"] is True
    assert verified["offset"] == first and "in_iface" not in verified["record"]
    completed = module.read_events(files, (generation,), position(verified), scope=scope, notify_proof=reply(False))
    assert "forwarding_observed" not in completed and completed["offset"] == end
    unverified = module.read_events(files, (generation,), None, scope=scope, notify_proof=reply(False))
    assert unverified["record"]["event_type"] == "flow" and "forwarding_observed" not in unverified


def test_file_identity_and_partial_cursor_fail_closed(feed):
    module, files = feed
    generations = module.start_generation(files, (), "block")
    with (files.root / "eve.json").open("ab") as stream:
        stream.write(b'{"incomplete":')
    idle = read(module, files, generations)
    assert idle["status"] == "idle" and idle["offset"] == 0
    assert read(module, files, generations, {"generation": generations[-1].id, "offset": 1})["status"] == "gap"

    files.write("eve.json", b"")
    append(files, alert())
    invalid = read(module, files, generations, position(idle))
    assert invalid["status"] == "gap" and invalid["generation"] is None


def test_irrelevant_scan_advances_and_oversized_line_fails_bounded(feed):
    module, files = feed
    generations = module.start_generation(files, (), "block")
    end = append(files, {"event_type": "stats"})
    idle = read(module, files, generations)
    assert idle["status"] == "idle" and idle["offset"] == end
    with (files.root / "eve.json").open("ab") as stream:
        stream.write(b"a" * (module.MAX_RECORD_BYTES + 1))
    result = read(module, files, generations, position(idle))
    assert result["status"] == "gap" and result["record"] is None


def test_truncated_latest_generation_does_not_replay_an_older_block(feed):
    module, files = feed
    generations = module.start_generation(files, (), "block")
    old_end = append(files, alert())
    generations = module.seal_generation(files, generations)
    append(files, {"event_type": "stats"})
    generations = module.start_generation(files, generations, "block")
    append(files, alert(flow_id=42))

    with (files.root / "eve.json").open("r+b") as stream:
        stream.truncate(old_end)

    fresh = read(module, files, generations)
    assert fresh == module.feed_response("gap")
    old = read(module, files, generations, {"generation": generations[0].id, "offset": 0})
    assert old["record"]["flow_id"] == alert()["flow_id"]
    assert read(module, files, generations, position(old))["status"] == "gap"


def test_history_is_bounded_and_evicted_cursor_reports_gap_to_latest(feed):
    module, files = feed
    generations = module.start_generation(files, (), "block")
    cursor = {"generation": generations[0].id, "offset": 0}
    for _ in range(module.MAX_GENERATIONS):
        generations = module.start_generation(files, module.seal_generation(files, generations), "block")
    assert len(generations) == module.MAX_GENERATIONS
    assert read(module, files, generations, cursor) == module.feed_response(
        "gap", generations[-1].id, generations[-1].offset
    )
