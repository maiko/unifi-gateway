import json
import sqlite3
from pathlib import Path
from types import SimpleNamespace

import pytest

from inspection.unifi_broker import BrokerPublishError


FIRST = "a" * 32
SECOND = "b" * 32
TRUST = SimpleNamespace(site_id="lab", gateway_mac="02:00:00:00:00:01")


def response(status, generation, offset, record=None):
    return {"schema": 1, "phase": "read-events", "status": status,
            "generation": generation, "offset": offset, "record": record}


def cursor(generation, offset):
    return {"generation": generation, "offset": offset}


@pytest.fixture
def observed_drop():
    path = Path(__file__).parent / "fixtures/uxg_pro/eve-inline-drop.json"
    return json.loads(path.read_text())


@pytest.fixture
def observed_notify():
    path = Path(__file__).parent / "fixtures/uxg_pro/eve-passive-alert.json"
    return json.loads(path.read_text())


def split(observation):
    alert = dict(observation)
    counts = alert.pop("flow")
    flow = {key: alert[key] for key in ("flow_id", "src_ip", "src_port", "dest_ip", "dest_port", "proto")}
    flow.update(event_type="flow", timestamp=alert["timestamp"],
                flow={**counts, "end": alert["timestamp"], "alerted": True})
    return alert, flow


def worker(tmp_path, source, publish, *, trust=TRUST, drop_enabled=True, notify_enabled=True):
    from inspection.event_worker import EventWorker

    return EventWorker(source, lambda: (trust, SimpleNamespace(publish=publish)),
                       tmp_path / "events.db", tmp_path / "cursor.json",
                       drop_enabled=drop_enabled, notify_enabled=notify_enabled)


def test_worker_recovers_unpaired_alert_and_dedupes_replayed_outbox(tmp_path, observed_drop):
    alert, flow = split(observed_drop)
    alert["payload_printable"] = "private wire contents"
    sent = []
    state = tmp_path / "cursor.json"

    def first_source(current):
        assert current is None
        return response("records", FIRST, 100, alert)

    assert worker(tmp_path, first_source, None).poll()
    assert state.stat().st_mode & 0o777 == 0o600
    assert "private wire contents" not in state.read_text()

    def source(current):
        if current == cursor(FIRST, 100):
            return response("records", FIRST, 200, flow)
        assert current == cursor(FIRST, 200)
        return response("idle", FIRST, 200)

    restarted = worker(tmp_path, source, lambda event_id, event: sent.append((event_id, event)))
    assert restarted.poll()
    before_publish = state.read_bytes()
    assert restarted.poll()
    assert len(sent) == 1 and sent[0][1]["action"] == "DROP"
    assert sent[0][1]["flow"]["bytes_toserver"] == observed_drop["flow"]["bytes_toserver"]

    state.write_bytes(before_publish)
    final = worker(tmp_path, source, lambda *_: pytest.fail("duplicate publication"))
    assert final.poll()
    assert not final.poll()


def test_notify_requires_relay_proof_and_a_completed_flow_across_restart(tmp_path, observed_notify):
    _, flow = split(observed_notify)
    state = tmp_path / "cursor.json"
    early = {**observed_notify, "flow": {**observed_notify["flow"], "bytes_toserver": 0}}
    proven = {**response("records", FIRST, 100, early), "forwarding_observed": True}

    active = worker(tmp_path, lambda _: proven, lambda *_: pytest.fail("published before flow completion"))
    assert active.poll()
    assert json.loads(state.read_text())["ready"] == []

    def source(current):
        if current == cursor(FIRST, 100):
            return response("records", FIRST, 200, flow)
        assert current == cursor(FIRST, 200)
        return response("idle", FIRST, 200)

    sent = []
    restarted = worker(tmp_path, source, lambda *event: sent.append(event))
    assert restarted.poll()
    before_publish = state.read_bytes()
    assert restarted.poll()
    assert len(sent) == 1 and sent[0][1]["action"] == "ACCEPT"
    assert sent[0][1]["flow"]["bytes_toserver"] == observed_notify["flow"]["bytes_toserver"]

    state.write_bytes(before_publish)
    replayed = worker(tmp_path, source, lambda *_: pytest.fail("published duplicate Notify"))
    assert replayed.poll()
    assert not replayed.poll()


def test_notify_does_not_infer_forwarding_from_eve_or_a_nested_proof(tmp_path, observed_notify):
    alert, flow = split(observed_notify)
    alert["forwarding_observed"] = True
    replies = iter([response("records", FIRST, 10, alert), response("records", FIRST, 20, flow),
                    response("idle", FIRST, 20)])
    active = worker(tmp_path, lambda _: next(replies), lambda *_: pytest.fail("inferred forwarding"))
    assert active.poll()
    assert active.poll()
    assert not active.poll()


@pytest.mark.parametrize("forwarded", [False, True])
def test_worker_skips_events_in_disabled_modes(tmp_path, observed_notify, observed_drop, forwarded):
    alert, flow = split(observed_notify if forwarded else observed_drop)
    first = response("records", FIRST, 10, alert)
    if forwarded:
        first["forwarding_observed"] = True
    replies = iter([first, response("records", FIRST, 20, flow), response("idle", FIRST, 20)])
    active = worker(tmp_path, lambda _: next(replies), lambda *_: pytest.fail("published a disabled mode"),
                    drop_enabled=forwarded, notify_enabled=not forwarded)
    assert active.poll()
    assert active.poll()
    assert not active.poll()
    state = json.loads((tmp_path / "cursor.json").read_text())
    assert state["cursor"] == cursor(FIRST, 20) and not state["ready"] and not state["pending"]


def test_disabling_notify_clears_pending_proof_even_while_feed_is_idle(tmp_path, observed_notify):
    alert, flow = split(observed_notify)
    proven = {**response("records", FIRST, 10, alert), "forwarding_observed": True}

    def publish(*_):
        pytest.fail("published previously disabled Notify")

    assert worker(tmp_path, lambda _: proven, publish).poll()
    disabled = worker(tmp_path, lambda _: response("idle", FIRST, 10), publish, notify_enabled=False)
    assert disabled.poll()
    assert not disabled.poll()
    source = iter([response("records", FIRST, 20, flow), response("idle", FIRST, 20)])
    enabled = worker(tmp_path, lambda _: next(source), publish)
    assert enabled.poll()
    assert not enabled.poll()


@pytest.mark.parametrize(("status", "kind", "proof"), [
    ("records", "notify", 1), ("records", "notify", False), ("records", "notify", None),
    ("records", "notify", "true"), ("records", "drop", True), ("records", "flow", True),
    ("records", "pass", True), ("records", "blocked", True), ("idle", None, True), ("gap", None, True),
])
def test_malformed_relay_proof_cannot_advance_checkpoint(tmp_path, observed_notify, observed_drop, status, kind, proof):
    _, flow = split(observed_notify)
    records = {
        "notify": observed_notify, "drop": observed_drop, "flow": flow,
        "pass": {**observed_notify, "verdict": {"action": "pass"}},
        "blocked": {**observed_notify, "alert": {**observed_notify["alert"], "action": "blocked"}},
    }
    observed = {**response(status, FIRST, 10, records.get(kind)), "forwarding_observed": proof}
    active = worker(tmp_path, lambda _: observed, lambda *_: pytest.fail("malformed proof accepted"))

    with pytest.raises(ValueError, match="forwarding proof"):
        active.poll()
    assert not (tmp_path / "cursor.json").exists()


def test_old_drop_checkpoint_keeps_ready_and_pending_records(tmp_path, observed_drop):
    new_drop = {**observed_drop, "flow_id": observed_drop["flow_id"] + 1}
    pending, flow = split(new_drop)
    state = tmp_path / "cursor.json"
    state.write_text(json.dumps({"schema": 1, "site": TRUST.site_id, "gateway": TRUST.gateway_mac,
                                 "cursor": cursor(FIRST, 10), "ready": [observed_drop], "pending": [pending]}))
    state.chmod(0o600)
    sent = []
    active = worker(tmp_path, lambda _: response("records", FIRST, 20, flow),
                    lambda *event: sent.append(event))

    for _ in range(3):
        assert active.poll()

    assert [event["action"] for _, event in sent] == ["DROP", "DROP"]
    assert json.loads(state.read_text())["schema"] == 2


@pytest.mark.parametrize("transition", ["gap", "idle"])
@pytest.mark.parametrize("mode", ["drop", "notify"])
def test_worker_does_not_pair_across_engine_generations(tmp_path, observed_drop, observed_notify, transition, mode, caplog):
    alert, flow = split(observed_notify if mode == "notify" else observed_drop)
    first = response("records", FIRST, 10, alert)
    if mode == "notify":
        first["forwarding_observed"] = True
    records = iter([first, response(transition, SECOND, 20),
                    response("records", SECOND, 40, flow), response("idle", SECOND, 40)])
    active = worker(tmp_path, lambda _: next(records), lambda *_: pytest.fail("cross-generation publication"))
    for _ in range(3):
        assert active.poll()
    assert not active.poll()
    if transition == "idle":
        assert "unpaired alerts expired" in caplog.text


def test_ambiguous_send_does_not_stall_next_event(tmp_path, observed_drop):
    newer = {**observed_drop, "flow_id": observed_drop["flow_id"] + 1}
    responses = iter([response("records", FIRST, offset, event) for offset, event in (
        (10, observed_drop), (20, observed_drop), (30, newer),
    )])
    attempts = []

    def publish(event_id, _event):
        attempts.append(event_id)
        if len(attempts) == 1:
            raise BrokerPublishError("ambiguous result")

    active = worker(tmp_path, lambda _: next(responses), publish)
    for _ in range(6):
        assert active.poll()
    assert len(set(attempts)) == 2
    with sqlite3.connect(tmp_path / "events.db") as journal:
        assert journal.execute("SELECT COUNT(*) FROM deliveries WHERE confirmed=0").fetchone() == (1,)
        assert journal.execute("SELECT COUNT(*) FROM deliveries WHERE confirmed=1").fetchone() == (1,)


def test_definitely_unsent_drop_remains_ready_and_retries_after_restart(tmp_path, observed_drop):
    staged = worker(tmp_path, lambda _: response("records", FIRST, 10, observed_drop), None)
    assert staged.poll()

    def unavailable(*_):
        raise BrokerPublishError("connection unavailable", definitely_unsent=True)

    def no_read(_):
        pytest.fail("ready delivery is retried before reading source")

    not_sent = worker(tmp_path, no_read, unavailable)
    assert not not_sent.poll()
    with sqlite3.connect(tmp_path / "events.db") as journal:
        assert journal.execute("SELECT COUNT(*) FROM deliveries").fetchone() == (0,)

    published = []
    restarted = worker(tmp_path, no_read, lambda *event: published.append(event))
    assert restarted.poll()
    assert len(published) == 1 and published[0][1]["action"] == "DROP"


def test_embedded_drop_can_publish_at_the_unpaired_alert_limit(tmp_path, observed_drop, monkeypatch):
    from inspection import event_worker

    monkeypatch.setattr(event_worker, "_MAX_ALERTS", 1)
    other, _ = split({**observed_drop, "flow_id": observed_drop["flow_id"] + 1})
    records = iter([response("records", FIRST, 10, other), response("records", FIRST, 20, observed_drop)])
    sent = []
    active = worker(tmp_path, lambda _: next(records), lambda *event: sent.append(event))
    for _ in range(3):
        assert active.poll()
    assert len(sent) == 1


@pytest.mark.parametrize("mode", ["drop", "notify"])
def test_checkpoint_cannot_deliver_existing_ready_observations_to_another_site(
    tmp_path, observed_drop, observed_notify, mode,
):
    if mode == "notify":
        alert, flow = split(observed_notify)
        replies = iter([{**response("records", FIRST, 10, alert), "forwarding_observed": True},
                        response("records", FIRST, 20, flow)])
    else:
        replies = iter([response("records", FIRST, 10, observed_drop)])
    active = worker(tmp_path, lambda _: next(replies), None)
    assert active.poll()
    if mode == "notify":
        assert active.poll()

    other_site = SimpleNamespace(site_id="different", gateway_mac=TRUST.gateway_mac)
    restarted = worker(tmp_path, None, lambda *_: pytest.fail("cross-site publication"), trust=other_site)
    with pytest.raises(ValueError, match="site or gateway"):
        restarted.poll()


def test_gap_at_unchanged_cursor_does_not_spin(tmp_path):
    records = iter([response("idle", FIRST, 10), response("gap", FIRST, 10)])
    active = worker(tmp_path, lambda _: next(records), None)
    assert active.poll()
    assert not active.poll()
