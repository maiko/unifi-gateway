"""Fixture checks for an isolated late IPv4 forwarding queue."""

from copy import deepcopy
from types import SimpleNamespace

import pytest

from inspection.suricata import InspectionIntent


@pytest.fixture
def api():
    from inspection import vyos_queue

    return vyos_queue


@pytest.fixture
def nft():
    return {
        "nftables": [
            {"metainfo": {"version": "1.0.9", "json_schema_version": 1}},
            {"table": {"family": "ip", "name": "vyos_filter", "handle": 1}},
            {
                "chain": {
                    "family": "ip",
                    "table": "vyos_filter",
                    "name": "VYOS_FORWARD_filter",
                    "type": "filter",
                    "hook": "forward",
                    "prio": 0,
                    "policy": "drop",
                }
            },
            {
                "rule": {
                    "family": "ip",
                    "table": "vyos_filter",
                    "chain": "VYOS_FORWARD_filter",
                    "expr": [{"drop": None}],
                    "comment": "operator rule",
                }
            },
            {
                "chain": {
                    "family": "ip",
                    "table": "vyos_filter",
                    "name": "VYOS_ZONE_FORWARD",
                    "type": "filter",
                    "hook": "forward",
                    "prio": 1,
                    "policy": "accept",
                }
            },
            {
                "chain": {
                    "family": "inet",
                    "table": "mangle",
                    "name": "FORWARD",
                    "type": "filter",
                    "hook": "forward",
                    "prio": -150,
                    "policy": "accept",
                }
            },
        ]
    }


@pytest.fixture
def data(api, nft):
    return SimpleNamespace(
        intent=InspectionIntent("block", ("br110", "br120")),
        scope=api.QueueScope(
            api.BridgeEndpoint(
                "br110", "eth3.110", "192.168.110.1/24", "192.168.110.2"
            ),
            api.BridgeEndpoint(
                "br120", "eth3.120", "192.168.120.1/24", "192.168.120.2"
            ),
            server_port=18443,
            queue_number=41110,
        ),
        links={
            "eth3.110": api.LiveVlan(110, "192.168.110.1/24", True),
            "eth3.120": api.LiveVlan(120, "192.168.120.1/24", True),
        },
        rule_snapshot=nft,
        queue_status="",
        vyos_version="2026.11.22-0018-rolling",
    )


def plan(api, data):
    return api.plan_inline_queue(
        data.intent,
        **{
            k: getattr(data, k)
            for k in ("scope", "links", "rule_snapshot", "queue_status", "vyos_version")
        },
    )


def test_isolated_rules_scope_both_directions_after_existing_policy(api, data):
    before = deepcopy(data.rule_snapshot)
    result = plan(api, data)
    batch = result.creation_batch()["nftables"]

    assert data.rule_snapshot == before
    assert batch[0] == {"create": {"table": {"family": "ip", "name": api.TABLE}}}
    chain = batch[1]["add"]["chain"]
    assert chain["prio"] > 10
    assert chain["hook"] == "forward"
    assert chain["policy"] == "accept"
    assert chain["table"] == api.TABLE
    assert len(batch) == 4
    for direction, key in enumerate(("dport", "sport")):
        rule = batch[direction + 2]["add"]["rule"]
        assert rule["table"] == api.TABLE
        assert rule["chain"] == chain["name"]
        predicates = [row["match"] for row in rule["expr"][:-2]]
        lookup = {
            tuple(term["left"].get("meta", term["left"].get("payload")).values()): term[
                "right"
            ]
            for term in predicates
        }
        assert lookup[("iifname",)] == ("eth3.110", "eth3.120")[direction]
        assert lookup[("oifname",)] == ("eth3.120", "eth3.110")[direction]
        assert lookup[("ip", "saddr")] == ("192.168.110.2", "192.168.120.2")[direction]
        assert lookup[("ip", "daddr")] == ("192.168.120.2", "192.168.110.2")[direction]
        assert lookup[("tcp", key)] == 18443
        assert rule["expr"][-2:] == [
            {"counter": None},
            {"queue": {"num": 41110, "flags": ["bypass"]}},
        ]


@pytest.mark.parametrize(
    "case",
    [
        "occupied",
        "later-hook",
        "flowtable",
        "unknown-version",
        "foreign-queue",
        "queue-bound",
        "bad-topology",
        "interface-down",
        "subset",
        "failed-read",
    ],
)
def test_refuses_unowned_or_unproved_placement(api, data, case):
    rows = data.rule_snapshot["nftables"]
    if case == "occupied":
        rows.append({"table": {"family": "ip", "name": api.TABLE}})
    if case == "later-hook":
        rows[-1]["chain"]["prio"] = 100
    if case == "flowtable":
        rows.append(
            {"flowtable": {"family": "ip", "table": "vyos_filter", "name": "fast"}}
        )
    if case == "unknown-version":
        data.vyos_version = "2026.11.23-0018-rolling"
    if case == "foreign-queue":
        rows[3]["rule"]["expr"] = [{"queue": {"num": {"range": [41109, 41112]}}}]
    if case == "queue-bound":
        data.queue_status = "41110 24989 0 2 65531 0 0 26 1\n"
    if case == "bad-topology":
        data.links["eth3.110"] = api.LiveVlan(111, "192.168.110.1/24", True)
    if case == "interface-down":
        data.links["eth3.110"] = api.LiveVlan(110, "192.168.110.1/24", False)
    if case == "subset":
        data.intent = InspectionIntent("block", ("br110",))
    if case == "failed-read":
        data.queue_status = None

    with pytest.raises(ValueError):
        plan(api, data)


def test_passive_and_off_make_no_inline_plan(api, data):
    data.intent = InspectionIntent("notify", ("br110", "br120"))
    assert plan(api, data) is None
    data.intent = InspectionIntent("off", ())
    assert plan(api, data) is None


def applied(plan, nft):
    readback = deepcopy(nft)
    for command in plan.creation_batch()["nftables"]:
        [object] = command.values()
        if "rule" in object:
            object["rule"]["expr"][-2]["counter"] = {"packets": 17, "bytes": 1068}
        readback["nftables"].append(object)
    return readback


def check(api, data, plan, *, peers=(), expected=None):
    return api.assess_inline_queue(
        plan,
        rule_snapshot=data.rule_snapshot,
        queue_status=data.queue_status,
        expected_engine=expected,
        observed_peers=peers,
        links=data.links,
        vyos_version=data.vyos_version,
    )


def test_exact_queue_rules_and_proc_peer_distinguish_bypass_foreign_and_attached(
    api, data
):
    result = plan(api, data)
    engine = api.EngineIdentity(832, 19000)
    peer = api.QueuePeer(24989, 20001, engine)
    assert check(api, data, result).state == "unprotected"
    data.rule_snapshot = applied(result, data.rule_snapshot)
    assert check(api, data, result).state == "bypassing"

    data.queue_status = "41110 24989 0 2 65531 0 0 26 1\n"
    assert check(api, data, result, expected=engine).state == "unverified"
    assert (
        check(
            api, data, result, peers=(peer,), expected=api.EngineIdentity(832, 19100)
        ).state
        == "unverified"
    )
    current = check(api, data, result, peers=(peer,), expected=engine)
    assert current.state == "attached"
    assert current.queue.packet_sequence == 26


def test_runtime_mismatch_missing_read_or_queue_loss_cannot_report_attached(api, data):
    result = plan(api, data)
    data.rule_snapshot = applied(result, data.rule_snapshot)
    engine = api.EngineIdentity(832, 19000)
    peer = api.QueuePeer(24989, 20001, engine)
    data.queue_status = None
    assert (
        check(api, data, result, peers=(peer,), expected=engine).state == "unverified"
    )
    data.queue_status = "41110 24989 0 2 65531 1 2 26 1\n"
    assert check(api, data, result, peers=(peer,), expected=engine).state == "degraded"
    data.queue_status = "41110 24989 0 2 65531 0 0 26 1\n"
    data.rule_snapshot["nftables"][-1]["rule"]["expr"].insert(0, {"accept": None})
    assert (
        check(api, data, result, peers=(peer,), expected=engine).state == "unverified"
    )


def test_proc_status_preserves_port_id_and_rejects_ambiguous_readback(api):
    sample = api.parse_nfqueue_status(
        "41110  24989     0 2 65531     0     0       26  1\n"
    )
    assert sample[41110].port_id == 24989
    with pytest.raises(ValueError):
        api.parse_nfqueue_status("41110 24989 0 2 65531 0 0 26 1\n" * 2)
    with pytest.raises(ValueError):
        api.parse_nfqueue_status("41110 24989 0 2 65531 0 0 ? 1\n")


def test_does_not_treat_a_chain_inventory_as_complete_firewall_readback(api, data):
    rows = data.rule_snapshot["nftables"]
    rows[:] = [row for row in rows if "rule" not in row and "table" not in row]
    with pytest.raises(ValueError, match="complete"):
        plan(api, data)


def test_dormant_native_policy_does_not_qualify_placement(api, data):
    data.rule_snapshot["nftables"][1]["table"]["flags"] = ["dormant"]
    with pytest.raises(ValueError, match="policy"):
        plan(api, data)


def test_overlapping_matches_after_a_correlated_engine_is_unverified(api, data):
    result = plan(api, data)
    data.rule_snapshot = applied(result, data.rule_snapshot)
    data.queue_status = "41110 24989 0 2 65531 0 0 26 1\n"
    engine = api.EngineIdentity(832, 19000)
    peer = api.QueuePeer(24989, 20001, engine)
    assert (
        check(api, data, result, peers=(peer, peer), expected=engine).state
        == "unverified"
    )

    data.links["eth3.110"] = api.LiveVlan(110, "192.168.111.1/24", True)
    assert (
        check(api, data, result, peers=(peer,), expected=engine).state == "unverified"
    )
