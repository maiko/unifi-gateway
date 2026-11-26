"""Coverage for the captured native IPv4 WAN speed-limit profile."""

from copy import deepcopy
import json
from pathlib import Path

import pytest


FIXTURES = json.loads((Path(__file__).parent / "fixtures/uxg_pro/native-qos-speed-limit-snapshots.json").read_text())
KERNEL = json.loads((Path(__file__).parent / "fixtures/uxg_pro/vyos-qos-kernel.json").read_text())


@pytest.mark.parametrize(("phase", "expected"), [("create", (8000, 3000)), ("edit", (8000, 5000)), ("removed", None)])
def test_qos_wire_normalization_matches_queue_and_preserves_unrelated_sets(phase, expected):
    from provisioners.uxg_qos import QosLimit, normalize_qos_policy

    doc = deepcopy(FIXTURES[phase])
    other = {"identification": {"name": "operator-network", "type": "address"}, "entries": ["192.168.120.0/24"]}
    doc["udapi"]["firewall/sets"].append(other)
    doc["udapi"]["another-scope"] = {"enabled": True}
    expected_doc = deepcopy(doc)
    expected_doc["udapi"].pop("qos", None)
    del expected_doc["udapi"]["firewall/mangle"]
    expected_doc["udapi"]["firewall/sets"] = [other]

    normalized, intent = normalize_qos_policy(json.dumps(doc), revision="observed-revision")

    assert intent.revision == "observed-revision"
    assert intent.limit == (QosLimit(*expected) if expected else None)
    assert json.loads(normalized) == expected_doc


@pytest.mark.parametrize("drift", [
    "foreign matcher", "no classifier", "missing queue", "modified queue name", "IPv6", "outbound WAN",
    "wrong source", "malformed destination", "prioritize", "burst", "missing direction", "incorrect integer", "legacy QoS",
])
def test_qos_wire_rejects_incomplete_and_unverified_policies(drift):
    from provisioners.uxg_qos import QosError, normalize_qos_policy

    doc = deepcopy(FIXTURES["create"])
    u = doc["udapi"]
    rules = u["firewall/mangle"][0]["rules"]
    rule = rules[0]
    qos = u["qos"]
    queue = qos["fw"]["queues"][0]
    if drift == "foreign matcher":
        rules.append({"id": 10002, "target": "MARK"})
    if drift == "no classifier":
        rules.clear()
    if drift == "missing queue":
        del u["qos"]
    if drift == "modified queue name":
        queue["name"] = "alternative"
    if drift == "IPv6":
        rule["ipVersion"] = "both"
    if drift == "outbound WAN":
        rule["outInterface"]["id"] = "eth2"
    if drift == "wrong source":
        u["firewall/sets"][0]["entries"] = ["192.168.120.0/24"]
    if drift == "malformed destination":
        u["firewall/sets"][1]["entries"].append("198.18.210.1")
    if drift == "prioritize":
        queue["priority"] = 3
    if drift == "burst":
        queue["uploadBurst"] = 1000
    if drift == "missing direction":
        del queue["downloadSpeed"]
    if drift == "incorrect integer":
        queue["uploadSpeed"] = 3000.0
    if drift == "legacy QoS":
        u["qos/ip"] = {"global": {"enabled": True}}
    with pytest.raises(QosError):
        normalize_qos_policy(json.dumps(doc), revision="observed-revision")


def running_qos(*, active=True):
    rules = {"79300": {"action": "drop", "inbound-interface": {"name": "vtun246"}}}
    running = {"firewall": {"ipv4": {"forward": {"filter": {"rule": rules}}}}}
    if not active:
        return running
    running["qos"] = {"interface": {}, "policy": {"shaper": {}}}
    for slot, mark, name, ingress, egress, rate, source, destination in (
        ("1", "43110", "UNIFI_QOS_UP", "eth3.110", "eth3.210", "3000kbit", "192.168.110.0/24", "198.18.210.2/32"),
        ("2", "43210", "UNIFI_QOS_DOWN", "eth3.210", "eth3.110", "8000kbit", "198.18.210.2/32", "192.168.110.0/24"),
    ):
        running["qos"]["interface"][egress] = {"egress": name}
        running["qos"]["policy"]["shaper"][name] = {
            "bandwidth": "10gbit",
            "default": {"bandwidth": "9gbit", "ceiling": "10gbit"},
            "class": {"10": {"bandwidth": rate, "ceiling": rate, "match": {"PAIR": {"mark": mark}}}},
        }
        rules[slot] = {"action": "continue", "set": {"mark": mark},
                       "inbound-interface": {"name": ingress}, "outbound-interface": {"name": egress},
                       "source": {"address": source}, "destination": {"address": destination}}
    return running


def test_qos_planner_applies_two_caps_and_scoped_markers_with_targeted_edits_and_withdrawal():
    from provisioners.uxg_qos import QosLimit
    from provisioners.vyos_qos import plan_qos, read_qos_state

    first, second = QosLimit(8000, 3000), QosLimit(8000, 5000)
    initial = running_qos(active=False)
    observed = running_qos()
    assert read_qos_state(initial) is None
    assert read_qos_state(observed) == first
    create = plan_qos(first, running=initial, verified=None)
    assert {op["path"][3] for op in create if op["path"][:3] == ["qos", "policy", "shaper"]} == {
        "UNIFI_QOS_UP", "UNIFI_QOS_DOWN",
    }
    marks = [operation for operation in create if operation["path"][0] == "firewall"]
    assert {operation["path"][5] for operation in marks} == {"1", "2"}
    assert [operation["value"] for operation in marks if operation["path"][-1] == "action"] == ["continue", "continue"]
    assert not plan_qos(first, running=observed, verified=first)
    edit = plan_qos(second, running=observed, verified=first)
    assert edit == tuple(
        {"op": "set", "path": ["qos", "policy", "shaper", "UNIFI_QOS_UP", "class", "10", field, "5000kbit"]}
        for field in ("bandwidth", "ceiling")
    )
    removed = plan_qos(None, running=observed, verified=first)
    assert len(removed) == 6 and all(operation["op"] == "delete" for operation in removed)
    assert all("79300" not in operation["path"] and len(operation["path"]) > 1 for operation in removed)
    assert {tuple(operation["path"]) for operation in removed if operation["path"][:2] == ["qos", "interface"]} == {
        ("qos", "interface", "eth3.110"), ("qos", "interface", "eth3.210"),
    }


def test_qos_readback_accepts_the_empty_stock_container_after_withdrawal():
    from provisioners.vyos_qos import read_qos_state

    running = running_qos(active=False)
    running["qos"] = {"interface": {"eth3.110": {}, "eth3.210": {}}, "policy": {}}
    assert read_qos_state(running) is None
    running["qos"] = {"interface": {}, "policy": {}}
    assert read_qos_state(running) is None


@pytest.mark.parametrize("drift", ["ownership", "reserved slot", "existing shaper", "offload", "preemptive state", "foreign mark", "NAT"])
def test_qos_planner_refuses_ambiguous_ownership_and_classifier_conflicts(drift):
    from provisioners.uxg_qos import QosError, QosLimit
    from provisioners.vyos_qos import plan_qos

    current = running_qos(active=drift == "ownership")
    forward = current["firewall"]["ipv4"]["forward"]["filter"]["rule"]
    if drift == "reserved slot":
        forward["1"] = {"action": "accept"}
    if drift == "existing shaper":
        current["qos"] = {"interface": {"eth3.110": {"egress": "operator-shaper"}}}
    if drift == "offload":
        current["firewall"]["flowtable"] = {"operator": {}}
    if drift == "preemptive state":
        current["firewall"]["global-options"] = {"state-policy": {"established": {"action": "accept"}}}
    if drift == "foreign mark":
        forward["20"] = {"action": "continue", "set": {"mark": "43110"}}
    if drift == "NAT":
        current["nat"] = {"source": {"rule": {"1": {"translation": {"address": "masquerade"}}}}}
    with pytest.raises(QosError):
        plan_qos(QosLimit(8000, 3000), running=current, verified=None)


def test_scope_verifies_the_stock_kernel_capture_and_clean_withdrawal():
    from provisioners.uxg_qos import QosLimit
    from provisioners.vyos_qos import verify_qos_kernel

    verify_qos_kernel(KERNEL, QosLimit(8000, 3000))
    removed = deepcopy(KERNEL)
    for snapshot in removed["interfaces"].values():
        snapshot.update(qdisc=[{"kind": "noqueue", "handle": "0:", "root": True,
                                "refcnt": 2, "options": {}}], **{"class": [], "filter": []})
    del removed["forward"]["nftables"][2:4]
    verify_qos_kernel(removed, None)


@pytest.mark.parametrize("drift", [
    "wrong rate", "default points at cap", "foreign filter", "narrow mark", "source match", "early accept",
    "operator shaper", "operator ingress filter", "changed default queue", "unrelated flow queue",
])
def test_scope_rejects_unverified_kernel_rates_and_matches(drift):
    from provisioners.uxg_qos import QosError, QosLimit
    from provisioners.vyos_qos import verify_qos_kernel

    actual = deepcopy(KERNEL)
    up = actual["interfaces"]["eth3.210"]
    rules = actual["forward"]["nftables"]
    if drift == "wrong rate":
        up["class"][1]["ceil"] = 400_000
    if drift == "default points at cap":
        up["qdisc"][0]["options"]["default"] = "0xa"
    if drift == "foreign filter":
        up["filter"].append({"kind": "u32"})
    if drift == "narrow mark":
        up["filter"][1]["options"]["fw"]["mask"] = "0x7fffffff"
    if drift == "source match":
        del rules[2]["rule"]["expr"][1]
    if drift == "early accept":
        rules.insert(2, deepcopy(rules[-1]))
    if drift == "operator shaper":
        actual["other_qdiscs"][0]["kind"] = "cake"
    if drift == "operator ingress filter":
        actual["other_qdiscs"].append({"dev": "eth2", "kind": "clsact", "handle": "ffff:", "parent": "ffff:fff1"})
    if drift == "changed default queue":
        next(row for row in actual["other_qdiscs"] if row["kind"] == "fq_codel")["options"]["flows"] = 512
    if drift == "unrelated flow queue":
        up["class"].append({"class": "fq_codel", "handle": "8888:1", "parent": "8888:"})
    with pytest.raises(QosError):
        verify_qos_kernel(actual, QosLimit(8000, 3000))
