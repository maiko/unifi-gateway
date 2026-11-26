"""Plan and verify the reserved stock VyOS QoS configuration."""

from dataclasses import asdict, dataclass
from ipaddress import IPv4Network
import json
import re

from backends.vyos_failover import _invalid_constant, _read_helper, _unique_fields
from provisioners.uxg_qos import QOS_SOURCE, QOS_WAN_HOST, QosError, QosLimit
from provisioners.uxg_wan_failover import _exact
from provisioners.vyos_firewall_commands import firewall_rule_changes


QOS_LAN_INTERFACE = "eth3.110"
QOS_WAN_INTERFACE = "eth3.210"
_FORWARD_PATH = ("firewall", "ipv4", "forward", "filter", "rule")
_FORWARD_CHAIN = "VYOS_FORWARD_filter"
_SHAPER_PATH = ("qos", "policy", "shaper")
_ROOT_BANDWIDTH = "10gbit"
_DEFAULT_BANDWIDTH = "9gbit"
_KERNEL_DEFAULTS = {
    "noqueue": {},
    "fq_codel": {"limit": 10240, "flows": 1024, "quantum": 1514, "target": 4999, "interval": 99999,
                 "memory_limit": 33554432, "ecn": True, "drop_batch": 64},
}


@dataclass(frozen=True, slots=True)
class _Direction:
    field: str
    policy: str
    ingress: str
    egress: str
    source: str
    destination: str
    slot: str
    mark: str


_WAN_PREFIX = f"{QOS_WAN_HOST}/32"
_DIRECTIONS = (
    _Direction("upload_kbps", "UNIFI_QOS_UP", QOS_LAN_INTERFACE, QOS_WAN_INTERFACE,
               QOS_SOURCE, _WAN_PREFIX, "1", "43110"),
    _Direction("download_kbps", "UNIFI_QOS_DOWN", QOS_WAN_INTERFACE, QOS_LAN_INTERFACE,
               _WAN_PREFIX, QOS_SOURCE, "2", "43210"),
)
QOS_MARKER_SLOTS = tuple(direction.slot for direction in _DIRECTIONS)


def qos_checkpoint(limit):
    if limit is None:
        return None
    return {**asdict(limit), "shapers": [direction.policy for direction in _DIRECTIONS]}


def limit_from_checkpoint(record):
    if record is None:
        return None
    if not isinstance(record, dict):
        raise QosError("Invalid saved VyOS QoS ownership")
    fields = dict(record)
    if fields.pop("shapers", None) != [direction.policy for direction in _DIRECTIONS]:
        raise QosError("Invalid saved VyOS shaper names")
    if fields.keys() != {"download_kbps", "upload_kbps"}:
        raise QosError("Invalid saved VyOS QoS rates")
    return QosLimit(**fields)


def _marker_rules():
    return {d.slot: {
        "action": "continue", "inbound-interface": {"name": d.ingress}, "outbound-interface": {"name": d.egress},
        "source": {"address": d.source}, "destination": {"address": d.destination}, "set": {"mark": d.mark},
    } for d in _DIRECTIONS}


def _shaper(direction, limit):
    rate = f"{getattr(limit, direction.field)}kbit"
    return {
        "bandwidth": _ROOT_BANDWIDTH,
        "default": {"bandwidth": _DEFAULT_BANDWIDTH, "ceiling": _ROOT_BANDWIDTH},
        "class": {"10": {"bandwidth": rate, "ceiling": rate, "match": {"PAIR": {"mark": direction.mark}}}},
    }


def _qos_configuration(limit):
    return {
        "interface": {d.egress: {"egress": d.policy} for d in _DIRECTIONS},
        "policy": {"shaper": {d.policy: _shaper(d, limit) for d in _DIRECTIONS}},
    }


def _running_markers(running):
    subtree = running
    for component in _FORWARD_PATH:
        if not isinstance(subtree, dict):
            raise QosError("Invalid VyOS IPv4 forwarding rule collection")
        subtree = subtree.get(component, {})
    if not isinstance(subtree, dict):
        raise QosError("Invalid VyOS IPv4 forwarding rule collection")
    return {slot: subtree[slot] for slot in QOS_MARKER_SLOTS if slot in subtree}


def _empty_qos(qos):
    if not isinstance(qos, dict) or qos.keys() - {"interface", "policy"}:
        return False
    interfaces = qos.get("interface", {})
    return (isinstance(interfaces, dict) and interfaces.keys() <= {d.egress for d in _DIRECTIONS}
            and all(config == {} for config in interfaces.values())
            and qos.get("policy", {}) in ({}, {"shaper": {}}))


def read_qos_state(running):
    if not isinstance(running, dict):
        raise QosError("QoS needs the complete VyOS configuration")
    qos = running.get("qos", {})
    markers = _running_markers(running)
    if _empty_qos(qos) and not markers:
        return None

    rates = {}
    try:
        for direction in _DIRECTIONS:
            encoded = qos["policy"]["shaper"][direction.policy]["class"]["10"]["bandwidth"]
            match = re.fullmatch(r"([1-9][0-9]{0,6})kbit", encoded)
            if not match:
                raise QosError("Invalid reserved VyOS QoS bandwidth")
            rates[direction.field] = int(match[1])
    except (AttributeError, KeyError, TypeError) as error:
        raise QosError("VyOS QoS resources differ from the reserved scope") from error
    limit = QosLimit(**rates)
    if qos != _qos_configuration(limit) or markers != _marker_rules():
        raise QosError("VyOS QoS policies or markers differ from the reserved scope")
    return limit


def _has_foreign_mark(node, owned_rules):
    if not isinstance(node, dict) or any(node is rule for rule in owned_rules):
        return False
    values = node.get("set")
    return (isinstance(values, dict) and "mark" in values
            or any(_has_foreign_mark(child, owned_rules) for child in node.values()))


def _check_classification(running):
    firewall = running.get("firewall", {})
    options = firewall.get("global-options", {})
    if not isinstance(options, dict) or "flowtable" in firewall or options.get("state-policy"):
        raise QosError("QoS markers need a forwarding path without offload or a preemptive state policy")
    if _has_foreign_mark(firewall, tuple(_running_markers(running).values())) or running.get("policy"):
        raise QosError("Other VyOS packet-marking and routing policies must be inactive for managed QoS")
    nat = running.get("nat", {})
    if (not isinstance(nat, dict) or nat.keys() - {"source", "destination"} or running.get("nat66")
            or any(not isinstance(section, dict) or section.keys() - {"rule"} or section.get("rule")
                   for section in nat.values())):
        raise QosError("Managed QoS requires the supported routed path without NAT")


def plan_qos(limit, *, running, verified):
    current = read_qos_state(running)
    if current != verified:
        raise QosError("VyOS QoS differs from the last verified configuration")
    if limit is not None:
        if not isinstance(limit, QosLimit):
            raise QosError("A complete bidirectional QoS limit is required")
        _check_classification(running)
    if limit == current:
        return ()

    commands = list(firewall_rule_changes(
        {"qos_markers": _FORWARD_PATH},
        {"qos_markers": _marker_rules() if current is not None else {}},
        {"qos_markers": _marker_rules() if limit is not None else {}},
    ))
    for direction in _DIRECTIONS:
        root = [*_SHAPER_PATH, direction.policy]
        interface = ["qos", "interface", direction.egress, "egress"]
        if limit is None:
            commands.extend(({"op": "delete", "path": interface[:-1]}, {"op": "delete", "path": root}))
            continue
        if current is None:
            commands.extend({"op": "set", "path": path} for path in (
                [*root, "bandwidth", _ROOT_BANDWIDTH],
                [*root, "default", "bandwidth", _DEFAULT_BANDWIDTH],
                [*root, "default", "ceiling", _ROOT_BANDWIDTH],
                [*root, "class", "10", "match", "PAIR", "mark", direction.mark],
                [*interface, direction.policy],
            ))
        value = getattr(limit, direction.field)
        if current is None or value != getattr(current, direction.field):
            commands.extend({"op": "set", "path": [*root, "class", "10", field, f"{value}kbit"]}
                            for field in ("bandwidth", "ceiling"))
    return tuple(commands)


def read_qos_kernel(command):
    body = _read_helper(command, reader="VyOS QoS reader")
    try:
        return json.loads(body, object_pairs_hook=_unique_fields, parse_constant=_invalid_constant)
    except (ValueError, RecursionError) as error:
        raise QosError("VyOS QoS reader returned invalid JSON") from error


def _verify_qdisc(snapshot, direction, limit):
    if not isinstance(snapshot, dict) or snapshot.keys() != {"qdisc", "class", "filter"}:
        raise QosError("Incomplete VyOS egress qdisc observation")
    qdiscs, classes, filters = (snapshot[key] for key in ("qdisc", "class", "filter"))
    if not all(isinstance(rows, list) and all(isinstance(row, dict) for row in rows)
               for rows in (qdiscs, classes, filters)):
        raise QosError("Invalid VyOS egress qdisc or filter inventory")
    if limit is None:
        if (len(qdiscs) != 1 or qdiscs[0].get("kind") != "noqueue" or qdiscs[0].get("root") is not True
                or qdiscs[0].get("handle") != "0:" or qdiscs[0].get("options") != {} or classes or filters):
            raise QosError(f"VyOS egress {direction.egress} has an unexpected kernel traffic policy")
        return

    roots = [row for row in qdiscs if row.get("root") is True]
    options = roots[0].get("options") if len(roots) == 1 else None
    if (len(qdiscs) != 3 or len(roots) != 1 or roots[0].get("kind") != "htb" or roots[0].get("handle") != "1:"
            or not isinstance(options, dict) or options.get("default") != "0xb"
            or {(row.get("parent"), row.get("kind")) for row in qdiscs if row is not roots[0]}
            != {("1:a", "fq_codel"), ("1:b", "fq_codel")}):
        raise QosError(f"VyOS egress {direction.egress} has an unexpected root or default queue")
    cap = getattr(limit, direction.field) * 125
    rates = {"1:1": (1_250_000_000, 1_250_000_000), "1:a": (cap, cap), "1:b": (1_125_000_000, 1_250_000_000)}
    shaper_classes = [row for row in classes if row.get("class") == "htb"]
    if (len(shaper_classes) != 3
            or not _exact({row.get("handle"): (row.get("rate"), row.get("ceil")) for row in shaper_classes}, rates)
            or any(row.get("parent") != (None if row.get("handle") == "1:1" else "1:1") for row in shaper_classes)):
        raise QosError(f"VyOS egress {direction.egress} rates differ from the scoped cap")
    leaf_handles = [row.get("handle") for row in qdiscs if row is not roots[0]]
    if (any(not isinstance(handle, str) or not re.fullmatch(r"[0-9a-f]{1,4}:", handle) for handle in leaf_handles)
            or len(set(leaf_handles)) != 2):
        raise QosError(f"VyOS egress {direction.egress} has invalid leaf queue handles")
    for row in classes:
        if row.get("class") == "htb":
            continue
        parent, handle = row.get("parent"), row.get("handle")
        if (row.keys() != {"class", "parent", "handle"} or row.get("class") != "fq_codel" or parent not in leaf_handles
                or not isinstance(handle, str) or not re.fullmatch(re.escape(parent) + r"[0-9a-f]{1,4}", handle)):
            raise QosError(f"VyOS egress {direction.egress} has an unexpected flow queue")

    classifier = {"parent": "1:", "protocol": "all", "pref": 1, "kind": "fw", "chain": 0}
    options = filters[1].get("options") if len(filters) == 2 else None
    if not isinstance(options, dict) or not isinstance(options.get("actions"), list) or len(options["actions"]) != 1:
        raise QosError(f"VyOS egress {direction.egress} has an incomplete mark classifier")
    action = options["actions"][0]
    if not isinstance(action, dict) or type(action.get("index")) is not int or action["index"] < 1:
        raise QosError(f"VyOS egress {direction.egress} has an invalid mark filter action")
    expected = {**classifier, "options": {
        "fw": {"mark": hex(int(direction.mark)), "mask": "0xffffffff"}, "classid": "1:a",
        "actions": [{"order": 1, "kind": "police", "index": action["index"], "control_action": {"type": "reclassify"},
                     "overhead": 0, "linklayer": "ethernet", "ref": 1, "bind": 1}],
    }}
    if not _exact(filters, [classifier, expected]):
        raise QosError(f"VyOS egress {direction.egress} selects a different mark or class")


def _nft_match(left, right):
    return {"match": {"op": "==", "left": left, "right": right}}


def _nft_address(field, value):
    prefix = IPv4Network(value)
    addr = str(prefix.network_address)
    selector = addr if prefix.prefixlen == 32 else {"prefix": {"addr": addr, "len": prefix.prefixlen}}
    return _nft_match({"payload": {"protocol": "ip", "field": field}}, selector)


def _nft_marker(direction):
    mark = int(direction.mark)
    mark_meta = {"meta": {"key": "mark"}}
    return {
        "family": "ip", "table": "vyos_filter", "chain": _FORWARD_CHAIN, "comment": f"ipv4-FWD-filter-{direction.slot}",
        "expr": [
            _nft_address("daddr", direction.destination), _nft_address("saddr", direction.source),
            _nft_match({"meta": {"key": "iifname"}}, direction.ingress),
            _nft_match({"meta": {"key": "oifname"}}, direction.egress), {"counter": {}},
            {"mangle": {"key": mark_meta, "value": {"|": [{"&": [mark_meta, 0x80000000 | mark]}, mark]}}},
            {"continue": None},
        ],
    }


def _verify_forward(snapshot, limit):
    if snapshot is None and limit is None:
        return
    if not isinstance(snapshot, dict) or snapshot.keys() != {"nftables"} or not isinstance(snapshot["nftables"], list):
        raise QosError("Invalid VyOS QoS forwarding chain observation")
    rows = snapshot["nftables"]
    rules = []
    chains = []
    for item in rows:
        if not isinstance(item, dict) or len(item) != 1 or not isinstance((row := next(iter(item.values()))), dict):
            raise QosError("Invalid VyOS nftables entry in the QoS forwarding chain")
        if "rule" in item and isinstance(row.get("expr"), list):
            rules.append({**{key: value for key, value in row.items() if key not in {"handle", "expr"}}, "expr": [
                {"counter": {}} if isinstance(expr, dict) and expr.keys() == {"counter"} else expr for expr in row["expr"]
            ]})
        elif "chain" in item:
            chains.append({key: value for key, value in row.items() if key != "handle"})
        elif "metainfo" not in item:
            raise QosError("Unexpected nftables object in the VyOS QoS forwarding chain")
    expected_chain = {"family": "ip", "table": "vyos_filter", "name": _FORWARD_CHAIN,
                      "type": "filter", "hook": "forward", "prio": 0, "policy": "accept"}
    expected = [_nft_marker(d) for d in _DIRECTIONS]
    marker_names = {row["comment"] for row in expected}
    marked = [row for row in rules if row.get("comment") in marker_names]
    if not _exact(chains, [expected_chain]):
        raise QosError("QoS markers must run in the VyOS IPv4 forward filter")
    if (limit is None and marked or limit is not None
            and (marked != expected or rules[:len(expected)] != expected)):
        raise QosError("The live VyOS QoS mark rules differ from the exact leading IPv4 matches and continue actions")


def _verify_other_qdiscs(rows):
    if not isinstance(rows, list) or not rows:
        raise QosError("QoS needs the other VyOS interfaces' kernel queue inventory")
    seen = {QOS_LAN_INTERFACE, QOS_WAN_INTERFACE}
    for row in rows:
        if not isinstance(row, dict) or row.keys() != {"dev", "kind", "handle", "root", "refcnt", "options"}:
            raise QosError("VyOS QoS would reset an unrelated or unrecognized kernel queue")
        device, kind = row["dev"], row["kind"]
        if (not isinstance(device, str) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,15}", device) or device in seen
                or not isinstance(kind, str) or kind not in _KERNEL_DEFAULTS or row["root"] is not True
                or row["handle"] != "0:" or not _exact(row["options"], _KERNEL_DEFAULTS[kind])):
            raise QosError("VyOS QoS would reset an unrelated or non-default kernel queue")
        seen.add(device)


def verify_qos_kernel(snapshot, limit):
    """Require both real shapers and the exact packet classifiers before acknowledging."""
    if (not isinstance(snapshot, dict) or snapshot.keys() != {"interfaces", "forward", "other_qdiscs"}
            or not isinstance(snapshot["interfaces"], dict)
            or snapshot["interfaces"].keys() != {QOS_LAN_INTERFACE, QOS_WAN_INTERFACE}):
        raise QosError("Incomplete VyOS QoS kernel snapshot")
    _verify_other_qdiscs(snapshot["other_qdiscs"])
    for direction in _DIRECTIONS:
        _verify_qdisc(snapshot["interfaces"][direction.egress], direction, limit)
    _verify_forward(snapshot["forward"], limit)
