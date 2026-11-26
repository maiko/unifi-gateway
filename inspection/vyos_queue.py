"""Plan a post-policy inspection queue for the supported IPv4 TCP flow."""

import re
from collections.abc import Mapping
from copy import deepcopy
from dataclasses import dataclass
from ipaddress import IPv4Address, IPv4Interface
from typing import Literal

from inspection.suricata import InspectionIntent

VYOS_VERSION = "2026.11.22-0018-rolling"
_NFT_VERSION = "1.0.9"
TABLE = "unifi_inspection"
_CHAIN = "post_policy_forward"
_PRIORITY = 100
_MAX_U32 = (1 << 32) - 1


@dataclass(frozen=True, slots=True)
class BridgeEndpoint:
    bridge: str
    interface: str
    gateway_cidr: str
    host: str


@dataclass(frozen=True, slots=True)
class LiveVlan:
    vlan_id: int
    gateway_cidr: str
    up: bool
    kind: str = "vlan"
    master: str | None = None


@dataclass(frozen=True, slots=True)
class QueueScope:
    initiator: BridgeEndpoint
    responder: BridgeEndpoint
    server_port: int
    queue_number: int


@dataclass(frozen=True, slots=True)
class QueuePlan:
    """Candidate placement for a caller that owns the separate nftables table."""

    scope: QueueScope

    def creation_batch(self) -> dict:
        """An exclusive table creation and its two rules in one nftables batch."""
        family = "ip"
        chain = {
            "family": family,
            "table": TABLE,
            "name": _CHAIN,
            "type": "filter",
            "hook": "forward",
            "prio": _PRIORITY,
            "policy": "accept",
        }
        return {
            "nftables": [
                {"create": {"table": {"family": family, "name": TABLE}}},
                {"add": {"chain": chain}},
                {"add": {"rule": self._rule(reply=False)}},
                {"add": {"rule": self._rule(reply=True)}},
            ]
        }

    def _rule(self, *, reply: bool) -> dict:
        src, dst = self.scope.initiator, self.scope.responder
        if reply:
            src, dst = dst, src
        return {
            "family": "ip",
            "table": TABLE,
            "chain": _CHAIN,
            "comment": "unifi-inspection-reply"
            if reply
            else "unifi-inspection-original",
            "expr": [
                _match({"meta": {"key": "iifname"}}, src.interface),
                _match({"meta": {"key": "oifname"}}, dst.interface),
                _match({"payload": {"protocol": "ip", "field": "saddr"}}, src.host),
                _match({"payload": {"protocol": "ip", "field": "daddr"}}, dst.host),
                _match(
                    {
                        "payload": {
                            "protocol": "tcp",
                            "field": "sport" if reply else "dport",
                        }
                    },
                    self.scope.server_port,
                ),
                {"counter": None},
                {"queue": {"num": self.scope.queue_number, "flags": ["bypass"]}},
            ],
        }


def _match(left, right):
    return {"match": {"op": "==", "left": left, "right": right}}


@dataclass(frozen=True, slots=True)
class QueueBinding:
    port_id: int
    backlog: int
    copy_mode: int
    copy_range: int
    queue_dropped: int
    user_dropped: int
    packet_sequence: int


@dataclass(frozen=True, slots=True)
class EngineIdentity:
    pid: int
    start_ticks: int


@dataclass(frozen=True, slots=True)
class QueuePeer:
    """One NETLINK_NETFILTER socket joined to its owner by socket inode."""

    port_id: int
    socket_inode: int
    owner: EngineIdentity


@dataclass(frozen=True, slots=True)
class QueueHealth:
    state: Literal["unprotected", "unverified", "bypassing", "degraded", "attached"]
    reason: str
    queue: QueueBinding | None = None


def parse_nfqueue_status(text: str) -> dict[int, QueueBinding]:
    """Decode a successful read of /proc/net/netfilter/nfnetlink_queue."""
    if type(text) is not str:
        raise ValueError("NFQUEUE status is unavailable")
    bindings = {}
    for line in text.splitlines():
        fields = line.split()
        if len(fields) != 9 or any(
            re.fullmatch(r"[0-9]{1,10}", value) is None for value in fields
        ):
            raise ValueError("Unexpected NFQUEUE status row")
        number, port, backlog, mode, span, drops, user_drops, seq, version = map(
            int, fields
        )
        if (
            version != 1
            or number in bindings
            or number > 65535
            or not 0 < port <= _MAX_U32
            or mode not in (0, 1, 2)
            or span > 65535
            or any(value > _MAX_U32 for value in (backlog, drops, user_drops, seq))
        ):
            raise ValueError("Invalid or ambiguous NFQUEUE status")
        bindings[number] = QueueBinding(
            port, backlog, mode, span, drops, user_drops, seq
        )
    return bindings


def _check_link(endpoint: BridgeEndpoint, links: Mapping[str, LiveVlan]):
    if not isinstance(endpoint, BridgeEndpoint) or not all(
        type(value) is str
        for value in (
            endpoint.bridge,
            endpoint.interface,
            endpoint.gateway_cidr,
            endpoint.host,
        )
    ):
        raise ValueError("Inspection requires approved bridge mappings")
    bridge_id = re.fullmatch(r"br([1-9][0-9]{0,3})", endpoint.bridge)
    vlan = re.fullmatch(r"eth[0-9]+\.([1-9][0-9]{0,3})", endpoint.interface)
    if (
        bridge_id is None
        or vlan is None
        or len(endpoint.interface) > 15
        or bridge_id[1] != vlan[1]
        or int(vlan[1]) > 4094
    ):
        raise ValueError(
            "Inspection requires a routed, explicitly mapped Ethernet VLAN"
        )
    live = links.get(endpoint.interface)
    if (
        not isinstance(live, LiveVlan)
        or live.kind != "vlan"
        or live.up is not True
        or live.master is not None
        or type(live.vlan_id) is not int
        or live.vlan_id != int(vlan[1])
        or live.gateway_cidr != endpoint.gateway_cidr
    ):
        raise ValueError("The live VLAN differs from the approved inspection mapping")
    try:
        gateway = IPv4Interface(endpoint.gateway_cidr)
        address = IPv4Address(endpoint.host)
    except (TypeError, ValueError):
        raise ValueError("Invalid approved inspection addresses") from None
    network = gateway.network
    if (
        str(gateway) != endpoint.gateway_cidr
        or str(address) != endpoint.host
        or address not in network
        or address in (network.network_address, network.broadcast_address, gateway.ip)
        or address.is_multicast
        or address.is_unspecified
        or address.is_loopback
    ):
        raise ValueError(
            "The inspection endpoint must be a usable host in its mapped subnet"
        )
    return network


def _check_scope(scope: QueueScope, links: Mapping[str, LiveVlan]) -> None:
    if (
        not isinstance(scope, QueueScope)
        or not isinstance(links, Mapping)
        or type(scope.server_port) is not int
        or not 1 <= scope.server_port <= 65535
        or type(scope.queue_number) is not int
        or not 0 <= scope.queue_number <= 65535
    ):
        raise ValueError("Inspection needs an exact TCP service and a reserved NFQUEUE")
    original = _check_link(scope.initiator, links)
    reply = _check_link(scope.responder, links)
    if original.overlaps(reply) or scope.initiator.bridge == scope.responder.bridge:
        raise ValueError("Inspection requires two distinct routed IPv4 VLANs")


def _nft_entries(rule_snapshot: dict, vyos_version: str) -> list[tuple[str, dict]]:
    if vyos_version != VYOS_VERSION or not isinstance(rule_snapshot, dict):
        raise ValueError(
            "The installed forwarding ruleset does not match the supported inspection ruleset"
        )
    rows = rule_snapshot.get("nftables")
    if not isinstance(rows, list) or not rows:
        raise ValueError("A complete nftables ruleset readback is required")
    entries = []
    for row in rows:
        if not isinstance(row, dict) or len(row) != 1:
            raise ValueError("Unexpected object in nftables ruleset")
        [(kind, value)] = row.items()
        if not isinstance(value, dict):
            raise ValueError("Unexpected object in nftables ruleset")
        entries.append((kind, value))
    meta = [row for kind, row in entries if kind == "metainfo"]
    if (
        len(meta) != 1
        or type(meta[0].get("json_schema_version")) is not int
        or meta[0]["json_schema_version"] != 1
        or meta[0].get("version") != _NFT_VERSION
    ):
        raise ValueError("Unsupported nftables JSON version")
    return entries


def _in_inspection_table(kind: str, row: dict) -> bool:
    return (
        row.get("family") == "ip"
        and row.get("name" if kind == "table" else "table") == TABLE
    )


def _check_placement(entries: list[tuple[str, dict]], queue_number: int) -> None:
    native_tables = base_seen = base_rules = 0
    for kind, row in entries:
        if _in_inspection_table(kind, row):
            continue
        family = row.get("family")
        if kind == "table" and family == "ip" and row.get("name") == "vyos_filter":
            native_tables += 1
            if row.get("flags", []) != []:
                raise ValueError(
                    "The native forwarding policy table is inactive or ambiguous"
                )
        if kind == "flowtable" and family != "ip6":
            raise ValueError("An offload path prevents verifying ingress coverage")
        if (
            kind == "chain"
            and family in ("ip", "inet")
            and row.get("hook") == "forward"
        ):
            priority = row.get("prio")
            if type(priority) is not int or priority >= _PRIORITY:
                raise ValueError(
                    "Inspection cannot be placed after all forwarding policy"
                )
            if (
                family,
                row.get("table"),
                row.get("name"),
                row.get("type"),
                priority,
            ) == ("ip", "vyos_filter", "VYOS_FORWARD_filter", "filter", 0):
                base_seen += 1
        if kind == "rule":
            if (family, row.get("table"), row.get("chain")) == (
                "ip",
                "vyos_filter",
                "VYOS_FORWARD_filter",
            ):
                base_rules += 1
            expressions = row.get("expr")
            if not isinstance(expressions, list):
                raise ValueError("Unexpected installed firewall rule expression")
            for expr in expressions:
                if not isinstance(expr, dict):
                    raise ValueError("Unexpected installed firewall rule expression")
                if "queue" in expr:
                    target = expr["queue"]
                    number = target.get("num") if isinstance(target, dict) else None
                    if type(number) is not int or number == queue_number:
                        raise ValueError(
                            "An existing rule may already target the reserved queue"
                        )
    if native_tables != 1 or base_seen != 1 or base_rules == 0:
        raise ValueError(
            "A complete readback of the installed VyOS forwarding policy is required"
        )


def plan_inline_queue(
    intent: InspectionIntent,
    *,
    scope: QueueScope,
    links: Mapping[str, LiveVlan],
    rule_snapshot: dict,
    queue_status: str | None,
    vyos_version: str,
) -> QueuePlan | None:
    """Plan an inline queue for blocking mode."""
    if not isinstance(intent, InspectionIntent):
        raise ValueError("An approved inspection intent is required")
    if intent.mode in ("off", "notify"):
        return None
    if intent.mode != "block":
        raise ValueError("Unsupported inline inspection mode")
    _check_scope(scope, links)
    selected = intent.networks
    if (
        type(selected) is not tuple
        or not all(type(value) is str for value in selected)
        or tuple(sorted(selected))
        != tuple(sorted((scope.initiator.bridge, scope.responder.bridge)))
    ):
        raise ValueError("The selected bridges differ from the approved routed pair")
    entries = _nft_entries(rule_snapshot, vyos_version)
    if any(_in_inspection_table(kind, row) for kind, row in entries):
        raise ValueError("The inspection table namespace is already occupied")
    _check_placement(entries, scope.queue_number)
    if scope.queue_number in parse_nfqueue_status(queue_status):
        raise ValueError("The reserved queue is already bound")
    return QueuePlan(scope)


def _expected_objects(plan: QueuePlan) -> list[tuple[str, dict]]:
    return [
        next(iter(value.items()))
        for command in plan.creation_batch()["nftables"]
        for value in command.values()
    ]


def _without_dynamic_fields(kind: str, row: dict) -> tuple[str, dict]:
    result = deepcopy(row)
    result.pop("handle", None)
    if kind == "rule" and isinstance(result.get("expr"), list):
        for exp in result["expr"]:
            if isinstance(exp, dict) and set(exp) == {"counter"}:
                counts = exp["counter"]
                if (
                    isinstance(counts, dict)
                    and counts.keys() == {"packets", "bytes"}
                    and all(
                        type(value) is int and value >= 0 for value in counts.values()
                    )
                ):
                    exp["counter"] = None
            if (
                isinstance(exp, dict)
                and set(exp) == {"queue"}
                and isinstance(exp["queue"], dict)
            ):
                queue = exp["queue"]
                if queue.get("flags") == "bypass":
                    queue["flags"] = ["bypass"]
    return kind, result


def assess_inline_queue(
    plan: QueuePlan,
    *,
    rule_snapshot: dict,
    queue_status: str | None,
    links: Mapping[str, LiveVlan],
    vyos_version: str,
    expected_engine: EngineIdentity | None = None,
    observed_peers: tuple[QueuePeer, ...] = (),
) -> QueueHealth:
    """Report verified attachment, separately from actual inspection verdicts."""
    try:
        entries = _nft_entries(rule_snapshot, vyos_version)
        _check_scope(plan.scope, links)
        _check_placement(entries, plan.scope.queue_number)
    except ValueError:
        return QueueHealth("unverified", "forwarding prerequisites differ")
    own = [
        _without_dynamic_fields(kind, row)
        for kind, row in entries
        if _in_inspection_table(kind, row)
    ]
    if not own:
        return QueueHealth("unprotected", "inspection rules are absent")
    if own != _expected_objects(plan):
        return QueueHealth("unverified", "inspection rules differ from the plan")
    try:
        queue = parse_nfqueue_status(queue_status).get(plan.scope.queue_number)
    except ValueError:
        return QueueHealth("unverified", "queue status is unavailable")
    if queue is None:
        return QueueHealth("bypassing", "no process is attached to the queue")
    if type(observed_peers) is not tuple or any(
        not isinstance(peer, QueuePeer) for peer in observed_peers
    ):
        return QueueHealth("unverified", "the queue socket readback is invalid", queue)
    peers = [peer for peer in observed_peers if peer.port_id == queue.port_id]
    if (
        not isinstance(expected_engine, EngineIdentity)
        or type(expected_engine.pid) is not int
        or expected_engine.pid <= 0
        or type(expected_engine.start_ticks) is not int
        or expected_engine.start_ticks <= 0
        or len(peers) != 1
        or peers[0].owner != expected_engine
        or type(peers[0].socket_inode) is not int
        or peers[0].socket_inode <= 0
        or queue.copy_mode != 2
        or queue.copy_range < 65531
    ):
        return QueueHealth(
            "unverified", "the queue listener is not the verified engine", queue
        )
    if queue.queue_dropped or queue.user_dropped:
        return QueueHealth("degraded", "the queue recorded packet delivery loss", queue)
    return QueueHealth("attached", "rules and engine attachment verified", queue)
