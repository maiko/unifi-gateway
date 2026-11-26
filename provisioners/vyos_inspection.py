"""Plan queue changes at the approved stock VyOS zone terminal permits."""

from dataclasses import asdict, dataclass
from hashlib import sha256
from ipaddress import IPv4Address
import json
import re


_VIF = re.compile(r"eth[0-9]{1,6}\.([1-9][0-9]{0,3})")
_NAME = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9_.-]{0,62}")
_QUEUE_NUMBER = re.compile(r"0|[1-9][0-9]{0,4}")
_RULE_NUMBER = re.compile(r"[1-9][0-9]{0,5}")
_DIGEST = re.compile(r"[0-9a-f]{64}")
_RETURN_ONLY = {"default-action": "return"}


def _unique_fields(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate inspection scope field")
        result[key] = value
    return result


def _matches(pattern, value):
    return isinstance(value, str) and pattern.fullmatch(value) is not None


@dataclass(frozen=True, slots=True)
class _Endpoint:
    interface: str
    host: str
    zone: str
    chain: str

    def __post_init__(self):
        if not _matches(_VIF, self.interface) or int(self.vlan) > 4094:
            raise ValueError("Stock inspection requires an exact Ethernet VLAN interface")
        if not isinstance(self.host, str):
            raise ValueError("Stock inspection requires an exact IPv4 host")
        host = IPv4Address(self.host)
        if str(host) != self.host or host.is_multicast or host.is_unspecified or host.is_reserved or host.is_loopback:
            raise ValueError("Stock inspection requires a canonical unicast IPv4 host")
        if not _matches(_NAME, self.zone) or not _matches(_NAME, self.chain):
            raise ValueError("Stock inspection requires explicit VyOS zone and chain names")

    @property
    def vlan(self):
        return self.interface.partition(".")[2]


@dataclass(frozen=True, slots=True)
class StockInspectionPolicy:
    queue: int
    server_port: int
    rule_id: int
    passthrough_chain: str
    topology_sha256: str
    initiator: _Endpoint
    responder: _Endpoint

    def __post_init__(self):
        for value, low, high in ((self.queue, 0, 65535), (self.server_port, 1, 65535), (self.rule_id, 1, 999999)):
            if type(value) is not int or not low <= value <= high:
                raise ValueError("Stock inspection requires a valid queue number, port and terminal rule number")
        if not _matches(_NAME, self.passthrough_chain) or not _matches(_DIGEST, self.topology_sha256):
            raise ValueError("Stock inspection requires a passthrough chain and approved topology SHA-256")
        if not isinstance(self.initiator, _Endpoint) or not isinstance(self.responder, _Endpoint):
            raise ValueError("Stock inspection needs two pinned endpoints")
        if any(getattr(self.initiator, field) == getattr(self.responder, field)
               for field in ("vlan", "host", "zone", "chain")):
            raise ValueError("Stock inspection requires distinct VLANs, hosts, zones and directional chains")
        if self.passthrough_chain in (self.initiator.chain, self.responder.chain):
            raise ValueError("Stock inspection passthrough chain must be distinct from the directional chains")

    @classmethod
    def from_json(cls, text):
        """Load the approved scope without defaults or extra fields."""
        if not isinstance(text, str):
            raise ValueError("Stock inspection scope must be a JSON string")
        try:
            scope = json.loads(text, object_pairs_hook=_unique_fields)
        except (ValueError, RecursionError) as error:
            raise ValueError("Stock inspection scope is not valid JSON") from error
        if not isinstance(scope, dict) or scope.keys() != {
            "queue", "server_port", "rule_id", "passthrough_chain", "topology_sha256", "initiator", "responder",
        }:
            raise ValueError("Unexpected stock inspection scope fields")
        for role in ("initiator", "responder"):
            endpoint = scope[role]
            if not isinstance(endpoint, dict) or endpoint.keys() != {"interface", "host", "zone", "chain"}:
                raise ValueError("Unexpected stock inspection endpoint fields")
            scope[role] = _Endpoint(**endpoint)
        return cls(**scope)

    @property
    def scope(self):
        return asdict(self)

    @property
    def networks(self):
        return tuple(sorted((f"br{self.initiator.vlan}", f"br{self.responder.vlan}")))

    @property
    def engine_scope(self):
        return {
            "queue": self.queue, "server_port": self.server_port,
            "initiator": {"interface": self.initiator.interface, "host": self.initiator.host},
            "responder": {"interface": self.responder.interface, "host": self.responder.host},
        }

    def fingerprint(self, config: dict) -> str:
        """Hash the two zones, full directional chains and both passthrough chains.

        The exact queued terminals are normalized to their permits. The base
        filter and unrelated named chains are excluded from the approved hash.
        """
        return self._observe(config)[1]

    def read(self, config: dict) -> bool:
        """Read the complete VyOS firewall subtree and prove approved ownership."""
        queued, digest = self._observe(config)
        if digest != self.topology_sha256:
            raise ValueError("Stock inspection differs from the approved topology")
        return queued

    def commands(self, current: bool, desired: bool) -> tuple[dict, ...]:
        """Change only the three queue-related leaves in each verified terminal."""
        if type(current) is not bool or type(desired) is not bool:
            raise ValueError("Stock inspection requires a verified current and desired queue state")
        if current == desired:
            return ()
        commands = []
        for endpoint in (self.initiator, self.responder):
            path = ["firewall", *self._terminal_path(endpoint)]
            if desired:
                commands.extend((
                    {"op": "set", "path": [*path, "action"], "value": "queue"},
                    {"op": "set", "path": [*path, "queue"], "value": str(self.queue)},
                    {"op": "set", "path": [*path, "queue-options"], "value": "bypass"},
                ))
            else:
                commands.extend((
                    {"op": "delete", "path": [*path, "queue-options"]},
                    {"op": "delete", "path": [*path, "queue"]},
                    {"op": "set", "path": [*path, "action"], "value": "accept"},
                ))
        return tuple(commands)

    def _terminal_path(self, endpoint):
        return "ipv4", "name", endpoint.chain, "rule", str(self.rule_id)

    def _permit(self, source, destination):
        reply = source == self.responder
        source_match = {"address": f"{source.host}/32"}
        destination_match = {"address": f"{destination.host}/32"}
        (source_match if reply else destination_match)["port"] = str(self.server_port)
        return {
            "action": "accept", "protocol": "tcp",
            "inbound-interface": {"name": source.interface}, "outbound-interface": {"name": destination.interface},
            "source": source_match, "destination": destination_match,
        }

    def _zone(self, endpoint, peer):
        return {
            "member": {"interface": endpoint.interface}, "default-action": "drop",
            "default-firewall": {"name": self.passthrough_chain, "ipv6-name": self.passthrough_chain},
            "from": {peer.zone: {"firewall": {"name": peer.chain}}},
        }

    def _observe(self, config):
        if not isinstance(config, dict):
            raise ValueError("Stock inspection needs the complete VyOS firewall subtree")
        families = {family: _subtree(config, family) for family in ("ipv4", "ipv6")}
        named = {family: _subtree(branch, "name") for family, branch in families.items()}
        global_options = _subtree(config, "global-options", optional=True)
        if "state-policy" in global_options or "flowtable" in config:
            raise ValueError("Global firewall state policy or flowtables preempt stock inspection")
        for branch in families.values():
            if set(_subtree(branch, "forward", optional=True)) - {"filter"}:
                raise ValueError("An unsupported forward hook could divert stock inspection")
        if any(branch.get(self.passthrough_chain) != _RETURN_ONLY for branch in named.values()):
            raise ValueError("Stock inspection requires the exact IPv4 and IPv6 passthrough chains")

        zones = _subtree(config, "zone")
        own_zones = {}
        chains = {self.passthrough_chain: _RETURN_ONLY}
        skipped = set()
        modes = set()
        for source, destination in ((self.initiator, self.responder), (self.responder, self.initiator)):
            zone = self._zone(source, destination)
            if zones.get(source.zone) != zone:
                raise ValueError("Stock inspection zone membership or directional bindings differ")
            own_zones[source.zone] = zone
            skipped.update((("zone", source.zone), self._terminal_path(source)))

            chain = _subtree(named["ipv4"], source.chain)
            if chain.keys() != {"default-action", "rule"} or chain["default-action"] != "return":
                raise ValueError("Stock inspection directional chain differs from its return policy")
            rules = _subtree(chain, "rule")
            terminal_slot = str(self.rule_id)
            if terminal_slot not in rules or any(
                not _matches(_RULE_NUMBER, slot) or int(slot) > self.rule_id
                or not isinstance(rule, dict) or (slot != terminal_slot and rule.get("action") not in ("drop", "reject"))
                for slot, rule in rules.items()
            ):
                raise ValueError("Stock inspection terminal rule position is not after only scoped denies")

            permit = self._permit(source, destination)
            queued = {**permit, "action": "queue", "queue": str(self.queue), "queue-options": "bypass"}
            if rules[terminal_slot] not in (permit, queued):
                raise ValueError("Stock inspection terminal permit or queue differs from the exact selectors")
            modes.add(rules[terminal_slot] == queued)
            chains[source.chain] = {"default-action": "return", "rule": {**rules, terminal_slot: permit}}

        if len(modes) != 1:
            raise ValueError("Stock inspection has mixed permit and queue state")
        self._check_other_zones(zones, own_zones)
        _check_foreign_config(config, skipped, set(chains), self.queue)
        topology = {
            "zone": own_zones, "ipv4": {"name": chains},
            "ipv6": {"name": {self.passthrough_chain: _RETURN_ONLY}},
        }
        canonical = json.dumps(topology, sort_keys=True, separators=(",", ":"), allow_nan=False)
        return modes.pop(), sha256(canonical.encode("utf-8")).hexdigest()

    def _check_other_zones(self, zones, own_zones):
        owned_vifs = {self.initiator.interface, self.responder.interface}
        for name in zones.keys() - own_zones.keys():
            zone = _subtree(zones, name)
            member = _subtree(zone, "member", optional=True)
            from_zones = _subtree(zone, "from", optional=True)
            interfaces = member.get("interface", [])
            if isinstance(interfaces, str):
                interfaces = [interfaces]
            if (
                set(member) - {"interface"} or own_zones.keys() & from_zones.keys()
                or not isinstance(interfaces, list) or any(
                    not isinstance(interface, str) or any(char in interface for char in "*?[") or interface in owned_vifs
                    for interface in interfaces
                )
            ):
                raise ValueError("A foreign firewall zone may overlap the stock inspection path")


def _subtree(config, key, *, optional=False):
    value = config.get(key, {} if optional else None)
    if not isinstance(value, dict):
        raise ValueError("Stock inspection needs a complete firewall configuration tree")
    return value


def _check_foreign_config(node, skipped, chain_names, queue_number, path=()):
    if "offload-target" in node or node.get("action") == "offload":
        raise ValueError("A firewall offload rule could bypass stock inspection")
    if {"queue", "queue-options"} & node.keys() or "queue" in (node.get("action"), node.get("default-action")):
        target = node.get("queue")
        if (
            node.get("action") != "queue" or node.get("default-action") == "queue"
            or not _matches(_QUEUE_NUMBER, target) or int(target) > 65535 or int(target) == queue_number
            or node.get("queue-options") not in (None, "bypass")
        ):
            raise ValueError("A foreign firewall rule may use the reserved inspection queue")
    for field, value in node.items():
        location = (*path, field)
        if location in skipped:
            continue
        if (
            field in ("jump-target", "default-jump-target", "ipv6-name")
            or (field == "name" and path[-1:] in (("firewall",), ("default-firewall",)))
        ):
            if not isinstance(value, str) or value in chain_names:
                raise ValueError("A foreign firewall rule or zone may reference an owned inspection chain")
        if isinstance(value, dict):
            _check_foreign_config(value, skipped, chain_names, queue_number, location)
        elif isinstance(value, list) and any(not isinstance(item, str) for item in value):
            raise ValueError("Stock inspection needs an unambiguous firewall configuration tree")
