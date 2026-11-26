"""Decode the native COMPLETE election and map it to owned stock VyOS resources."""

from copy import deepcopy
from dataclasses import dataclass, replace
from ipaddress import IPv4Address, IPv4Interface, IPv6Address, ip_interface
import re

from gateway_profiles.vyos_vrrp import SHADOW_SYNC_GROUP
from provisioners.uxg_enterprise_shadow import SHADOW_ADDRESSES, validate_shadow_interface
from provisioners.vyos_shadow_binding import ShadowEnrollmentPair
from provisioners.vyos_shadow_guard import ShadowManagementGuard


SHADOW_VRRP_GROUP = "UXGSHADOW"
_POLICY_GUARD = "/config/scripts/unifi-gateway-shadow-policy-eligible.py"
_VRRP = ["high-availability", "vrrp"]
SHADOW_VRRP_PARENTS = (("high-availability",), tuple(_VRRP))
_CONNTRACK = ["service", "conntrack-sync"]
_BRIDGE = re.compile(r"br[0-9]{1,4}")
_IFACE = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,14}")
_INTERCONNECT = IPv4Interface(SHADOW_ADDRESSES[0]).network
_INSTANCE_FIELDS = {"interface", "vrid", "priority", "advertisementInterval", "useVmac", "unicastAdvertise", "virtualIPs"}


@dataclass(frozen=True)
class ShadowElection:
    source: str
    peer: str
    priority: int
    virtual_ips: tuple[tuple[str, IPv4Interface], ...]
    peer_lan: tuple[str, str] | None


@dataclass(frozen=True)
class ShadowNode:
    interconnect: str
    local_address: str
    interfaces: dict[str, str]
    lan_address: str


def decode_shadow_vrrp(payload, *, version):
    """Match the pinned managed gateway resource before accepting any election fields."""
    if type(version) is not int or version != 5:
        raise ValueError("Unsupported Enterprise Shadow Mode VRRP schema")
    if not isinstance(payload, dict) or payload.keys() != {"enabled", "instances"} or payload["enabled"] is not True:
        raise ValueError("Expected an enabled Enterprise Shadow Mode election")
    instances = payload["instances"]
    if not isinstance(instances, list) or len(instances) != 1 or not isinstance(instances[0], dict):
        raise ValueError("Enterprise Shadow Mode requires one interconnect election")
    instance = instances[0]
    if instance.keys() - {"masterGuard"} != _INSTANCE_FIELDS:
        raise ValueError("Unknown Enterprise Shadow Mode VRRP fields")
    priority = instance["priority"]
    if (instance["interface"] != "eth1" or type(instance["vrid"]) is not int or instance["vrid"] != 42
            or type(instance["advertisementInterval"]) is not int or instance["advertisementInterval"] != 1
            or instance["useVmac"] is not False or type(priority) is not int or priority not in {100, 120, 255}):
        raise ValueError("Unsupported Enterprise Shadow Mode election options")
    endpoints = tuple(str(IPv4Interface(address).ip) for address in SHADOW_ADDRESSES)
    source, peer = endpoints[::-1] if priority == 100 else endpoints
    if instance["unicastAdvertise"] != {"sourceIP": source, "peerIP": peer}:
        raise ValueError("The Shadow Mode priority and unicast endpoints disagree")
    peer_lan = None
    if "masterGuard" in instance:
        guard = instance["masterGuard"]
        lan = guard.get("peerLan") if isinstance(guard, dict) and guard.keys() == {"peerLan"} else None
        if (priority != 100 or not isinstance(lan, dict) or lan.keys() != {"interface", "address"}
                or lan["interface"] != "br0" or not isinstance(lan["address"], str) or "%" in lan["address"]):
            raise ValueError("Unsupported Shadow Mode LAN peer guard")
        try:
            address = IPv6Address(lan["address"])
        except ValueError:
            raise ValueError("Invalid link-local Shadow Mode LAN peer") from None
        if not address.is_link_local:
            raise ValueError("The Shadow Mode LAN peer must be link-local")
        peer_lan = ("br0", str(address))

    addresses = instance["virtualIPs"]
    if not isinstance(addresses, list) or not addresses:
        raise ValueError("Stock VyOS Shadow Mode requires an IPv4 virtual address")
    vips = {}
    used_ips = set()
    for row in addresses:
        if (not isinstance(row, dict) or row.keys() != {"interface", "address"}
                or not isinstance(row["interface"], str) or _BRIDGE.fullmatch(row["interface"]) is None
                or not isinstance(row["address"], str)):
            raise ValueError("Invalid Shadow Mode virtual address record")
        bridge = row["interface"]
        try:
            address = IPv4Interface(row["address"])
        except ValueError:
            raise ValueError("Invalid IPv4 Shadow Mode virtual address") from None
        network = address.network
        if (str(address) != row["address"] or bridge in vips or address.ip in used_ips
                or network.prefixlen == 0 or network.overlaps(_INTERCONNECT)
                or (network.prefixlen < 31 and address.ip in (network.network_address, network.broadcast_address))
                or any(network.overlaps(other.network) for other in vips.values())
                or address.ip.is_multicast or address.ip.is_loopback
                or address.ip.is_unspecified or address.ip.is_reserved):
            raise ValueError("Ambiguous or unsupported Shadow Mode virtual address")
        vips[bridge] = address
        used_ips.add(address.ip)
    return ShadowElection(source, peer, priority, tuple(vips.items()), peer_lan)


def _set_tree(path, tree):
    for name, value in tree.items():
        item = [*path, name]
        if value and isinstance(value, dict):
            yield from _set_tree(item, value)
        elif value == {}:
            yield {"op": "set", "path": item}
        else:
            yield {"op": "set", "path": item, "value": value}


def _vrrp_inventory(vrrp):
    if vrrp is not None and not isinstance(vrrp, dict):
        raise ValueError("VyOS returned an invalid VRRP inventory")
    groups = (vrrp or {}).get("group", {})
    sync = (vrrp or {}).get("sync-group", {})
    if not all(isinstance(branch, dict) and all(isinstance(row, dict) for row in branch.values()) for branch in (groups, sync)):
        raise ValueError("VyOS returned an invalid VRRP inventory")
    for name, member in sync.items():
        members = member.get("member", [])
        if isinstance(members, str):
            members = [members]
        if not isinstance(members, list):
            raise ValueError("VyOS returned an invalid VRRP membership")
        if name != SHADOW_SYNC_GROUP and SHADOW_VRRP_GROUP in members:
            raise ValueError("An operator VRRP sync group refers to the Shadow Mode group")
    return groups, sync


@dataclass(frozen=True)
class _ShadowResourceScope:
    interconnect: str
    local_sync: IPv4Interface
    peer_sync: IPv4Address
    election: str
    vips: tuple[tuple[IPv4Interface, str], ...]
    lan_source: IPv4Interface | None = None
    lan_peer: IPv4Address | None = None
    primary_lan_link_local: str | None = None

    def verify_empty(self, vrrp, conntrack, kernel_addresses, *, transferring=None):
        groups, sync = _vrrp_inventory(vrrp)
        if SHADOW_VRRP_GROUP in groups or SHADOW_SYNC_GROUP in sync or conntrack is not None:
            raise ValueError("VyOS Shadow Mode resources are already in use")
        self.verify_other_groups(groups)
        expected = () if transferring is None else (transferring,)
        self.verify_kernel(kernel_addresses, expected=expected)

    def verify_other_groups(self, groups):
        intended_ips = {str(address.ip) for address, _ in self.vips}
        for name, group in groups.items():
            if name == SHADOW_VRRP_GROUP:
                continue
            if group.get("interface") == self.election and group.get("vrid") == "42":
                raise ValueError("VyOS already uses VRID 42 on the Shadow Mode election interface")
            for branch in ("address", "excluded-address"):
                current = group.get(branch, {})
                if not isinstance(current, dict):
                    raise ValueError("VyOS returned invalid VRRP address ownership")
                if any(cidr.split("/")[0] in intended_ips for cidr in current):
                    raise ValueError("An operator VRRP group already owns a Shadow Mode virtual IP")

    def verify_kernel(self, kernel_addresses, *, expected):
        owners = {interface for _, interface in self.vips}
        if not isinstance(kernel_addresses, dict) or not (owners | {self.interconnect, self.election}).issubset(kernel_addresses):
            raise ValueError("A mapped VyOS Shadow Mode interface is unavailable")
        assignments = [(interface, address) for interface, addresses in kernel_addresses.items() for address in addresses]
        endpoints = [(interface, address) for interface, address in assignments
                     if address.ip in {self.local_sync.ip, self.peer_sync}]
        if endpoints != [(self.interconnect, self.local_sync)]:
            raise ValueError("Kernel addresses disagree with the verified Shadow Mode interconnect")
        if self.lan_source is not None:
            endpoints = [(interface, address) for interface, address in assignments
                         if address.ip in {self.lan_source.ip, self.lan_peer}]
            if endpoints != [(self.election, self.lan_source)]:
                raise ValueError("Kernel addresses disagree with the Shadow Mode LAN election endpoints")
        if self.primary_lan_link_local is not None and not any(
                str(address.ip) == self.primary_lan_link_local for address in kernel_addresses[self.election]):
            raise ValueError("The verified primary LAN is missing the native Shadow Mode peer address")
        intended_ips = {vip.ip for vip, _ in self.vips}
        actual = [(interface, address) for interface, address in assignments if address.ip in intended_ips]
        if len(actual) != len(expected) or set(actual) != set(expected):
            raise ValueError("Kernel addresses disagree with the expected Shadow Mode VIP ownership")
        if any(owner != interface and address.network.overlaps(vip.network)
               for interface, address in assignments for vip, owner in self.vips):
            raise ValueError("An operator interface already routes a Shadow Mode virtual network")


@dataclass(frozen=True)
class VyOSShadowElection:
    group: dict
    sync_group: dict
    conntrack: dict
    lan_source: IPv4Interface | None = None
    primary_lan_link_local: str | None = None

    def _resource_scope(self):
        interconnect, link = next(iter(self.conntrack["interface"].items()))
        return _ShadowResourceScope(
            interconnect, IPv4Interface(f'{self.conntrack["listen-address"]}/24'), IPv4Address(link["peer"]),
            self.group["interface"], _vip_assignments(self.group["address"]), self.lan_source,
            IPv4Address(self.group["peer-address"]) if self.lan_source is not None else None,
            self.primary_lan_link_local,
        )

    def verify_empty(self, vrrp, conntrack, kernel_addresses, *, transferring=None):
        """Refuse existing consumers of the election, VIPs or global conntrack service."""
        self._resource_scope().verify_empty(vrrp, conntrack, kernel_addresses, transferring=transferring)

    def create_commands(self):
        """Render the exact group, receipt guard and stock connection replication commands."""
        return [*_set_tree([*_VRRP, "group", SHADOW_VRRP_GROUP], self.group),
                *_set_tree([*_VRRP, "sync-group", SHADOW_SYNC_GROUP], self.sync_group),
                *_set_tree(_CONNTRACK, self.conntrack)]

    def verify_owned(self, vrrp, conntrack):
        groups, sync = _vrrp_inventory(vrrp)
        if groups.get(SHADOW_VRRP_GROUP) != self.group or sync.get(SHADOW_SYNC_GROUP) != self.sync_group or conntrack != self.conntrack:
            raise ValueError("VyOS Shadow Mode resources differ from verified ownership")
        self._resource_scope().verify_other_groups(groups)

    def withdraw_commands(self, vrrp, conntrack):
        self.verify_owned(vrrp, conntrack)
        return [{"op": "delete", "path": path} for path in (
            _CONNTRACK, [*_VRRP, "sync-group", SHADOW_SYNC_GROUP], [*_VRRP, "group", SHADOW_VRRP_GROUP],
        )]

    def withdraw_stock_commands(self, stock, *, created_vrrp_parent):
        """Delete owned leaves or prune a proven ancestor that holds only those leaves."""
        if stock.projected:
            raise ValueError("Shadow Mode withdrawal requires complete running and saved configuration")
        self.verify_owned(stock.read(stock.saved, _VRRP), stock.read(stock.saved, _CONNTRACK))
        withdrawal = self.withdraw_commands(stock.read(stock.running, _VRRP), stock.read(stock.running, _CONNTRACK))
        owned_vrrp = {"group": {SHADOW_VRRP_GROUP: self.group},
                      "sync-group": {SHADOW_SYNC_GROUP: self.sync_group}}
        if created_vrrp_parent:
            for path, expected in zip(SHADOW_VRRP_PARENTS, ({"vrrp": owned_vrrp}, owned_vrrp), strict=True):
                if (path[:len(created_vrrp_parent)] == created_vrrp_parent
                        and all(stock.read(config, path) == expected for config in (stock.running, stock.saved))):
                    return [{"op": "delete", "path": _CONNTRACK}, {"op": "delete", "path": list(path)}]
        return withdrawal


_VRRP_ADDRESS_ROW = {"type": "dynamic", "cidr": None, "origin": "vrrp", "eui64": False, "version": "v4"}
_ETHERNET_LAN = re.compile(r"(eth[0-9]{1,7})(?:\.([1-9][0-9]{0,3}))?")


def _address_leaf(interface):
    match = _ETHERNET_LAN.fullmatch(interface)
    if match:
        parent, tag = match.groups()
        if tag is None:
            return ("interfaces", "ethernet", parent, "address")
        if int(tag) <= 4094:
            return ("interfaces", "ethernet", parent, "vif", tag, "address")
    if _BRIDGE.fullmatch(interface):
        return ("interfaces", "bridge", interface, "address")
    raise ValueError("The verified Shadow Mode LAN has an unsupported VyOS configuration path")


def _configured_address_order(interface):
    if not isinstance(interface, dict) or {"disable", "vrf"} & interface.keys():
        raise ValueError("The verified Shadow Mode LAN configuration is unavailable")
    addresses = interface.get("address", [])
    if isinstance(addresses, str):
        addresses = [addresses]
    if (not isinstance(addresses, list) or any(not isinstance(value, str) for value in addresses)
            or len(set(addresses)) != len(addresses)):
        raise ValueError("The verified Shadow Mode LAN has an invalid address inventory")
    return tuple(addresses)


def _absent_vrrp_parent(config):
    parent, branch = _VRRP
    if parent not in config:
        return (parent,)
    if not isinstance(config[parent], dict):
        raise ValueError("Invalid VyOS high-availability configuration")
    return () if branch in config[parent] else (parent, branch)


def _remove_config_subtree(tree, path):
    key, *rest = path
    if key not in tree:
        return
    if not rest:
        del tree[key]
        return
    child = tree[key]
    if not isinstance(child, dict):
        raise ValueError("Unexpected VyOS configuration subtree during the Shadow Mode handoff")
    _remove_config_subtree(child, rest)
    if not child:
        del tree[key]


def _verify_controller_alias(ordinary, complete, address):
    static = {"type": "static", "cidr": str(address), "version": "v4"}
    if (not isinstance(ordinary, list) or not isinstance(complete, list) or not ordinary or not complete
            or ordinary[0] != static or complete[0] != _VRRP_ADDRESS_ROW
            or complete[0]["eui64"] is not False or ordinary[1:] != complete[1:]):
        raise ValueError("The controller did not transfer exactly the ordinary Shadow Mode LAN gateway address")
    for row in ordinary[1:]:
        if not isinstance(row, dict):
            raise ValueError("The verified Shadow Mode LAN has a malformed alias")
        cidr = row.get("cidr")
        if isinstance(cidr, str) and cidr.split("/")[0] == str(address.ip):
            raise ValueError("The controller also declares the Shadow Mode gateway as a LAN alias")


def _configured_interface_ips(interface, node):
    if not isinstance(node, dict):
        raise ValueError("VyOS returned an invalid configured interface")
    values = node.get("address", [])
    if isinstance(values, str):
        values = [values]
    if not isinstance(values, list) or any(not isinstance(value, str) for value in values):
        raise ValueError("VyOS returned invalid configured interface addresses")
    for value in values:
        if value not in {"dhcp", "dhcpv6"}:
            address = ip_interface(value)
            if address.version == 4:
                yield interface, address
    for kind in ("vif", "vif-s", "vif-c"):
        children = node.get(kind, {})
        if not isinstance(children, dict):
            raise ValueError("VyOS returned invalid configured interface VLANs")
        for tag, child in children.items():
            yield from _configured_interface_ips(f"{interface}.{tag}", child)


def _vip_assignments(addresses):
    return tuple((IPv4Interface(cidr), row["interface"]) for cidr, row in addresses.items())


def _verify_configured_vips(config, vips, transferring):
    interfaces = ShadowStockState.read(config, ("interfaces",))
    if interfaces is None:
        return
    if not isinstance(interfaces, dict) or any(not isinstance(group, dict) for group in interfaces.values()):
        raise ValueError("VyOS returned an invalid configured interface inventory")
    for group in interfaces.values():
        for name, node in group.items():
            for interface, address in _configured_interface_ips(name, node):
                if any((address.ip == vip.ip and (interface, address) != transferring)
                       or (interface != owner and vip.network.overlaps(address.network)) for vip, owner in vips):
                    raise ValueError("A configured interface conflicts with a Shadow Mode virtual IP or network")


@dataclass(frozen=True)
class ShadowStockState:
    running: dict
    saved: dict
    kernel: dict
    projected: bool = False

    @staticmethod
    def read(config, path):
        for name in path:
            if not isinstance(config, dict):
                raise ValueError("VyOS returned an invalid Shadow Mode configuration tree")
            if name not in config:
                return None
            config = config[name]
        return config

    def verify_empty(self, plan, *, transferring=None):
        self._verify_fenced(plan._resource_scope(), transferring=transferring)

    def _verify_fenced(self, scope, *, transferring=None):
        for config in (self.running, self.saved):
            scope.verify_empty(self.read(config, _VRRP), self.read(config, _CONNTRACK),
                               self.kernel, transferring=transferring)
            _verify_configured_vips(config, scope.vips, transferring)


@dataclass(frozen=True)
class ShadowLanPreimage:
    addresses: tuple[str, ...]
    route_source: str
    guard_containers: tuple[tuple[str, ...], ...] = ()
    created_vrrp_parent: tuple[str, ...] = ()


@dataclass(frozen=True)
class ShadowLanHandoff:
    primary: VyOSShadowElection
    standby_scope: _ShadowResourceScope
    address: IPv4Interface
    path: tuple[str, ...]
    other_addresses: frozenset[str]
    ordinary_route_source: str
    ordinary_address_order: tuple[str, ...]
    complete_snapshot_sha256: str | None = None
    complete_binding: ShadowEnrollmentPair | None = None
    standby_resources_sha256: str | None = None
    site_policy_sha256: str | None = None
    management_guard: ShadowManagementGuard | None = None
    guard_containers: tuple[tuple[str, ...], ...] = ()
    created_vrrp_parent: tuple[str, ...] = ()

    def _verify_config_addresses(self, config, *, static):
        addresses = self.other_addresses | {str(self.address)} if static else self.other_addresses
        if frozenset(_configured_address_order(config)) != addresses:
            raise ValueError("Configured LAN addresses disagree with the Shadow Mode handoff")

    def _verify_kernel_addresses(self, kernel, *, static):
        assignments = [(interface, address) for interface, rows in kernel.items()
                       for address in rows if address.ip == self.address.ip]
        expected = [(self.primary.group["interface"], self.address)] if static else []
        if assignments != expected:
            raise ValueError("The gateway address is assigned outside the expected Shadow Mode handoff")
        addresses = self.other_addresses | {str(self.address)} if static else self.other_addresses
        live = {str(address) for address in kernel.get(self.primary.group["interface"], ())}
        if not (addresses - {"dhcp", "dhcpv6"}) <= live:
            raise ValueError("A configured Shadow Mode LAN address is missing in the kernel")

    def verify_address(self, running, saved, kernel, *, static):
        self._verify_config_addresses(running, static=static)
        self._verify_config_addresses(saved, static=static)
        self._verify_kernel_addresses(kernel, static=static)

    def create_commands(self):
        guards = self.management_guard.create_commands() if self.management_guard is not None else []
        return [{"op": "delete", "path": [*self.path, str(self.address)]}, *self.primary.create_commands(), *guards]

    def outside_transfer_configuration(self, config):
        """Keep the full configuration outside the gateway address and exact owned resources."""
        result = deepcopy(config)
        lan = ShadowStockState.read(result, self.path[:-1])
        lan[self.path[-1]] = [cidr for cidr in _configured_address_order(lan) if cidr != str(self.address)]
        for path in ((*_VRRP, "group", SHADOW_VRRP_GROUP), (*_VRRP, "sync-group", SHADOW_SYNC_GROUP), _CONNTRACK):
            _remove_config_subtree(result, path)
        if self.management_guard is not None:
            for path in self.management_guard.paths:
                _remove_config_subtree(result, path)
        return result

    def reboot_safe_transfer_commands(self, preimage, *, peer, route_source):
        """Prepare a transfer whose unconfirmed candidate reboots into the verified preimage."""
        self._verify_reboot_preimage(preimage, peer=peer, route_source=route_source)
        self._verify_boot_source_order()
        return self.create_commands()

    def verify_reboot_rollback(self, preimage, restored, *, peer, route_source):
        """Require a fresh boot of the exact pre-handoff configuration and its original route."""
        if restored.boot_id == preimage.boot_id:
            raise ValueError("Shadow Mode rollback still needs a verified reboot")
        if (restored.saved_sha256, restored.config_sha256) != (preimage.saved_sha256, preimage.config_sha256):
            raise ValueError("Shadow Mode reboot did not restore the verified configuration preimage")
        self._verify_reboot_preimage(restored, peer=peer, route_source=route_source)

    def _verify_reboot_preimage(self, observation, *, peer, route_source):
        if observation.rollback_action != "reboot":
            raise ValueError("This Shadow Mode handoff requires VyOS's reboot rollback action")
        if (observation.phase != "saved_commit" or observation.role != "unknown"
                or observation.state.running != observation.state.saved):
            raise ValueError("Shadow Mode reboot requires a settled ordinary configuration")
        self.verify_standby_fenced(peer)
        self._verify_restoration(observation.state, route_source)
        saved_lan = observation.state.read(observation.state.saved, self.path[:-1])
        if _configured_address_order(saved_lan) != self.ordinary_address_order:
            raise ValueError("Shadow Mode reboot configuration changed the ordinary LAN address order")
        if not observation.state.projected:
            self.verify_ordinary_vrrp_ancestry(observation.state.saved)

    def verify_ordinary_vrrp_ancestry(self, config):
        if self.created_vrrp_parent and _absent_vrrp_parent(config) != self.created_vrrp_parent:
            raise ValueError("The ordinary Shadow Mode VRRP ancestry changed before transfer")

    def _verify_released(self, kernel):
        virtual = {IPv4Interface(cidr).ip for cidr in self.primary.group["address"]}
        if any(address.ip in virtual for rows in kernel.values() for address in rows):
            raise ValueError("The primary must release all Shadow Mode virtual IPs")

    def verify_standby_fenced(self, peer):
        for config in (peer.running, peer.saved):
            lan = peer.read(config, _address_leaf(self.standby_scope.election)[:-1])
            _verify_standby_lan(lan, self.standby_scope.lan_source, self.address)
        peer._verify_fenced(self.standby_scope)

    def verify_staged_transfer(self, local, *, peer, role):
        """Require the running candidate and the saved ordinary configuration before confirm."""
        if role != "fault":
            raise ValueError("The staged Shadow Mode primary must stay fenced")
        self.verify_standby_fenced(peer)
        self.primary.verify_owned(local.read(local.running, _VRRP), local.read(local.running, _CONNTRACK))
        scope = self.primary._resource_scope()
        scope.verify_empty(local.read(local.saved, _VRRP), local.read(local.saved, _CONNTRACK), local.kernel)
        _verify_configured_vips(local.running, scope.vips, None)
        _verify_configured_vips(local.saved, scope.vips, (self.primary.group["interface"], self.address))
        self._verify_config_addresses(local.read(local.running, self.path[:-1]), static=False)
        if _configured_address_order(local.read(local.saved, self.path[:-1])) != self.ordinary_address_order:
            raise ValueError("The saved ordinary address order changed during the Shadow Mode handoff")
        self._verify_kernel_addresses(local.kernel, static=False)

    def verify_saved_transfer(self, local, *, peer, role):
        """Verify the saved primary candidate while it still owns no virtual IPs."""
        if role != "fault":
            raise ValueError("The saved Shadow Mode primary must stay fenced until activation")
        self._verify_transferred(local, peer=peer, owns_vips=False)

    def verify_primary_master(self, local, *, peer, role):
        """Verify live ownership after activation and before acknowledging the primary role."""
        if role != "master":
            raise ValueError("The activated Shadow Mode primary must report MASTER")
        self._verify_transferred(local, peer=peer, owns_vips=True)

    def _verify_transferred(self, local, *, peer, owns_vips):
        self.verify_standby_fenced(peer)
        scope = self.primary._resource_scope()
        for config in (local.running, local.saved):
            self.primary.verify_owned(local.read(config, _VRRP), local.read(config, _CONNTRACK))
            self._verify_config_addresses(local.read(config, self.path[:-1]), static=False)
            _verify_configured_vips(config, scope.vips, None)
        expected = tuple((interface, vip) for vip, interface in scope.vips) if owns_vips else ()
        scope.verify_kernel(local.kernel, expected=expected)
        self._verify_kernel_addresses(local.kernel, static=owns_vips)

    def restore_commands(self, *, local, peer):
        """Restore the primary preimage after verified persistent withdrawal on the standby."""
        if local.projected:
            raise ValueError("Shadow Mode withdrawal requires complete running and saved configuration")
        self.verify_standby_fenced(peer)
        self.verify_address(local.read(local.running, self.path[:-1]), local.read(local.saved, self.path[:-1]),
                            local.kernel, static=False)
        self._verify_released(local.kernel)
        guard = self.management_guard
        if guard is not None:
            guard.verify_stock(local.saved, installed=True)
        withdrawal = self.primary.withdraw_stock_commands(local, created_vrrp_parent=self.created_vrrp_parent)
        return [*withdrawal,
                *(guard.withdraw_commands(local.running, created_containers=self.guard_containers)
                  if guard is not None else ()),
                {"op": "set", "path": list(self.path), "value": str(self.address)}]

    def _verify_restored_tree(self, config, local):
        scope = self.primary._resource_scope()
        transferring = self.primary.group["interface"], self.address
        scope.verify_empty(local.read(config, _VRRP), local.read(config, _CONNTRACK), local.kernel,
                           transferring=transferring)
        _verify_configured_vips(config, scope.vips, transferring)
        self._verify_config_addresses(local.read(config, self.path[:-1]), static=True)
        if not local.projected and self.created_vrrp_parent:
            if local.read(config, _VRRP) == {} or local.read(config, self.created_vrrp_parent) == {}:
                raise ValueError("The restored router still has an empty Shadow Mode VRRP parent")
            if self.created_vrrp_parent == tuple(_VRRP) and _VRRP[0] not in config:
                raise ValueError("Shadow Mode restoration removed the pre-existing high-availability parent")
        if self.management_guard is not None:
            self.management_guard.verify_stock(config, installed=False)

    def _verify_restored_route(self, local, route_source):
        self._verify_kernel_addresses(local.kernel, static=True)
        if route_source != self.ordinary_route_source:
            raise ValueError("The restored Shadow Mode LAN route changed its preferred source")

    def _verify_staged_restoration(self, local):
        if local.projected:
            raise ValueError("Shadow Mode restoration requires complete running and saved configuration")
        self._verify_restored_tree(local.running, local)
        self.primary.verify_owned(local.read(local.saved, _VRRP), local.read(local.saved, _CONNTRACK))
        self._verify_config_addresses(local.read(local.saved, self.path[:-1]), static=False)
        if self.management_guard is not None:
            self.management_guard.verify_stock(local.saved, installed=True)

    def verify_staged_restoration(self, local, *, route_source):
        """Leave commit-confirm armed when the candidate fails the ordinary route preimage."""
        self._verify_staged_restoration(local)
        self._verify_restored_route(local, route_source)

    def _verify_boot_source_order(self):
        static_addresses = (ip_interface(value) for value in self.ordinary_address_order if value not in {"dhcp", "dhcpv6"})
        original_subnet = [address for address in static_addresses
                           if address.network == self.address.network]
        if not original_subnet or str(original_subnet[0].ip) != self.ordinary_route_source:
            raise ValueError("The saved Shadow Mode LAN address order does not explain the original preferred source")

    def maintenance_restore_commands(self, *, local, peer):
        """Prepare the original saved address order for a separately verified maintenance reboot."""
        self._verify_boot_source_order()
        withdrawal = self.restore_commands(local=local, peer=peer)
        return [
            *withdrawal[:-1],
            *({"op": "delete", "path": [*self.path, cidr]} for cidr in self.ordinary_address_order if cidr != str(self.address)),
            *({"op": "set", "path": list(self.path), "value": cidr} for cidr in self.ordinary_address_order),
        ]

    def verify_staged_maintenance_restoration(self, local):
        """Check exact ordinary order before saving for reboot. Verify the route after boot."""
        self._verify_staged_restoration(local)
        if _configured_address_order(local.read(local.running, self.path[:-1])) != self.ordinary_address_order:
            raise ValueError("The staged Shadow Mode LAN address order differs from the saved ordinary order")
        if self.outside_transfer_configuration(local.running) != self.outside_transfer_configuration(local.saved):
            raise ValueError("The staged restoration changed configuration outside Shadow Mode ownership")
        self._verify_kernel_addresses(local.kernel, static=True)

    def verify_restored(self, local, *, route_source):
        """Check the static preimage, withdrawn resources and the original connected route source."""
        if local.projected:
            raise ValueError("Shadow Mode restoration requires complete running and saved configuration")
        self._verify_restoration(local, route_source)

    def _verify_restoration(self, local, route_source):
        self._verify_restored_tree(local.running, local)
        self._verify_restored_tree(local.saved, local)
        self._verify_restored_route(local, route_source)


def _verify_standby_lan(lan, source, vip):
    addresses = _configured_address_order(lan)
    if str(source) not in addresses or any(address.split("/")[0] == str(vip.ip) for address in addresses):
        raise ValueError("The standby LAN configuration must have its unique address and no static VIP")


def prepare_shadow_lan_handoff(primary, standby, *, ordinary, complete, local, peer, route_source):
    """Prepare the primary transfer from an authenticated ordinary and COMPLETE address pair."""
    if (primary.lan_source is None or standby.lan_source is None or primary.primary_lan_link_local is None
            or primary.group["priority"] != "120" or standby.group["priority"] != "100"
            or primary.group["peer-address"] != str(standby.lan_source.ip)
            or standby.group["peer-address"] != str(primary.lan_source.ip)
            or primary.group["address"].keys() != standby.group["address"].keys()):
        raise ValueError("The Shadow Mode LAN handoff requires a verified matched pair")
    if len(ordinary) != 2 or len(complete) != 2:
        raise ValueError("The Shadow Mode LAN handoff requires both nodes' controller snapshots")
    handoff = _prepare_shadow_lan_handoff(primary, standby._resource_scope(), ordinary=ordinary[0], complete=complete[0],
                                          local=local, peer=peer, route_source=route_source)
    _verify_controller_alias(ordinary[1], complete[1], handoff.address)
    return handoff


def prepare_shadow_primary_lan_handoff(election, *, nodes, primary_lan_link_local, ordinary, complete, local, peer,
                                       route_source, recovery=None):
    """Prepare the initial primary transfer without compiling a standby configuration."""
    primary = build_vyos_shadow_primary_activation(election, nodes=nodes, primary_lan_link_local=primary_lan_link_local)
    _, standby = nodes
    standby_scope = _ShadowResourceScope(
        standby.interconnect, IPv4Interface(standby.local_address), IPv4Address(election.source), standby.interfaces["br0"],
        _vip_assignments(_mapped_vip_addresses(election.virtual_ips, standby)), IPv4Interface(standby.lan_address),
        primary.lan_source.ip,
    )
    return _prepare_shadow_lan_handoff(primary, standby_scope, ordinary=ordinary, complete=complete, local=local,
                                       peer=peer, route_source=route_source, recovery=recovery)


def _prepare_shadow_lan_handoff(primary, standby_scope, *, ordinary, complete, local, peer, route_source, recovery=None):
    lan = primary.group["interface"]
    address, = (IPv4Interface(cidr) for cidr, row in primary.group["address"].items() if row["interface"] == lan)
    _verify_controller_alias(ordinary, complete, address)
    path = _address_leaf(lan)
    if recovery is not None:
        other_addresses = frozenset(recovery.addresses) - {str(address)}
        if str(address) not in recovery.addresses or str(primary.lan_source) not in other_addresses:
            raise ValueError("The saved Shadow Mode preimage lacks the mapped LAN addresses")
        result = ShadowLanHandoff(primary, standby_scope, address, path, other_addresses,
                                  recovery.route_source, recovery.addresses, guard_containers=recovery.guard_containers,
                                  created_vrrp_parent=recovery.created_vrrp_parent)
        result._verify_boot_source_order()
        result.verify_standby_fenced(peer)
        return result
    running, saved = (local.read(config, path[:-1]) for config in (local.running, local.saved))
    other_addresses = frozenset(_configured_address_order(running)) - {str(address)}
    if str(primary.lan_source) not in other_addresses:
        raise ValueError("The primary LAN needs a saved election address before the gateway handoff")
    if (not isinstance(route_source, str)
            or IPv4Address(route_source) not in {entry.ip for entry in local.kernel.get(lan, ())}):
        raise ValueError("The ordinary connected route needs a verified preferred source on the primary LAN")
    created_parent = ()
    if not local.projected:
        created_parent = _absent_vrrp_parent(local.saved)
        if _absent_vrrp_parent(local.running) != created_parent:
            raise ValueError("Running and saved Shadow Mode VRRP ancestry disagree")
    result = ShadowLanHandoff(primary, standby_scope, address, path, other_addresses, route_source,
                              _configured_address_order(saved), created_vrrp_parent=created_parent)
    result.verify_standby_fenced(peer)
    local.verify_empty(primary, transferring=(lan, address))
    result.verify_address(running, saved, local.kernel, static=True)
    return result


def build_vyos_shadow(election, *, interconnect, local_address, interfaces):
    """Prepare stock primary resources. Standby activation needs an independent LAN guard."""
    if election.priority == 100 or election.peer_lan is not None:
        raise ValueError("Shadow Mode standby needs a verified independent peer guard")
    return _build_vyos_shadow(election, ShadowNode(interconnect, local_address, interfaces, ""))


def build_vyos_shadow_pair(primary, standby, *, nodes, initial_setup=False):
    """Prepare matching stock elections on the mapped LAN and state sync on the interconnect."""
    left, right = nodes
    if initial_setup is True and primary.priority == 255:
        # Stock priority 255 denotes an address owner and overrides no-preempt.
        primary = replace(primary, priority=120)
    if (primary.priority != 120 or standby.priority != 100 or primary.peer_lan is not None
            or standby.peer_lan is None or standby.peer_lan[0] != "br0"
            or primary.source != standby.peer or primary.peer != standby.source
            or dict(primary.virtual_ips) != dict(standby.virtual_ips)):
        raise ValueError("Shadow Mode needs matching primary and standby COMPLETE resources")
    lan_addresses = _paired_lan_addresses(primary, left, right)
    return (
        _build_vyos_shadow(primary, left, lan_addresses, standby.peer_lan[1]),
        _build_vyos_shadow(standby, right, lan_addresses[::-1]),
    )


def build_vyos_shadow_primary_activation(primary, *, nodes, primary_lan_link_local):
    """Plan only the initial primary using both independently verified LAN mappings."""
    left, right = nodes
    if primary.priority != 255 or primary.peer_lan is not None:
        raise ValueError("Shadow Mode initial activation requires the initial primary election")
    if not isinstance(primary_lan_link_local, str) or "%" in primary_lan_link_local:
        raise ValueError("Shadow Mode initial activation requires an unscoped primary LAN link-local address")
    link_local = IPv6Address(primary_lan_link_local)
    if not link_local.is_link_local:
        raise ValueError("Shadow Mode initial activation requires a primary LAN link-local address")
    _verify_node_interconnect(right, primary.peer)
    _mapped_vip_addresses(primary.virtual_ips, right)
    lan_addresses = _paired_lan_addresses(primary, left, right)
    return _build_vyos_shadow(replace(primary, priority=120), left, lan_addresses, str(link_local))


def build_vyos_shadow_standby_candidate(election, *, nodes):
    """Compile the standby after the caller verifies the active primary and reciprocal COMPLETE."""
    primary, standby = nodes
    if (election.priority != 100 or election.peer_lan is None or election.peer_lan[0] != "br0"
            or not isinstance(election.peer_lan[1], str)):
        raise ValueError("Shadow Mode requires a verified standby election")
    peer_link = IPv6Address(election.peer_lan[1])
    if not peer_link.is_link_local or peer_link.scope_id is not None:
        raise ValueError("Shadow Mode standby requires an unscoped primary LAN link-local address")
    _verify_node_interconnect(primary, election.peer)
    primary_lan, standby_lan = _paired_lan_addresses(election, primary, standby)
    return _build_vyos_shadow(election, standby, (standby_lan, primary_lan))


def standby_resource_scope(election, nodes):
    """Map an authenticated standby election to the resources which must remain fenced."""
    return build_vyos_shadow_standby_candidate(election, nodes=nodes)._resource_scope()


def standby_election_commands(plan, observation):
    """Prepare a timed election write from a verified saved standby policy preimage."""
    if observation.phase != "saved_commit" or observation.role != "unknown" or observation.rollback_action != "reboot":
        raise ValueError("Shadow Mode standby requires a settled, fenced VyOS configuration before election staging")
    local = observation.state
    if local.running != local.saved:
        raise ValueError("Running and saved standby preimages disagree before election staging")
    scope = _verify_standby_election_addresses(plan, local)
    local._verify_fenced(scope)
    return plan.create_commands()


def verify_standby_election_candidate(plan, observation, *, preimage_sha256=None):
    """Verify the staged or saved stock election before the standby receipt is published."""
    if (observation.role != "fault" or observation.rollback_action != "reboot"
            or observation.phase not in ("staged_reboot", "completed", "saved_commit")):
        raise ValueError("The Shadow Mode standby election candidate must be fenced")
    local = observation.state
    scope = _verify_standby_election_addresses(plan, local)
    plan.verify_owned(local.read(local.running, _VRRP), local.read(local.running, _CONNTRACK))
    if observation.phase == "saved_commit" or (
        observation.phase == "completed" and preimage_sha256 is not None and observation.saved_sha256 != preimage_sha256
    ):
        plan.verify_owned(local.read(local.saved, _VRRP), local.read(local.saved, _CONNTRACK))
        scope.verify_kernel(local.kernel, expected=())
    else:
        scope.verify_empty(local.read(local.saved, _VRRP), local.read(local.saved, _CONNTRACK), local.kernel)


def verify_standby_backup(plan, observation):
    """Prove that the saved election is BACKUP and does not own any of the virtual IPs."""
    if observation.role != "backup" or observation.phase != "saved_commit":
        raise ValueError("Shadow Mode standby does not have a verified BACKUP election")
    local = observation.state
    scope = _verify_standby_election_addresses(plan, local)
    for config in (local.running, local.saved):
        plan.verify_owned(local.read(config, _VRRP), local.read(config, _CONNTRACK))
    scope.verify_kernel(local.kernel, expected=())


def _verify_standby_election_addresses(plan, local):
    if plan.group.get("priority") != "100" or plan.lan_source is None:
        raise ValueError("Shadow Mode election verification requires the mapped standby plan")
    scope = plan._resource_scope()
    lan_vip, = (vip for vip, interface in scope.vips if interface == scope.election)
    for config in (local.running, local.saved):
        _verify_standby_lan(local.read(config, _address_leaf(scope.election)[:-1]), scope.lan_source, lan_vip)
        sync = local.read(config, _address_leaf(scope.interconnect)[:-1])
        if _configured_address_order(sync) != (str(scope.local_sync),):
            raise ValueError("Shadow Mode standby interconnect differs from the saved local address")
        _verify_configured_vips(config, scope.vips, None)
    return scope


def _paired_lan_addresses(primary, left, right):
    lan_vip = dict(primary.virtual_ips).get("br0")
    lan_addresses = (IPv4Interface(left.lan_address), IPv4Interface(right.lan_address))
    if (lan_vip is None or len({address.ip for address in lan_addresses} | {lan_vip.ip}) != 3
            or any(address.network != lan_vip.network
                   or address.ip in (lan_vip.network.network_address, lan_vip.network.broadcast_address)
                   for address in lan_addresses)):
        raise ValueError("Shadow Mode needs two distinct LAN election addresses on the br0 VIP network")
    return lan_addresses


def _verify_node_interconnect(node, expected_source):
    validate_shadow_interface(node.interconnect)
    if node.local_address not in SHADOW_ADDRESSES or str(IPv4Interface(node.local_address).ip) != expected_source:
        raise ValueError("The verified Shadow Mode interconnect does not match the election source")


def _mapped_vip_addresses(virtual_ips, node):
    addresses = {}
    owners = set()
    for bridge, address in virtual_ips:
        owner = node.interfaces.get(bridge)
        if not isinstance(owner, str) or _IFACE.fullmatch(owner) is None or owner == node.interconnect or owner in owners:
            raise ValueError("A Shadow Mode virtual IP needs an independent mapped interface")
        addresses[str(address)] = {"interface": owner}
        owners.add(owner)
    return addresses


def _build_vyos_shadow(election, node, lan_addresses=None, primary_lan_link_local=None):
    _verify_node_interconnect(node, election.source)
    interconnect = node.interconnect
    addresses = _mapped_vip_addresses(election.virtual_ips, node)
    group = {"interface": interconnect, "vrid": "42", "priority": str(election.priority), "advertise-interval": "1",
             "hello-source-address": election.source, "peer-address": election.peer, "address": addresses}
    lan_source = None
    if lan_addresses is not None:
        lan_source, lan_peer = lan_addresses
        group.update({"interface": node.interfaces["br0"], "hello-source-address": str(lan_source.ip),
                      "peer-address": str(lan_peer.ip), "no-preempt": {}})
    return VyOSShadowElection(
        group=group,
        sync_group={"member": SHADOW_VRRP_GROUP, "health-check": {"script": _POLICY_GUARD, "interval": "1",
                                                                  "timeout": "1", "failure-count": "1"}},
        conntrack={"interface": {interconnect: {"peer": election.peer}}, "listen-address": election.source,
                   "failover-mechanism": {"vrrp": {"sync-group": SHADOW_SYNC_GROUP}}, "startup-resync": {},
                   "accept-protocol": "tcp"},
        lan_source=lan_source,
        primary_lan_link_local=primary_lan_link_local,
    )
