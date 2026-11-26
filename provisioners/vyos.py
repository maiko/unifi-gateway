"""Reconcile UniFi gateway settings with the explicitly managed VyOS configuration."""
from collections.abc import Callable
from contextlib import contextmanager
from dataclasses import asdict, dataclass, field, fields
import fcntl
import hashlib
from ipaddress import IPv4Address, IPv4Interface, IPv4Network, IPv6Interface, IPv6Network, ip_address
import json
import os
from pathlib import Path
import re
import stat
import time
from uuid import UUID

from backends.vyos import VyOSReadError, VyOSWriteError
from backends.vyos_failover import VyOSRoutingSSH, read_failover_fib
from collectors.vyos import interface_details, interface_ipv4_addresses, interface_ipv6_observations
from inspection.controller import InspectionControlError
from inspection.suricata import InspectionIntent
from inspection.unifi_broker import BrokerTrust, decode_broker_provisioning
from provisioners import JOURNAL_SCHEMA_VERSION
from provisioners.vyos_bgp import (
    BgpIntent, BgpProvisioningIntent, BgpScope, bgp_checkpoint, bgp_checkpoint_has_password, bgp_checkpoint_resources,
    plan_bgp_commands, read_bgp_configuration, redact_bgp_configuration, vyos_bgp_configuration,
)
from provisioners.vyos_shadow_handoff import SHADOW_HANDOFF, SHADOW_ROLLBACK, validate_shadow_handoff
from provisioners.vyos_shadow_standby import (
    STANDBY_ELECTION,
    STANDBY_POLICY,
    STANDBY_POLICY_ROLLBACK,
    validate_standby_election,
    validate_standby_policy,
    validate_standby_rollback,
)
from provisioners.uxg_enterprise_shadow import (
    SHADOW_ADDRESSES, interconnect_commands, read_interconnect, validate_shadow_interface, verify_interconnect,
    verify_no_vrrp_interconnect_conflict,
)
from provisioners.vyos_dhcp import DhcpIntent, DhcpScope, decode_dhcp_intent, plan_dhcp_commands
from provisioners.vyos_dns import DnsIntent, DnsScope, decode_dns_intent, outside_dns_records, plan_dns_commands
from provisioners.uxg_intent import FirewallIntent, decode_firewall_intent
from provisioners.vyos_ipsec import IpsecIntent, IpsecScope, decode_ipsec_intent, plan_ipsec_commands, redact_ipsec_config
from provisioners.uxg_ipsec_policy import scrub_ipsec_policy
from provisioners.vyos_mdns import (
    MDNS_CONTAINER_PATH, MdnsContainerImage, MdnsIntent, MdnsScope, decode_mdns_intent,
    normalize_mdns_service_version, plan_mdns_commands,
    scrub_mdns_policy, verify_mdns_state,
)
from provisioners.vyos_nat import NatIntent, NatScope, decode_nat_intent, outside_nat_rules, plan_nat_commands
from provisioners.uxg_openvpn import OpenVpnClientIntent
from provisioners.vyos_ospf import (
    OspfIntent, OspfScope, decode_ospf_intent, ospf_config_has_authentication, plan_ospf_commands,
    redact_ospf_config, scrub_ospf_policy, verify_ospf_router_id_edit, verify_ospf_runtime, verify_ospf_state,
)
from provisioners.uxg_pbr import POLICY_ROUTE_DESTINATIONS, PolicyRouteIntent
from provisioners.vyos_port_forward import (
    PortForwardIntent, PortForwardScope, decode_port_forward_intent, plan_port_forward_commands, port_forward_remainder,
)
from provisioners.uxg_qos import QOS_SOURCE, QosIntent
from provisioners.vyos_routes import (
    StaticRoute, StaticRouteIntent, StaticRouteScope, decode_route_intent, extends_static_route_scope,
    plan_route_commands, static_route_identities, validate_static_route_identities, verify_route_forwarding,
)
from provisioners.uxg_schema import selected_schema
from provisioners.vyos_vlan import VlanIntent, VlanScope, decode_vlan_intent, plan_vlan_commands, scrub_vlan_policy, verify_vlan_state
from provisioners.uxg_wan_failover import WanFailoverError, WanFailoverIntent
from provisioners.vyos_wireguard import (
    WireGuardIntent, WireGuardScope, decode_wireguard_intent, plan_wireguard_commands, redact_wireguard_interface,
)
from provisioners.uxg_wireguard_policy import scrub_wireguard_policy
from provisioners.vyos_firewall_commands import firewall_rule_changes
from provisioners.vyos_ipsec_guards import (
    IPSEC_GUARD_PATHS, IPSEC_GUARD_SLOTS, owned_ipsec_guards, plan_ipsec_guards, verify_ipsec_guard_order,
)
from provisioners.vyos_openvpn import OpenVpnScope, plan_openvpn, read_openvpn_state
from provisioners.vyos_openvpn_guards import (
    OPENVPN_GUARD_PATHS, OPENVPN_GUARD_SLOTS, OpenVpnGuardScope, verify_openvpn_guard_order, verify_openvpn_guards,
)
from provisioners.vyos_pbr import (
    plan_policy_route, plan_policy_route_guard, policy_route_guard_configuration,
    prepare_policy_table, read_policy_route_guard,
    read_policy_route_state, read_policy_route_fib, verify_policy_route_fib, verify_policy_route_guard,
)
from provisioners.vyos_port_forward_guards import (
    PORT_FORWARD_GUARD_PATHS, owned_port_forward_guards, plan_port_forward_guards, port_forward_guard_slots,
)
from provisioners.vyos_qos import (
    QOS_LAN_INTERFACE, QOS_MARKER_SLOTS, QOS_WAN_INTERFACE, plan_qos, read_qos_state, read_qos_kernel,
    limit_from_checkpoint, qos_checkpoint, verify_qos_kernel,
)
from provisioners.vyos_wan_failover import plan_wan_default, read_wan_state, verify_wan_fib
from provisioners.vyos_wireguard_guards import GUARD_PATHS, WireGuardGuardScope, owned_guard_rules, plan_wireguard_guards
from tools import atomic_write


_RULE_PATH = ["firewall", "ipv4", "forward", "filter", "rule"]
_IPV6_RULE_PATH = ["firewall", "ipv6", "forward", "filter", "rule"]
_POLICY_RULE_PATHS = {"rules": _RULE_PATH, "rules_ipv6": _IPV6_RULE_PATH}
_LAN_CHAINS = {"lan_chain": "rules", "lan_chain_ipv6": "rules_ipv6"}
_DHCP_PATH = ["service", "dhcp-server", "shared-network-name"]
_OSPF_PATH = ["protocols", "ospf"]
_DNS_PATH = ["service", "dns", "forwarding"]
_MDNS_PATH = ["service", "mdns"]
_NAT_PATH = ["nat", "source", "rule"]
_DNAT_PATH = ["nat", "destination", "rule"]
_WIREGUARD_PATH = ["interfaces", "wireguard"]
_IPSEC_PATH = ["vpn", "ipsec"]
_ETHERNET_PATH = ["interfaces", "ethernet"]
_RULE_LIMIT = 32
_CONFIRM_MINUTES = 2
_SHADOW_ADDRESS_UNSPECIFIED = object()
_EMPTY_CONFIG = {
    "rules": {}, "rules_ipv6": {}, "lan_chain": None, "lan_chain_ipv6": None, "dhcp": None, "routes": {}, "dns": None,
    "nat": {}, "wireguard": None,
    "port_forward": None, "vlan": None, "mdns": None, "ospf": None, "ipsec": None, "openvpn": None, "wan_default": None,
    "policy_route": None, "qos": None, "inspection_queue": None, "shadow_interconnect": None, "bgp": {},
}


def _routing_reader_scope(reader):
    if isinstance(reader, VyOSRoutingSSH):
        return {"ssh_observer": reader.endpoint}
    if isinstance(reader, str) and os.path.isabs(reader) and "\x00" not in reader:
        return {"fib_command": reader}
    raise ValueError("VyOS routing requires a pinned SSH observer or an absolute FIB reader path")


@dataclass(frozen=True)
class ApplyResult:
    verified_revision: str | None
    changed: bool = False
    error: str | None = None


@dataclass(frozen=True)
class OpenVpnDesired:
    revision: str
    client: OpenVpnClientIntent | None


@dataclass(frozen=True)
class ShadowStandbyPolicyPlan:
    revision: str
    boot_id: str
    configuration_sha256: str
    commands: tuple[dict, ...] = field(repr=False)
    desired: dict = field(repr=False)


class VyOSReconciler:
    def __init__(
        self, backend, *, interfaces, state_path, rule_base, dhcp_scope=None,
        route_scope=None, dns_scope=None, nat_scope=None, wireguard_scope=None, wireguard_guard=None,
        port_forward_scope=None, port_forward_guard_base=None, vlan_scope=None, mdns_scope=None, ospf_scope=None,
        ipsec_scope=None, ipsec_guard_base=None,
        openvpn_scope=None, openvpn_guard=None, wan_fib_command=None, policy_route_fib_command=None,
        qos_kernel_command=None, ipv6_interfaces=None, stock_inspection_policy=None, inspection_controller=None,
        commit_proof=None, mdns_container=None, shadow_interconnect=None, bgp_scope=None,
    ):
        if type(rule_base) is not int or not 1 <= rule_base <= 1_000_000 - _RULE_LIMIT:
            raise ValueError("Invalid reserved VyOS firewall rule range")
        if bgp_scope is not None and (not isinstance(bgp_scope, BgpScope) or commit_proof is None):
            raise ValueError("Managed BGP requires an approved peer and saved-configuration proof")
        if shadow_interconnect is not None:
            validate_shadow_interface(shadow_interconnect)
            if commit_proof is None or shadow_interconnect in set(interfaces.values()) | set((ipv6_interfaces or {}).values()):
                raise ValueError("Shadow Mode needs an independent interconnect and saved-configuration proof")
        if not interfaces or len(set(interfaces.values())) != len(interfaces):
            raise ValueError("A distinct VyOS interface is required for each managed LAN prefix")
        if (stock_inspection_policy is None) != (inspection_controller is None) or (
            stock_inspection_policy is not None and stock_inspection_policy.networks != inspection_controller.networks
        ):
            raise ValueError("Stock inspection requires the same approved networks for queue and engine")
        if any(not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,15}", name)
               for name in interfaces.values()):
            raise ValueError("Invalid VyOS interface in the managed LAN map")
        if dhcp_scope is not None and (
            not isinstance(dhcp_scope, DhcpScope) or dhcp_scope.interface not in interfaces.values()
            or not re.fullmatch(r"eth[0-9]+\.[0-9]+", dhcp_scope.interface)
        ):
            raise ValueError("Managed DHCP requires a mapped VyOS ethernet VLAN interface")
        if route_scope is not None and not isinstance(route_scope, StaticRouteScope):
            raise ValueError("Managed static routes require an explicit VyOS scope")
        if dns_scope is not None and not isinstance(dns_scope, DnsScope):
            raise ValueError("Managed DNS requires an explicit local zone")
        if nat_scope is not None and not isinstance(nat_scope, NatScope):
            raise ValueError("Managed source NAT requires an explicit flow scope")
        if (
            (wireguard_scope is None) != (wireguard_guard is None)
            or wireguard_scope is not None and (
                not isinstance(wireguard_scope, WireGuardScope) or not isinstance(wireguard_guard, WireGuardGuardScope)
                or wireguard_guard.rule_base + 3 >= rule_base
            )
        ):
            raise ValueError("Managed WireGuard requires reserved ingress and forwarding guards")
        if (port_forward_scope is None) != (port_forward_guard_base is None):
            raise ValueError("Managed port forwarding requires reserved ingress and forwarding guards")
        if port_forward_scope is not None:
            if (not isinstance(port_forward_scope, PortForwardScope)
                    or interfaces.get(IPv4Interface(port_forward_scope.lan_cidr).network) != port_forward_scope.lan_interface):
                raise ValueError("Managed port forwarding requires an explicitly mapped target LAN")
            guard_count = port_forward_guard_slots(port_forward_scope, port_forward_guard_base)
            guard_end = port_forward_guard_base + guard_count
            if guard_end > rule_base or (
                wireguard_guard is not None and port_forward_guard_base <= wireguard_guard.rule_base + 3
                and wireguard_guard.rule_base < guard_end
            ):
                raise ValueError("Port forwarding guard slots overlap another managed firewall range")
        if vlan_scope is not None and (
            not isinstance(vlan_scope, VlanScope) or vlan_scope.interface in interfaces.values()
            or any(IPv4Interface(vlan_scope.address).network.overlaps(prefix) for prefix in interfaces)
        ):
            raise ValueError("Managed VLAN must have a separate interface and prefix from the pinned LAN policy")
        if mdns_scope is not None and (
            not isinstance(mdns_scope, MdnsScope) or any(
                interfaces.get(IPv4Interface(mdns_scope.addresses[bridge]).network) != interface
                for bridge, interface in mdns_scope.interfaces.items()
            )
        ):
            raise ValueError("Managed mDNS needs two explicitly mapped VyOS LAN prefixes")
        if mdns_container is not None and (mdns_scope is None or not isinstance(mdns_container, MdnsContainerImage)):
            raise ValueError("Managed mDNS container needs a pinned image and LAN scope")
        if ospf_scope is not None and (
            not isinstance(ospf_scope, OspfScope)
            or interfaces.get(IPv4Interface(ospf_scope.interface_address).network) != ospf_scope.vyos_interface
        ):
            raise ValueError("Managed OSPF requires one explicitly mapped VyOS transit VLAN")
        if (ipsec_scope is None) != (ipsec_guard_base is None):
            raise ValueError("Managed IPsec requires reserved ingress and forwarding guards")
        ipsec_route_scope = None
        if ipsec_scope is not None:
            if (not isinstance(ipsec_scope, IpsecScope)
                    or interfaces.get(IPv4Interface(ipsec_scope.lan_cidr).network) != ipsec_scope.lan_interface
                    or type(ipsec_guard_base) is not int or not 1 <= ipsec_guard_base <= rule_base - IPSEC_GUARD_SLOTS):
                raise ValueError("Managed IPsec requires a mapped LAN and a reserved firewall range")
            ipsec_slots = set(range(ipsec_guard_base, ipsec_guard_base + IPSEC_GUARD_SLOTS))
            if (
                wireguard_guard is not None
                and ipsec_slots.intersection(range(wireguard_guard.rule_base, wireguard_guard.rule_base + 4))
                or port_forward_scope is not None
                and ipsec_slots.intersection(range(port_forward_guard_base, guard_end))
            ):
                raise ValueError("IPsec guard slots overlap another managed firewall range")
            if route_scope is not None and any(
                IPv4Network(ipsec_scope.remote_selector).overlaps(IPv4Network(destination))
                for destination in route_scope.destinations
            ):
                raise ValueError("IPsec remote selector overlaps the managed static route scope")
            ipsec_route_scope = StaticRouteScope((ipsec_scope.remote_selector,),
                                                 {ipsec_scope.remote_peer: ipsec_scope.wan_interface})
        if (openvpn_scope is None) != (openvpn_guard is None):
            raise ValueError("Managed OpenVPN requires reserved ingress, egress, and forwarding guards")
        if openvpn_scope is not None:
            if not isinstance(openvpn_scope, OpenVpnScope) or not isinstance(openvpn_guard, OpenVpnGuardScope):
                raise ValueError("Managed OpenVPN requires a pinned router and guard scope")
            approved_guard = OpenVpnGuardScope(
                openvpn_scope.interface, openvpn_scope.tunnel_cidr, openvpn_scope.tunnel_peer, openvpn_guard.rule_base,
                openvpn_scope.wan_interface, openvpn_scope.local_address, openvpn_scope.remote_host, openvpn_scope.remote_ports,
            )
            guard_end_openvpn = openvpn_guard.rule_base + OPENVPN_GUARD_SLOTS
            if openvpn_guard != approved_guard or guard_end_openvpn > rule_base:
                raise ValueError("OpenVPN guards differ from the approved router scope or firewall range")
            slots = set(range(openvpn_guard.rule_base, guard_end_openvpn))
            if (wireguard_guard is not None and slots.intersection(range(wireguard_guard.rule_base, wireguard_guard.rule_base + 4))
                    or port_forward_scope is not None and slots.intersection(range(port_forward_guard_base, guard_end))
                    or ipsec_scope is not None and slots.intersection(ipsec_slots)):
                raise ValueError("OpenVPN guard slots overlap another managed firewall range")
        self.backend = backend
        self.commit_proof = commit_proof
        self.bgp_scope = bgp_scope
        self.shadow_interconnect = shadow_interconnect
        self.interfaces = dict(interfaces)
        self.ipv6_interfaces = {} if ipv6_interfaces is None else dict(ipv6_interfaces)
        if self.ipv6_interfaces and (
            len(self.ipv6_interfaces) < 2 or not set(self.ipv6_interfaces.values()).issubset(interfaces.values())
            or len(set(self.ipv6_interfaces.values())) != len(self.ipv6_interfaces)
            or any(not isinstance(prefix, IPv6Network) or not prefix.prefixlen
                   or prefix.is_link_local or prefix.is_multicast or prefix.is_loopback
                   for prefix in self.ipv6_interfaces)
        ):
            raise ValueError("Managed IPv6 firewall rules require distinct IPv6 prefixes on mapped VyOS LANs")
        self.state_path = Path(state_path)
        self.slots = tuple(str(rule_base + index) for index in range(_RULE_LIMIT))
        self.lan_chain_name = f"UNIFI_LAN_{rule_base}"
        self.dhcp_scope = dhcp_scope
        self.route_scope = route_scope
        self.dns_scope = dns_scope
        self.nat_scope = nat_scope
        self.wireguard_scope = wireguard_scope
        self.wireguard_guard = wireguard_guard
        self.port_forward_scope = port_forward_scope
        self.port_forward_guard_base = port_forward_guard_base
        self.vlan_scope = vlan_scope
        self.mdns_scope = mdns_scope
        self.mdns_container = mdns_container
        self.ospf_scope = ospf_scope
        self.ipsec_scope = ipsec_scope
        self.ipsec_guard_base = ipsec_guard_base
        self.ipsec_route_scope = ipsec_route_scope
        self.openvpn_scope = openvpn_scope
        self.openvpn_guard = openvpn_guard
        if wan_fib_command is not None and (
            interfaces != {IPv4Network(f"192.168.{n}.0/24"): f"eth3.{n}" for n in (110, 120)}
            or nat_scope is not None and set(nat_scope.slots) & {str(slot) for slot in range(80180, 80184)}
        ):
            raise ValueError("WAN failover requires 192.168.110.0/24 on eth3.110, 192.168.120.0/24 on eth3.120 and NAT slots 80180–80183")
        self.wan_fib_command = wan_fib_command
        if policy_route_fib_command is not None and (wan_fib_command is None or rule_base < 3):
            raise ValueError("Policy routing requires WAN failover and two reserved forward rule slots")
        self.policy_route_fib_command = policy_route_fib_command
        if qos_kernel_command is not None and (
            not isinstance(qos_kernel_command, str) or not os.path.isabs(qos_kernel_command) or "\x00" in qos_kernel_command
            or interfaces.get(IPv4Network(QOS_SOURCE)) != QOS_LAN_INTERFACE
            or any(base is not None and base <= int(QOS_MARKER_SLOTS[-1]) for base in (
                rule_base, port_forward_guard_base, ipsec_guard_base, getattr(wireguard_guard, "rule_base", None),
                getattr(openvpn_guard, "rule_base", None),
            ))
        ):
            raise ValueError("QoS requires 192.168.110.0/24 on eth3.110, free packet-marker slots and an absolute kernel reader path")
        self.qos_kernel_command = qos_kernel_command
        self.stock_inspection_policy = stock_inspection_policy
        self.inspection_controller = inspection_controller
        self.scope = {"rule_base": rule_base, "interfaces": {str(k): v for k, v in interfaces.items()}}
        if bgp_scope is not None:
            peers = sorted(map(str, bgp_scope.peers))
            self.scope["bgp"] = {**({"peer": peers[0]} if len(peers) == 1 else {"peers": peers}),
                                 "imports": sorted(map(str, bgp_scope.imports)), "exports": sorted(map(str, bgp_scope.exports))}
            if bgp_scope.dual_stack_peers:
                self.scope["bgp"]["dual_stack_peers"] = sorted(map(str, bgp_scope.dual_stack_peers))
        if shadow_interconnect is not None:
            self.scope["shadow_interconnect"] = {"interface": shadow_interconnect}
        if self.ipv6_interfaces:
            self.scope["rules_ipv6"] = {str(prefix): interface for prefix, interface in self.ipv6_interfaces.items()}
        if dhcp_scope is not None:
            self.scope["dhcp"] = asdict(dhcp_scope)
        if route_scope is not None:
            self.scope["routes"] = {"destinations": list(route_scope.destinations), "next_hops": route_scope.next_hops}
            if route_scope.interface_ids:
                self.scope["routes"]["interface_ids"] = route_scope.interface_ids
        if dns_scope is not None:
            self.scope["dns"] = asdict(dns_scope)
        if nat_scope is not None:
            self.scope["nat"] = asdict(nat_scope)
            for key in ("ports", "translation_addresses"):
                self.scope["nat"][key] = list(self.scope["nat"][key])
        if wireguard_scope is not None:
            vpn_scope = asdict(wireguard_scope)
            vpn_scope["ports"] = list(vpn_scope["ports"])
            self.scope["wireguard"] = {"interface": vpn_scope, "guard": asdict(wireguard_guard)}
        if port_forward_scope is not None:
            self.scope["port_forward"] = {**asdict(port_forward_scope), "guard_rule_base": port_forward_guard_base,
                                          "ports": [list(pair) for pair in port_forward_scope.ports]}
        if vlan_scope is not None:
            self.scope["vlan"] = asdict(vlan_scope)
        if mdns_scope is not None:
            self.scope["mdns"] = asdict(mdns_scope)
            if mdns_container is not None:
                self.scope["mdns"]["container"] = asdict(mdns_container)
        if ospf_scope is not None:
            self.scope["ospf"] = asdict(ospf_scope)
        if ipsec_scope is not None:
            self.scope["ipsec"] = {**asdict(ipsec_scope), "guard_rule_base": ipsec_guard_base}
        if openvpn_scope is not None:
            self.scope["openvpn"] = {**asdict(openvpn_scope), "remote_ports": list(openvpn_scope.remote_ports),
                                     "guard_rule_base": openvpn_guard.rule_base}
        if wan_fib_command is not None:
            self.scope["wan_default"] = _routing_reader_scope(wan_fib_command)
        if policy_route_fib_command is not None:
            self.scope["policy_route"] = _routing_reader_scope(policy_route_fib_command)
        if qos_kernel_command is not None:
            self.scope["qos"] = {"kernel_command": qos_kernel_command}
        if stock_inspection_policy is not None:
            self.scope["inspection_queue"] = {
                "topology": stock_inspection_policy.scope,
                "vendor_controls_sha256": inspection_controller.vendor_controls_sha256,
            }

    @classmethod
    def from_config(
        cls, collector, settings, dhcp_settings=None, route_settings=None,
        dns_settings=None, nat_settings=None, wireguard_settings=None, port_forward_settings=None, vlan_settings=None,
        mdns_settings=None, ospf_settings=None, ipsec_settings=None, openvpn_settings=None, wan_settings=None,
        policy_route_settings=None, qos_settings=None, stock_inspection_policy=None, inspection_controller=None,
        commit_proof=None, routing_ssh=None, shadow_interconnect=None, bgp_scope=None,
    ):
        interfaces = {IPv4Network(prefix): interface for prefix, interface in json.loads(settings["interfaces"]).items()}
        ipv6_interfaces = {IPv6Network(prefix): interface
                           for prefix, interface in json.loads(settings.get("ipv6_interfaces", "{}")).items()}
        mapped_lan = {port["realif"] for port in collector.ports if port["type"] in ("lan", "lan2")}
        if not set(interfaces.values()).issubset(mapped_lan):
            raise ValueError("Managed firewall interfaces must be explicitly mapped VyOS LAN ports")
        if stock_inspection_policy is not None:
            scope = stock_inspection_policy.engine_scope
            for endpoint in (scope["initiator"], scope["responder"]):
                host = IPv4Address(endpoint["host"])
                if not any(host in prefix and interface == endpoint["interface"] for prefix, interface in interfaces.items()):
                    raise ValueError("Stock inspection queue endpoints must use their mapped VyOS LANs")
        mapped_wan = {port["ifname"]: port["realif"] for port in collector.ports if port["type"] in ("wan", "wan2")}
        dhcp_scope = None
        if dhcp_settings is not None and dhcp_settings.getboolean("enabled", fallback=False):
            dhcp_scope = DhcpScope(dhcp_settings["bridge"], dhcp_settings["interface"],
                                   dhcp_settings["shared_network"], dhcp_settings.getint("subnet_id"))
        route_scope = None
        if route_settings is not None and route_settings.getboolean("enabled", fallback=False):
            route_scope = StaticRouteScope(
                json.loads(route_settings["destinations"]), json.loads(route_settings["next_hops"]),
                json.loads(route_settings.get("interface_ids", "{}")),
            )
            mapped_ports = {port["realif"] for port in collector.ports}
            route_ports = set(route_scope.next_hops.values()) | set(route_scope.interface_ids.values())
            if not route_ports.issubset(mapped_ports):
                raise ValueError("Static route egress must use explicitly mapped VyOS ports")
        dns_scope = None
        if dns_settings is not None and dns_settings.getboolean("enabled", fallback=False):
            dns_scope = DnsScope(dns_settings["zone"])
        nat_scope = None
        if nat_settings is not None and nat_settings.getboolean("enabled", fallback=False):
            nat_scope = NatScope(
                source=nat_settings["source"], destination=nat_settings["destination"],
                bridge=nat_settings["bridge"], interface=nat_settings["interface"],
                rule_base=nat_settings.getint("rule_base"), ports=json.loads(nat_settings["ports"]),
                translation_addresses=json.loads(nat_settings.get("translation_addresses", "[]")),
            )
            if IPv4Network(nat_scope.source) not in interfaces or nat_scope.interface not in mapped_lan:
                raise ValueError("Source NAT requires a managed source prefix and a mapped egress")
        wireguard_scope = wireguard_guard = None
        if wireguard_settings is not None and wireguard_settings.getboolean("enabled", fallback=False):
            options = wireguard_settings
            wireguard_scope = WireGuardScope(
                options["wan_id"], options["wan_interface"], options["wan_cidr"], options["interface"],
                json.loads(options["ports"]), options["tunnel_cidr"], options["peer_cidr"], options.get("server_id", "1"),
            )
            wireguard_guard = WireGuardGuardScope(
                options["wan_peer"], options["target"], options["target_interface"],
                options.getint("target_port"), options.getint("guard_rule_base"),
            )
            if mapped_wan.get(wireguard_scope.wan_id) != wireguard_scope.wan_interface or not any(
                name == wireguard_guard.target_interface and IPv4Address(wireguard_guard.target) in prefix
                for prefix, name in interfaces.items()
            ):
                raise ValueError("WireGuard requires mapped WAN and LAN interfaces")
        port_forward_scope = port_forward_guard_base = None
        if port_forward_settings is not None and port_forward_settings.getboolean("enabled", fallback=False):
            options = port_forward_settings
            port_forward_scope = PortForwardScope(
                options["wan_id"], options["wan_interface"], options["wan_cidr"], options["peer"], options["lan_bridge"],
                options["lan_interface"], options["lan_cidr"], options["target"], options.getint("rule_base"),
                json.loads(options["ports"]),
            )
            port_forward_guard_base = options.getint("guard_rule_base")
            if mapped_wan.get(port_forward_scope.wan_id) != port_forward_scope.wan_interface:
                raise ValueError("Port forwarding requires an explicitly mapped WAN interface")
        vlan_scope = None
        if vlan_settings is not None and vlan_settings.getboolean("enabled", fallback=False):
            vlan_scope = VlanScope(vlan_settings["parent"], vlan_settings.getint("vlan_id"), vlan_settings["address"])
            if not any(port["ifname"] == vlan_scope.bridge and port["realif"] == vlan_scope.interface
                       and port["type"] in ("lan", "lan2") and "port_idx" not in port for port in collector.ports):
                raise ValueError("Managed VLAN needs an explicitly mapped logical LAN interface")
        mdns_scope = mdns_container = None
        if mdns_settings is not None and mdns_settings.getboolean("enabled", fallback=False):
            mdns_scope = MdnsScope(json.loads(mdns_settings["interfaces"]), json.loads(mdns_settings["addresses"]))
            engine = mdns_settings.get("engine", "stock")
            if engine == "container":
                mdns_container = MdnsContainerImage(mdns_settings["container_image"], mdns_settings["container_image_id"])
            elif engine != "stock":
                raise ValueError("Unsupported VyOS mDNS engine")
        ospf_scope = None
        if ospf_settings is not None and ospf_settings.getboolean("enabled", fallback=False):
            ospf_scope = OspfScope(
                router_id=ospf_settings.get("router_id"), controller_interface=ospf_settings["controller_interface"],
                vyos_interface=ospf_settings["vyos_interface"], interface_address=ospf_settings["interface_address"],
            )
        ipsec_scope = ipsec_guard_base = None
        if ipsec_settings is not None and ipsec_settings.getboolean("enabled", fallback=False):
            ipsec_scope = IpsecScope(**{field.name: ipsec_settings[field.name] for field in fields(IpsecScope)})
            ipsec_guard_base = ipsec_settings.getint("guard_rule_base")
            if (mapped_wan.get(ipsec_scope.wan_id) != ipsec_scope.wan_interface
                    or ipsec_scope.lan_interface not in mapped_lan):
                raise ValueError("IPsec requires explicitly mapped WAN and LAN interfaces")
        openvpn_scope = openvpn_guard = None
        if openvpn_settings is not None and openvpn_settings.getboolean("enabled", fallback=False):
            openvpn_scope = OpenVpnScope(
                server_name=openvpn_settings.get("server_name"),
                ca_name=openvpn_settings.get("ca_name", "UNIFI-OPENVPN-CA"),
                certificate_name=openvpn_settings.get("certificate_name", "UNIFI-OPENVPN-CLIENT"),
            )
            if mapped_wan.get("eth0") != openvpn_scope.wan_interface:
                raise ValueError("OpenVPN requires WAN1 mapped to eth3.210")
            openvpn_guard = OpenVpnGuardScope(
                openvpn_scope.interface, openvpn_scope.tunnel_cidr, openvpn_scope.tunnel_peer,
                openvpn_settings.getint("guard_rule_base"), openvpn_scope.wan_interface, openvpn_scope.local_address,
                openvpn_scope.remote_host, openvpn_scope.remote_ports,
            )
        wan_fib_command = None
        if wan_settings is not None and wan_settings.getboolean("enabled", fallback=False):
            if mapped_wan != {"eth0": "eth3.210", "eth2": "eth3.220"}:
                raise ValueError("WAN failover requires WAN1 on eth3.210 and WAN2 on eth3.220")
            wan_fib_command = wan_settings.get("fib_command", routing_ssh)
            if wan_fib_command is None:
                raise ValueError("WAN failover needs a routing SSH observer or a FIB reader command")
        policy_route_fib_command = None
        if policy_route_settings is not None and policy_route_settings.getboolean("enabled", fallback=False):
            policy_route_fib_command = policy_route_settings.get("fib_command", routing_ssh)
            if policy_route_fib_command is None:
                raise ValueError("Policy routing needs a routing SSH observer or a FIB reader command")
        qos_kernel_command = None
        if qos_settings is not None and qos_settings.getboolean("enabled", fallback=False):
            if mapped_wan.get("eth0") != QOS_WAN_INTERFACE:
                raise ValueError("QoS needs the explicitly mapped VyOS WAN 210 uplink")
            qos_kernel_command = qos_settings["kernel_command"]
        return cls(collector.backend, interfaces=interfaces, state_path=settings["state_path"],
                   rule_base=settings.getint("rule_base"), dhcp_scope=dhcp_scope, route_scope=route_scope,
                   dns_scope=dns_scope, nat_scope=nat_scope, wireguard_scope=wireguard_scope,
                   wireguard_guard=wireguard_guard, port_forward_scope=port_forward_scope,
                   port_forward_guard_base=port_forward_guard_base, vlan_scope=vlan_scope, mdns_scope=mdns_scope,
                   mdns_container=mdns_container,
                   ospf_scope=ospf_scope, ipsec_scope=ipsec_scope, ipsec_guard_base=ipsec_guard_base,
                   openvpn_scope=openvpn_scope, openvpn_guard=openvpn_guard, wan_fib_command=wan_fib_command,
                   policy_route_fib_command=policy_route_fib_command, qos_kernel_command=qos_kernel_command,
                   ipv6_interfaces=ipv6_interfaces, stock_inspection_policy=stock_inspection_policy,
                   inspection_controller=inspection_controller, commit_proof=commit_proof,
                   shadow_interconnect=shadow_interconnect, bgp_scope=bgp_scope)

    def reconcile(
        self, intent: FirewallIntent, *, dhcp_intent: DhcpIntent | None = None,
        route_intent: StaticRouteIntent | None = None, dns_intent: DnsIntent | None = None,
        nat_intent: NatIntent | None = None, wireguard_intent: WireGuardIntent | None = None,
        port_forward_intent: PortForwardIntent | None = None,
        vlan_intent: VlanIntent | None = None,
        mdns_intent: MdnsIntent | None = None,
        ospf_intent: OspfIntent | None = None,
        ipsec_intent: IpsecIntent | None = None,
        openvpn_intent: OpenVpnDesired | None = None,
        wan_intent: WanFailoverIntent | None = None,
        policy_route_intent: PolicyRouteIntent | None = None,
        qos_intent: QosIntent | None = None,
        inspection_intent: InspectionIntent | None = None,
        bgp_intent: BgpProvisioningIntent | None = None,
        shadow_interconnect_address=_SHADOW_ADDRESS_UNSPECIFIED,
        verify_unchanged: Callable[[], None] | None = None,
    ) -> ApplyResult:
        revision = None
        try:
            with self.locked_state() as state:
                revision = state["verified_revision"]
                if SHADOW_HANDOFF in state:
                    raise ValueError("Shadow Mode handoff recovery is pending")
                if state.get("restart") is not None:
                    raise ValueError("VyOS restart recovery is pending")
                if shadow_interconnect_address is _SHADOW_ADDRESS_UNSPECIFIED:
                    if self.shadow_interconnect is not None:
                        raise ValueError("A complete Shadow Mode interconnect intent is required")
                    shadow_interconnect_address = None
                return self._reconcile_locked(
                    intent, dhcp_intent, route_intent, dns_intent, nat_intent, wireguard_intent,
                    port_forward_intent, vlan_intent, mdns_intent, ospf_intent, ipsec_intent, openvpn_intent, wan_intent,
                    policy_route_intent, qos_intent, state,
                    verify_unchanged=verify_unchanged, inspection_intent=inspection_intent,
                    shadow_interconnect_address=shadow_interconnect_address, bgp_intent=bgp_intent,
                )
        except (OSError, ValueError, KeyError, TypeError, VyOSReadError, VyOSWriteError) as error:
            return ApplyResult(revision, error=str(error))

    @contextmanager
    def locked_state(self):
        fd = os.open(self.state_path.with_suffix(".lock"), os.O_CREAT | os.O_RDWR, 0o600)
        with os.fdopen(fd, "r+") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            yield self._load_state()

    def plan_shadow_standby_policy(self, intent, state, **intents):
        """Compile from saved stock state while the Shadow coordinator holds both locks."""
        reservation = state.get(SHADOW_HANDOFF)
        validate_shadow_handoff(reservation)
        if (reservation["phase"] != "standby" or state.get("scope") != self.scope or state.get("pending") is not None
                or {"restart", "policy_table_setup", "policy_route_guard_setup"} & state.keys()
                or state["verified_shadow_interconnect"] != SHADOW_ADDRESSES[1] or self.commit_proof is None):
            raise ValueError("Shadow Mode policy planning requires a reserved standby with verified interconnect")
        boot_id, saved = self.commit_proof(phase="saved_commit")
        if str(UUID(boot_id)) != boot_id or not isinstance(saved, str) or re.fullmatch("[0-9a-f]{64}", saved) is None:
            raise ValueError("Shadow Mode standby returned invalid saved configuration proof")
        options = {
            f"{name}_intent": None for name in (
                "dhcp", "route", "dns", "nat", "wireguard", "port_forward", "vlan", "mdns", "ospf", "ipsec",
                "openvpn", "wan", "policy_route", "qos", "inspection", "bgp",
            )
        }
        if intents.keys() - options.keys():
            raise ValueError("Unsupported Shadow Mode standby policy planner options")
        result = self._reconcile_locked(intent, **(options | intents), state=state,
                                        shadow_interconnect_address=SHADOW_ADDRESSES[1], plan_only=True)
        if isinstance(result, ApplyResult):
            raise ValueError(result.error)
        if self.commit_proof(phase="saved_commit") != (boot_id, saved):
            raise ValueError("Shadow Mode standby configuration changed during policy planning")
        commands, desired = result
        return ShadowStandbyPolicyPlan(intent.revision, boot_id, saved, tuple(commands), desired)

    def _load_state(self):
        try:
            state = json.loads(self.state_path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return {"schema_version": JOURNAL_SCHEMA_VERSION, "scope": self.scope, "verified_revision": None, "previous_revisions": [], "pending": None,
                    **{f"verified_{feature}": value for feature, value in _EMPTY_CONFIG.items()}}
        if (not isinstance(state, dict) or type(state.get("schema_version")) is not int
                or state["schema_version"] != JOURNAL_SCHEMA_VERSION):
            raise ValueError("Unsupported VyOS provisioning journal schema")
        required = {"verified_revision", "previous_revisions", "pending", "scope"}
        if not required.issubset(state) or any(f"verified_{feature}" not in state for feature in _EMPTY_CONFIG):
            raise ValueError("Incomplete VyOS provisioning journal")
        if SHADOW_ROLLBACK in state and (
            not isinstance(state[SHADOW_ROLLBACK], str) or re.fullmatch(r"[0-9a-f]{64}", state[SHADOW_ROLLBACK]) is None
        ):
            raise ValueError("Invalid saved Shadow Mode rollback revision")
        if SHADOW_HANDOFF in state:
            validate_shadow_handoff(state[SHADOW_HANDOFF])
            if (state.get("scope") != self.scope or state.get("pending") is not None
                    or {"restart", "policy_table_setup", "policy_route_guard_setup"} & state.keys()):
                raise ValueError("Shadow Mode handoff conflicts with VyOS provisioning state")
        if STANDBY_POLICY in state:
            validate_standby_policy(state[STANDBY_POLICY], state.get(SHADOW_HANDOFF), state.get("verified_revision"))
        if STANDBY_ELECTION in state:
            validate_standby_election(state[STANDBY_ELECTION], state.get(STANDBY_POLICY))
        if STANDBY_POLICY_ROLLBACK in state:
            validate_standby_rollback(state[STANDBY_POLICY_ROLLBACK])
        watermark = state.get("restart_watermark")
        if "restart_watermark" in state and (type(watermark) is not int or not 10**12 <= watermark < 10**13):
            raise ValueError("Invalid saved VyOS restart timestamp")
        if "restart" in state:
            restart = state["restart"]
            try:
                if (
                    not isinstance(restart, dict) or restart.keys() != {"boot_id", "configuration_sha256"}
                    or type(restart["boot_id"]) is not str or str(UUID(restart["boot_id"])) != restart["boot_id"]
                    or type(restart["configuration_sha256"]) is not str
                    or not re.fullmatch("[0-9a-f]{64}", restart["configuration_sha256"])
                    or state.get("pending") is not None or watermark is None
                ):
                    raise ValueError
            except ValueError:
                raise ValueError("Invalid saved VyOS restart state") from None
        if state.get("scope") != self.scope:
            previous = state.get("scope")
            if not isinstance(previous, dict) or not {"rule_base", "interfaces"}.issubset(previous):
                raise ValueError("VyOS provisioning state belongs to a different scope")
            retired = previous.keys() - self.scope.keys()
            if (
                state.get("pending") is not None
                or any(
                    value != self.scope[key] and (
                        not (key == "routes" and extends_static_route_scope(self.route_scope, value))
                        and not (key == "mdns" and self._can_switch_mdns_engine(value, state))
                        and not (key == "bgp" and self.bgp_scope is not None and self.bgp_scope.accepts_existing_scope(value))
                    )
                    for key, value in previous.items() if key in self.scope
                )
                or any(
                    key == "rules" or key not in _EMPTY_CONFIG or f"verified_{key}" not in state
                    or state[f"verified_{key}"] != _EMPTY_CONFIG[key]
                    for key in retired
                )
            ):
                raise ValueError("VyOS provisioning state belongs to a different scope")
            state["scope"] = self.scope
        for key, expected in (("verified_rules", dict), ("previous_revisions", list)):
            if not isinstance(state.get(key), expected):
                raise ValueError("Invalid saved VyOS firewall state")
        if not set(state["verified_rules"]).issubset(self.slots):
            raise ValueError("Invalid saved VyOS firewall ownership range")
        ipv6_rules = state["verified_rules_ipv6"]
        if (not isinstance(ipv6_rules, dict) or not set(ipv6_rules).issubset(self.slots)
                or ipv6_rules and not self.ipv6_interfaces):
            raise ValueError("Invalid saved VyOS IPv6 firewall ownership")
        for name in _LAN_CHAINS:
            lan_chain = state[f"verified_{name}"]
            if lan_chain is not None and (
                not isinstance(lan_chain, dict) or lan_chain.keys() != {"default-action", "rule"}
                or lan_chain["default-action"] != "return" or not isinstance(lan_chain["rule"], dict)
                or not set(lan_chain["rule"]).issubset(self.slots)
            ):
                raise ValueError("Invalid saved VyOS LAN firewall chain ownership")
        self._validate_firewall_ownership(state)
        if state["verified_dhcp"] is not None and (
            self.dhcp_scope is None or not isinstance(state["verified_dhcp"], dict)
        ):
            raise ValueError("Invalid saved VyOS DHCP ownership")
        routes = state["verified_routes"]
        route_destinations = self.route_scope.destinations if self.route_scope is not None else ()
        if not isinstance(routes, dict) or not set(routes).issubset(route_destinations):
            raise ValueError("Invalid saved VyOS static route ownership")
        if "verified_route_identities" in state:
            validate_static_route_identities(state["verified_route_identities"], routes, self.route_scope)
        dns_zone = state["verified_dns"]
        if dns_zone is not None and (self.dns_scope is None or not isinstance(dns_zone, dict)):
            raise ValueError("Invalid saved VyOS DNS ownership")
        nat_rules = state["verified_nat"]
        nat_slots = self.nat_scope.slots if self.nat_scope is not None else ()
        if not isinstance(nat_rules, dict) or not set(nat_rules).issubset(nat_slots):
            raise ValueError("Invalid saved VyOS source NAT ownership")
        wireguard = state["verified_wireguard"]
        if wireguard is not None and (
            self.wireguard_scope is None or not isinstance(wireguard, dict) or wireguard.keys() != {"interface", "guards"}
        ):
            raise ValueError("Invalid saved VyOS WireGuard ownership")
        port_forward = state["verified_port_forward"]
        if port_forward is not None and (
            self.port_forward_scope is None or not isinstance(port_forward, dict)
            or port_forward.keys() != {"rules", "guards"}
        ):
            raise ValueError("Invalid saved VyOS port forwarding ownership")
        vlan = state["verified_vlan"]
        if vlan is not None and (self.vlan_scope is None or vlan != {"address": self.vlan_scope.address}):
            raise ValueError("Invalid saved VyOS VLAN ownership")
        mdns = state["verified_mdns"]
        if mdns is not None and (self.mdns_scope is None or not isinstance(mdns, dict)):
            raise ValueError("Invalid saved VyOS mDNS ownership")
        ospf = state["verified_ospf"]
        if ospf is not None and (self.ospf_scope is None or not isinstance(ospf, dict)):
            raise ValueError("Invalid saved VyOS OSPF ownership")
        bgp = bgp_checkpoint_resources(state["verified_bgp"])
        if bgp and self.bgp_scope is None:
            raise ValueError("Retain the VyOS BGP scope until its configuration has been withdrawn")
        pending_transaction = state["pending"]
        if isinstance(pending_transaction, dict) and (self.bgp_scope is not None or "bgp" in pending_transaction):
            pending_bgp = bgp_checkpoint_resources(pending_transaction.get("bgp"))
            if pending_bgp and self.bgp_scope is None:
                raise ValueError("Retain the VyOS BGP scope until its transaction has been recovered")
            if pending_bgp != bgp and (type(pending_transaction.get("confirmed")) is not bool
                    or pending_transaction["confirmed"] and "confirmation_sha256" not in pending_transaction):
                raise ValueError("Pending VyOS BGP change is missing its confirmation proof")
        ipsec = state["verified_ipsec"]
        if ipsec is not None and (self.ipsec_scope is None or not isinstance(ipsec, dict)
                                  or ipsec.keys() != {"config", "guards", "routes"}):
            raise ValueError("Invalid saved VyOS IPsec ownership")
        openvpn = state["verified_openvpn"]
        if openvpn is not None and (self.openvpn_scope is None or not isinstance(openvpn, dict)
                                    or openvpn.keys() != {"resources", "remote_port", "digests"}):
            raise ValueError("Invalid saved VyOS OpenVPN ownership")
        wan_default = state["verified_wan_default"]
        if wan_default is not None and (self.wan_fib_command is None or not isinstance(wan_default, dict)
                                        or wan_default.keys() != {"failover", "nat"}):
            raise ValueError("Invalid saved VyOS WAN failover ownership")
        policy_route = state["verified_policy_route"]
        if policy_route is not None and (self.policy_route_fib_command is None or policy_route not in POLICY_ROUTE_DESTINATIONS):
            raise ValueError("Invalid saved VyOS policy route ownership")
        if "policy_table_setup" in state:
            setup = state["policy_table_setup"]
            fields = {"expected_sha256", "retry_after", "confirmed"}
            if (self.policy_route_fib_command is None or state.get("pending") is not None or state.get("restart") is not None
                    or policy_route is not None
                    or not isinstance(setup, dict) or setup.keys() not in (fields, fields | {"confirmation_sha256"})
                    or type(setup["confirmed"]) is not bool or type(setup["retry_after"]) not in (int, float)
                    or not 0 < setup["retry_after"] < 10**12
                    or not isinstance(setup["expected_sha256"], str)
                    or not re.fullmatch(r"[0-9a-f]{64}", setup["expected_sha256"])):
                raise ValueError("Invalid saved VyOS policy table preparation")
        guard = state.get("policy_route_guard", [])
        guard_setup = state.get("policy_route_guard_setup")
        if ((guard or guard_setup is not None) and self.policy_route_fib_command is None
                or guard_setup is not None and ("restart" in state or "policy_table_setup" in state)
                or not self._valid_policy_route_guard(guard)):
            raise ValueError("Invalid saved VyOS policy route guard ownership")
        if guard_setup is not None:
            planned = {"protected", "retry_after", "selector"}
            staged = planned | {"configuration_sha256", "confirmed"}
            if (not isinstance(guard_setup, dict)
                    or guard_setup.keys() not in (planned, staged, staged | {"confirmation_sha256"})
                    or not self._valid_policy_route_guard(guard_setup["protected"]) or guard_setup["protected"] == guard
                    or guard_setup["selector"] is not None and guard_setup["selector"] not in guard_setup["protected"]
                    or type(guard_setup["retry_after"]) not in (float, int)
                    or not 0 < guard_setup["retry_after"] < 10**12
                    or "configuration_sha256" in guard_setup and (
                        type(guard_setup["confirmed"]) is not bool or not isinstance(guard_setup["configuration_sha256"], str)
                        or re.fullmatch(r"[0-9a-f]{64}", guard_setup["configuration_sha256"]) is None
                    )):
                raise ValueError("Invalid saved VyOS policy route guard transition")
        pending = state.get("pending")
        if isinstance(pending, dict) and "policy_route_saved" in pending and (
            pending["policy_route_saved"] is not True or self.policy_route_fib_command is None
            or not (pending.get("confirmed") or "confirmation_sha256" in pending)
        ):
            raise ValueError("Invalid saved VyOS policy route selector transition")
        qos = state["verified_qos"]
        if qos is not None:
            if self.qos_kernel_command is None:
                raise ValueError("Invalid saved VyOS QoS ownership")
            limit_from_checkpoint(qos)
        inspection_queue = state["verified_inspection_queue"]
        if inspection_queue is not None and (inspection_queue is not True or self.stock_inspection_policy is None):
            raise ValueError("Invalid saved VyOS inspection queue ownership")
        shadow = state["verified_shadow_interconnect"]
        if shadow is not None and (self.shadow_interconnect is None or shadow not in SHADOW_ADDRESSES):
            raise ValueError("Invalid saved Shadow Mode interconnect ownership")
        if isinstance(pending, dict) and pending.get("shadow_interconnect") is not None and (
            self.shadow_interconnect is None or pending["shadow_interconnect"] not in SHADOW_ADDRESSES
        ):
            raise ValueError("Invalid pending Shadow Mode interconnect ownership")
        if self.shadow_interconnect is not None and pending is not None:
            if (not isinstance(pending, dict) or "shadow_interconnect" not in pending
                    or type(pending.get("confirmed")) is not bool or not isinstance(pending.get("revision"), str)
                    or not pending["revision"] or type(pending.get("retry_after")) not in (int, float)
                    or not 0 < pending["retry_after"] < 10**12):
                raise ValueError("Invalid pending Shadow Mode transaction")
            if pending["confirmed"] or "confirmation_sha256" in pending:
                fingerprint = pending.get("confirmation_sha256")
                if not isinstance(fingerprint, str) or re.fullmatch(r"[0-9a-f]{64}", fingerprint) is None:
                    raise ValueError("Missing verified fingerprint for the pending Shadow Mode transaction")
        return state

    def _write_state(self, state, *, durable=False):
        atomic_write(self.state_path, lambda output: json.dump(state, output, sort_keys=True))
        if durable:
            self._sync_state_directory()

    def _sync_state_directory(self):
        directory = os.open(self.state_path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)

    def _require_completed_commit(self, pending):
        if "confirmation_sha256" not in pending:
            return
        fingerprint = pending["confirmation_sha256"]
        if not isinstance(fingerprint, str) or re.fullmatch(r"[0-9a-f]{64}", fingerprint) is None:
            raise ValueError("Invalid saved VyOS confirmation fingerprint")
        if self.commit_proof is None:
            raise ValueError("Retain the VyOS commit proof helper until this transaction is recovered")
        if self.commit_proof(phase="completed") != fingerprint:
            raise ValueError("VyOS completed revision differs from the fully verified staged configuration")

    def _stock_inspection_intent(self, mode):
        if mode == "off":
            return InspectionIntent("off", ())
        if mode not in ("notify", "block"):
            raise ValueError("Invalid stock inspection mode")
        engine = self.inspection_controller
        return InspectionIntent(mode, engine.networks, engine.vendor_controls_sha256)

    def _read_stock_inspection_queue(self):
        if self.stock_inspection_policy is None:
            return None
        active = self.stock_inspection_policy.read(self.backend.read_config(["firewall"]))
        return True if active else None

    def _verify_stock_inspection_queue(self, desired):
        if self._read_stock_inspection_queue() is not desired:
            raise ValueError("Stock VyOS inspection queue differs from intended state")

    def _finish_stock_inspection(self, intent):
        if intent is not None:
            self._verify_stock_inspection_queue(True if intent.mode == "block" else None)
            if intent.mode != "block":
                self.inspection_controller.apply_engine(intent)
            self.inspection_controller.verify_engine(intent)

    def verify_stock_inspection(self, intent):
        try:
            self._verify_stock_inspection_queue(True if intent.mode == "block" else None)
            self.inspection_controller.verify_engine(intent)
        except (OSError, TypeError, KeyError, ValueError, VyOSReadError) as error:
            raise InspectionControlError(str(error)) from error

    def _read_owned(self, path=_RULE_PATH):
        if path == _IPV6_RULE_PATH and not self.ipv6_interfaces:
            return {}
        subtree = self.backend.read_config(path)
        if subtree is None:
            return {}
        rules = subtree.get("rule")
        if set(subtree) != {"rule"} or not isinstance(rules, dict):
            raise VyOSReadError("Unexpected VyOS forwarding rule collection format")
        return self._normalize_firewall_rules({slot: rules[slot] for slot in self.slots if slot in rules})

    @staticmethod
    def _normalize_firewall_rules(rules):
        if not isinstance(rules, dict):
            raise VyOSReadError("Unexpected VyOS firewall rule collection format")
        normalized = rules.copy()
        for slot, rule in rules.items():
            if not isinstance(rule, dict):
                raise VyOSReadError("Unexpected VyOS forwarding rule format")
            if isinstance(states := rule.get("state"), str):
                normalized[slot] = {**rule, "state": [states]}
            elif isinstance(states, list) and all(isinstance(state, str) for state in states):
                normalized[slot] = {**rule, "state": sorted(states)}
        return normalized

    def _lan_chain_anchor(self):
        return {self.slots[0]: {
            "action": "jump", "jump-target": self.lan_chain_name, "description": "UniFi managed LAN policy",
        }}

    def _validate_firewall_ownership(self, state):
        pending = state.get("pending")
        if pending is not None and not isinstance(pending, dict):
            raise ValueError("Invalid pending VyOS provisioning state")
        for record, prefix in ((state, "verified_"), (pending or {}, "")):
            for chain, rules in _LAN_CHAINS.items():
                entries = record.get(prefix + rules, {})
                owned_chain = record.get(prefix + chain)
                if owned_chain is not None:
                    if entries != self._lan_chain_anchor() or not isinstance(owned_chain, dict):
                        raise ValueError("Invalid saved VyOS LAN firewall chain ownership")
                    entries = owned_chain.get("rule")
                if not isinstance(entries, dict) or not entries.keys() <= set(self.slots):
                    raise ValueError("Invalid saved VyOS firewall rule range")
                for rule in entries.values():
                    if not isinstance(rule, dict) or rule.get("description") != self._firewall_rule_label(rule.get("action")):
                        raise ValueError("Invalid saved VyOS firewall rule ownership")

    def _read_firewall_policy(self, read_chains):
        firewall = (self.backend.read_config(["firewall"]) or {}) if read_chains else {}
        policy = {}
        for name, rules in _LAN_CHAINS.items():
            path = _POLICY_RULE_PATHS[rules]
            policy[name] = None
            if name not in read_chains:
                policy[rules] = self._read_owned(path)
                continue
            family = path[1]
            family_config = firewall.get(family, {})
            entries = family_config.get("forward", {}).get("filter", {}).get("rule", {})
            self._verify_lan_chain_references(firewall, family, self.lan_chain_name)
            policy[rules] = self._normalize_firewall_rules({slot: entries[slot] for slot in self.slots if slot in entries})
            chain = family_config.get("name", {}).get(self.lan_chain_name)
            if chain is not None and "rule" in chain:
                chain = {**chain, "rule": self._normalize_firewall_rules(chain["rule"])}
            policy[name] = chain
        return policy

    def _verify_lan_chain_references(self, firewall, family, name):
        anchor = ("forward", "filter", "rule", self.slots[0], "jump-target")
        nodes = [((), firewall.get(family, {}))]
        while nodes:
            path, node = nodes.pop()
            for key, value in node.items():
                location = (*path, key)
                if isinstance(value, dict):
                    nodes.append((location, value))
                elif key in ("jump-target", "default-jump-target") and value == name and location != anchor:
                    raise ValueError("An operator firewall rule references the reserved VyOS LAN chain")
        binding_key = "ipv6-name" if family == "ipv6" else "name"
        for zone in firewall.get("zone", {}).values():
            bindings = (zone.get("default-firewall", {}), *(
                pair.get("firewall", {}) for pair in zone.get("from", {}).values()
            ))
            if any(binding.get(binding_key) == name for binding in bindings):
                raise ValueError("An operator firewall zone references the reserved VyOS LAN chain")

    def _lan_chain_changes(self, family, name, current, desired):
        if current == desired:
            return ()
        path = ["firewall", family, "name", name]
        if desired is None:
            return ({"op": "delete", "path": path},)
        steps = () if current else ({"op": "set", "path": [*path, "default-action"], "value": "return"},)
        previous = current["rule"] if current else {}
        return (*steps, *firewall_rule_changes({"lan": [*path, "rule"]}, {"lan": previous}, {"lan": desired["rule"]}))

    def _firewall_commands(self, current, desired):
        before, after = [], []
        for name, rules in _LAN_CHAINS.items():
            family = _POLICY_RULE_PATHS[rules][1]
            commands = self._lan_chain_changes(family, self.lan_chain_name, current[name], desired[name])
            # Create targets before their jumps and remove jumps before their targets.
            (before if desired[name] else after).extend(commands)
        return (*before, *firewall_rule_changes(_POLICY_RULE_PATHS, current, desired), *after)

    def _read_dhcp_networks(self):
        if self.dhcp_scope is None:
            return {}
        subtree = self.backend.read_config(_DHCP_PATH)
        if subtree is None:
            return {}
        networks = subtree.get("shared-network-name")
        if set(subtree) != {"shared-network-name"} or not isinstance(networks, dict):
            raise VyOSReadError("Unexpected VyOS DHCP shared network format")
        return networks

    def _owned_dhcp(self, networks):
        return networks.get(self.dhcp_scope.shared_network) if self.dhcp_scope is not None else None

    def _read_static_routes(self):
        destinations = self.route_scope.destinations if self.route_scope is not None else ()
        routes = {}
        if self.ipsec_scope is not None or any(":" not in destination for destination in destinations):
            routes.update(self._read_static_route_family("route"))
        if any(":" in destination for destination in destinations):
            routes.update(self._read_static_route_family("route6"))
        return routes

    def _read_static_route_family(self, node):
        config = self.backend.read_config(["protocols", "static", node])
        if config is None:
            return {}
        if config.keys() != {node} or not isinstance(config[node], dict):
            raise VyOSReadError(f"Unexpected VyOS static {node} format")
        return config[node]

    def _operational_static_routes(self, destinations):
        routes = {}
        if any(":" not in destination for destination in destinations):
            routes.update(self.backend.show_ipv4_routes())
        if any(":" in destination for destination in destinations):
            routes.update(self.backend.show_ipv6_routes())
        return routes

    def _owned_routes(self, routes):
        if self.route_scope is None:
            return {}
        return {name: routes[name] for name in self.route_scope.destinations if name in routes}

    def read_verified_static_route_state(self):
        with self.locked_state() as state:
            verified = state["verified_routes"]
            if not verified:
                return {}, {}
            running = self._read_static_routes()
            owned = {prefix: tree for prefix, tree in verified.items() if running.get(prefix) == tree}
            identities = state.get("verified_route_identities", {})
            return owned, {prefix: identities[prefix] for prefix in owned if prefix in identities}

    def _read_dns(self):
        if self.dns_scope is None:
            return {}
        return self.backend.read_config(_DNS_PATH) or {}

    def _owned_dns(self, forwarding):
        if self.dns_scope is None:
            return None
        zones = forwarding.get("authoritative-domain", {})
        if not isinstance(zones, dict):
            raise VyOSReadError("Unexpected VyOS authoritative DNS domain format")
        return zones.get(self.dns_scope.zone)

    def _plan_dns(self, intent, dns_intent, forwarding, verified):
        if self.dns_scope is None:
            if dns_intent is not None:
                raise ValueError("No managed VyOS DNS zone is configured")
            return None, ()
        if dns_intent is None or dns_intent.revision != intent.revision:
            raise ValueError("The managed DNS zone needs intent from this controller revision")
        plan = plan_dns_commands(dns_intent, scope=self.dns_scope, current_forwarding=forwarding, verified_zone=verified)
        return plan.desired_zone, plan.commands

    def _read_nat(self):
        if self.nat_scope is None and self.ipsec_scope is None and self.openvpn_scope is None:
            return {}
        return self._read_rule_collection(_NAT_PATH)

    def _read_mdns(self):
        if self.mdns_scope is None:
            return None
        stock = self.backend.read_config(_MDNS_PATH)
        if self.mdns_container is None:
            return stock
        if stock is not None:
            raise ValueError("VyOS stock mDNS is configured and prevents container ownership")
        return self.backend.read_config(list(MDNS_CONTAINER_PATH))

    def _can_switch_mdns_engine(self, previous, state):
        return (isinstance(previous, dict) and state.get("verified_mdns") is None
                and {key: value for key, value in previous.items() if key != "container"} == asdict(self.mdns_scope))

    def _plan_mdns(self, intent, mdns_intent, current, verified):
        scope = self.mdns_scope
        if scope is None:
            if mdns_intent is not None:
                raise ValueError("No managed VyOS mDNS scope is configured")
            return None, ()
        if not isinstance(mdns_intent, MdnsIntent) or mdns_intent.revision != intent.revision or mdns_intent.scope != scope:
            raise ValueError("Managed mDNS needs intent for its pinned scope from this controller revision")
        live_interfaces = interface_details(self.backend.show_interfaces())
        if self.mdns_container is not None:
            desired, commands = self.mdns_container.plan(mdns_intent, current, verified, live_interfaces)
            if desired is not None:
                self.mdns_container.require_preloaded(self.backend.show_container_images())
            if verified is None or desired == verified:
                self.mdns_container.verify(scope, verified, current, live_interfaces, self.backend)
            return desired, commands
        plan = plan_mdns_commands(
            scope=scope, enabled=mdns_intent.enabled, current_mdns=current, verified_repeater=verified,
            live_interfaces=live_interfaces,
            listener_present=self.backend.has_mdns_listener(), services=mdns_intent.services,
        )
        return plan.desired_repeater, plan.commands

    def _verify_mdns(self, expected, config, detail):
        if self.mdns_container is not None:
            self.mdns_container.verify(self.mdns_scope, expected, config, interface_details(detail), self.backend)
        elif self.mdns_scope is not None:
            verify_mdns_state(
                scope=self.mdns_scope, expected_repeater=expected, current_mdns=config,
                live_interfaces=interface_details(detail), listener_present=self.backend.has_mdns_listener(),
            )

    def _read_rule_collection(self, path):
        config = self.backend.read_config(path)
        if config is None:
            return {}
        if set(config) != {"rule"} or not isinstance(config["rule"], dict):
            raise VyOSReadError(f"Unexpected VyOS rule collection at {' '.join(path)}")
        return config["rule"]

    def _owned_nat(self, rules):
        if self.nat_scope is None:
            return {}
        return {slot: rules[slot] for slot in self.nat_scope.slots if slot in rules}

    def _plan_nat(self, intent, nat_intent, current_rules, verified):
        scope = self.nat_scope
        if scope is None:
            if nat_intent is not None:
                raise ValueError("No managed VyOS source NAT scope is configured")
            return {}, ()
        if nat_intent is None or nat_intent.revision != intent.revision:
            raise ValueError("Managed source NAT needs intent from this controller revision")
        addresses = {}
        if nat_intent.rules:
            interfaces = interface_details(self.backend.show_interfaces())
            flags, body = interfaces.get(scope.interface, ([], ""))
            if not {"UP", "LOWER_UP"}.issubset(flags):
                raise VyOSReadError("Source NAT egress is not up on VyOS")
            addresses[scope.interface] = [str(address) for address in interface_ipv4_addresses(body)]
        plan = plan_nat_commands(
            nat_intent, scope=scope, current_rules=current_rules, verified_rules=verified,
            live_interface_addresses=addresses,
        )
        return plan.desired_rules, plan.commands

    def _read_wireguard(self):
        if self.wireguard_scope is None:
            return {}
        raw_interfaces = self.backend.read_config(_WIREGUARD_PATH)
        if raw_interfaces is None:
            raw_interfaces = {"wireguard": {}}
        if set(raw_interfaces) != {"wireguard"} or not isinstance(raw_interfaces["wireguard"], dict):
            raise VyOSReadError("Unexpected VyOS WireGuard configuration format")
        return raw_interfaces["wireguard"]

    def _read_guards(self):
        paths = {}
        if self.wireguard_scope is not None:
            paths.update(GUARD_PATHS)
        if self.port_forward_scope is not None:
            paths.update(PORT_FORWARD_GUARD_PATHS)
        if self.ipsec_scope is not None:
            paths.update(IPSEC_GUARD_PATHS)
        if self.openvpn_scope is not None:
            paths.update(OPENVPN_GUARD_PATHS)
        chains = {name: self._read_rule_collection(path) for name, path in paths.items()}
        wireguard = {name: chains[name] for name in GUARD_PATHS} if self.wireguard_scope else {}
        port_forward = {name: chains[name] for name in PORT_FORWARD_GUARD_PATHS} if self.port_forward_scope else {}
        ipsec = {name: chains[name] for name in IPSEC_GUARD_PATHS} if self.ipsec_scope else {}
        openvpn = {name: chains[name] for name in OPENVPN_GUARD_PATHS} if self.openvpn_scope else {}
        if self.openvpn_scope is not None:
            verify_openvpn_guards(openvpn, self.openvpn_guard)
        return wireguard, port_forward, ipsec, openvpn

    def _read_ipsec(self):
        if self.ipsec_scope is None:
            return None
        configuration = self.backend.read_config(_IPSEC_PATH)
        if configuration is not None and configuration.keys() == {"ipsec"}:
            return configuration["ipsec"]
        return configuration

    def _owned_ipsec(self, raw, guard_chains, static_routes):
        if self.ipsec_scope is None:
            return None
        config = redact_ipsec_config(raw, scope=self.ipsec_scope)
        guards = owned_ipsec_guards(guard_chains, self.ipsec_guard_base)
        prefix = self.ipsec_scope.remote_selector
        routes = {prefix: static_routes[prefix]} if prefix in static_routes else {}
        if config is not None or any(guards.values()) or routes:
            return {"config": config, "guards": guards, "routes": routes}
        return None

    def _verify_vpn_guard_path(self, feature):
        if (self.backend.read_config(["firewall", "flowtable"]) is not None
                or self.backend.read_config(["firewall", "global-options", "state-policy"]) is not None):
            raise ValueError(f"Managed {feature} requires a verified path without firewall offload or preemptive state policy")

    def _plan_ipsec(self, intent, ipsec_intent, raw, guard_chains, static_routes, verified):
        scope = self.ipsec_scope
        if scope is None:
            if ipsec_intent is not None:
                raise ValueError("No managed VyOS IPsec scope is configured")
            return None, ()
        if not isinstance(ipsec_intent, IpsecIntent) or ipsec_intent.revision != intent.revision:
            raise ValueError("Managed IPsec needs intent from this controller revision")
        active = ipsec_intent.peer is not None
        live = {}
        requested_routes = ()
        if active:
            self._verify_vpn_guard_path("IPsec")
            live = interface_details(self.backend.show_interfaces())
            requested_routes = (StaticRoute(IPv4Network(scope.remote_selector), IPv4Address(scope.remote_peer),
                                           1, UUID(ipsec_intent.peer.native_id)),)
        previous = verified or {"config": None, "guards": {name: {} for name in IPSEC_GUARD_PATHS}, "routes": {}}
        config = plan_ipsec_commands(ipsec_intent, scope=scope, current_config=raw,
                                     verified_config=previous["config"], live_interfaces=live)
        guards = plan_ipsec_guards(scope, self.ipsec_guard_base, active=active,
                                   current=guard_chains, verified=previous["guards"])
        route_scope = self.ipsec_route_scope
        routes = plan_route_commands(
            StaticRouteIntent(intent.revision, route_scope, requested_routes), scope=route_scope,
            current_routes=static_routes, verified_routes=previous["routes"],
            connected_routes=self.backend.show_ipv4_routes() if active else {},
            require_connected=True,
        )
        desired = {"config": config.desired_config, "guards": guards.desired, "routes": routes.desired_routes} if active else None
        return desired, (*guards.commands, *config.commands, *routes.commands)

    def _read_openvpn(self):
        if self.openvpn_scope is None:
            return None
        return read_openvpn_state(self.backend.read_complete_configuration(), self.openvpn_scope)

    def _read_routing_configuration(self):
        if self.wan_fib_command is None and self.qos_kernel_command is None:
            return None, None, None
        running = self.backend.read_complete_configuration()
        if self.wan_fib_command is None:
            return running, None, None
        policy = read_policy_route_state(running) if self.policy_route_fib_command is not None else None
        wan = read_wan_state(running, ignore_inactive=True, policy_route=policy)
        return running, wan, policy

    def _plan_wan_default(self, intent, wan_intent, running, current, previous, policy_route):
        if self.wan_fib_command is None:
            if wan_intent is not None:
                raise ValueError("No managed VyOS WAN failover scope is configured")
            return None, ()
        if not isinstance(wan_intent, WanFailoverIntent) or wan_intent.revision != intent.revision:
            raise ValueError("Managed WAN failover requires a complete snapshot from this controller revision")
        if wan_intent.primary is None and current is None and previous is None:
            return None, ()
        plan = plan_wan_default(
            wan_intent, running=running, verified=previous, fib=read_failover_fib(self.wan_fib_command),
            live_interfaces=interface_details(self.backend.show_interfaces()) if wan_intent.primary is not None else {},
            policy_route=policy_route,
        )
        return plan.expected, plan.commands

    def _plan_policy_route(self, intent, route, running, current, previous, *, wan_active):
        if self.policy_route_fib_command is None:
            if route is not None:
                raise ValueError("No managed VyOS policy route scope is configured")
            return None, ()
        if not isinstance(route, PolicyRouteIntent) or route.revision != intent.revision:
            raise ValueError("Managed policy routing requires a complete snapshot from this controller revision")
        if (route.destination is not None or current is not None) and self.commit_proof is None:
            raise ValueError("Policy routing requires VyOS commit proof to recover interrupted guard and selector writes")
        commands = plan_policy_route(route.destination, running=running, current=current, verified=previous,
                                     wan_active=wan_active)
        return route.destination, commands

    def _verify_policy_route(self, expected):
        verify_policy_route_fib(read_policy_route_fib(self.policy_route_fib_command), expected)

    @staticmethod
    def _valid_policy_route_guard(protected):
        return (isinstance(protected, list) and all(isinstance(item, str) and item in POLICY_ROUTE_DESTINATIONS for item in protected)
                and protected == sorted(set(protected)))

    def _observe_policy_route_guard(self, running):
        actual = read_policy_route_guard(running)
        verify_policy_route_guard(read_policy_route_fib(self.policy_route_fib_command), actual)
        return actual

    @staticmethod
    def _policy_table_configuration_hash(running):
        return hashlib.sha256(json.dumps(running, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()

    def _save_prepared_policy_table(self, state, setup):
        running = self.backend.read_complete_configuration()
        if self._policy_table_configuration_hash(running) != setup["expected_sha256"]:
            raise ValueError("VyOS configuration differs from the prepared policy table transaction")
        self._verify_policy_route(None)
        self.backend.show_interfaces()
        self._require_completed_commit(setup)
        self.backend.save_configuration()
        del state["policy_table_setup"]
        self._write_state(state, durable=True)
        return running

    def _ensure_policy_route_table(self, state, running, *, requested):
        expected, commands = prepare_policy_table(running)
        setup = state.get("policy_table_setup")
        if setup is not None:
            if not commands and (setup["confirmed"] or "confirmation_sha256" in setup):
                return self._save_prepared_policy_table(state, setup)
            if not commands or setup["confirmed"] or time.time() < setup["retry_after"]:
                raise ValueError("Prior VyOS policy table preparation still requires recovery")
            verify_policy_route_fib(read_policy_route_fib(self.policy_route_fib_command), None, table_present=False)
            del state["policy_table_setup"]
            self._write_state(state, durable=True)

        if not commands or not requested:
            return running
        if self.commit_proof is not None:
            self.commit_proof(phase="saved")
        verify_policy_route_fib(read_policy_route_fib(self.policy_route_fib_command), None, table_present=False)
        setup = {"expected_sha256": self._policy_table_configuration_hash(expected), "confirmed": False,
                 "retry_after": time.time() + 60 * _CONFIRM_MINUTES + 15}
        state["policy_table_setup"] = setup
        self._write_state(state, durable=True)
        self.backend.stage_configuration(commands, confirm_minutes=_CONFIRM_MINUTES)
        if self.backend.read_complete_configuration() != expected:
            raise ValueError("Staged VyOS policy table read-back differs from its intended configuration")
        staged_fingerprint = self.commit_proof(phase="staged") if self.commit_proof is not None else None
        self._verify_policy_route(None)
        self.backend.show_interfaces()
        if staged_fingerprint is not None:
            if self.commit_proof(phase="staged") != staged_fingerprint:
                raise ValueError("VyOS policy table configuration changed during verification")
            setup["confirmation_sha256"] = staged_fingerprint
            self._write_state(state, durable=True)
        self.backend.confirm_configuration()
        setup["confirmed"] = True
        self._write_state(state, durable=True)
        return self._save_prepared_policy_table(state, setup)

    def _save_policy_route_guard(self, state, setup):
        running = self.backend.read_complete_configuration()
        if (self._policy_table_configuration_hash(policy_route_guard_configuration(running)) != setup["configuration_sha256"]
                or self._observe_policy_route_guard(running) != setup["protected"]):
            raise ValueError("VyOS configuration differs from the verified policy route guard transaction")
        self._verify_policy_route(setup["selector"])
        self.backend.show_interfaces()
        self._require_completed_commit(setup)
        self.backend.save_configuration()
        state["policy_route_guard"] = setup["protected"]
        del state["policy_route_guard_setup"]
        self._write_state(state, durable=True)
        return running

    def _recover_policy_route_guard(self, state, running):
        setup = state.get("policy_route_guard_setup")
        if setup is None:
            return running
        if read_policy_route_state(running) != setup["selector"]:
            raise ValueError("The VyOS selector changed during policy route guard recovery")
        actual = self._observe_policy_route_guard(running)
        if actual == setup["protected"] and (setup.get("confirmed") or "confirmation_sha256" in setup):
            return self._save_policy_route_guard(state, setup)
        if (actual == state.get("policy_route_guard", []) and not setup.get("confirmed")
                and time.time() >= setup["retry_after"]):
            del state["policy_route_guard_setup"]
            self._write_state(state, durable=True)
            return running
        raise ValueError("Prior VyOS policy route guard transition still requires recovery")

    def _set_policy_route_guard(self, state, protected, *, selector):
        current = state.get("policy_route_guard", [])
        if not (current or protected):
            return
        if self.commit_proof is None:
            raise ValueError("Policy routing requires VyOS commit proof to verify the saved guard")
        running = self.backend.read_complete_configuration()
        if self._observe_policy_route_guard(running) != current:
            raise ValueError("The VyOS policy route guard differs from last verified ownership")
        if read_policy_route_state(running) != selector or selector is not None and selector not in protected:
            raise ValueError("The VyOS policy selector would lose its forwarding guard")
        self._verify_policy_route(selector)
        if current == protected:
            return
        self.commit_proof(phase="saved")
        expected, commands = plan_policy_route_guard(running, current, protected)
        expected = policy_route_guard_configuration(expected)
        setup = {"protected": protected, "selector": selector, "retry_after": time.time() + 60 * _CONFIRM_MINUTES + 15}
        state["policy_route_guard_setup"] = setup
        self._write_state(state, durable=True)
        self.backend.stage_configuration(commands, confirm_minutes=_CONFIRM_MINUTES)
        running = self.backend.read_complete_configuration()
        staged_fingerprint = self.commit_proof(phase="staged")
        if policy_route_guard_configuration(running) != expected or self._observe_policy_route_guard(running) != protected:
            raise ValueError("Staged VyOS policy route guard differs from the requested rules")
        self._verify_policy_route(selector)
        self.backend.show_interfaces()
        setup.update(configuration_sha256=self._policy_table_configuration_hash(expected), confirmed=False)
        if self.commit_proof(phase="staged") != staged_fingerprint:
            raise ValueError("VyOS configuration changed during policy route guard verification")
        setup["confirmation_sha256"] = staged_fingerprint
        self._write_state(state, durable=True)
        self.backend.confirm_configuration()
        setup["confirmed"] = True
        self._write_state(state, durable=True)
        self._save_policy_route_guard(state, setup)

    def _save_and_finish_policy_route(self, state, pending):
        destination = pending.get("policy_route")
        protected = [destination] if destination is not None else []
        trim_guard = state.get("policy_route_guard", []) != protected
        bgp_changed = pending.get("bgp", {}) != state.get("verified_bgp", {})
        if not pending.get("policy_route_saved"):
            required = {destination, state["verified_policy_route"]} - {None}
            if required:
                actual = self._observe_policy_route_guard(self.backend.read_complete_configuration())
                if actual != state.get("policy_route_guard", []) or not required.issubset(actual):
                    raise ValueError("Policy route selector cannot be saved without both verified forwarding guards")
            self._require_completed_commit(pending)
            self.backend.save_configuration()
            if self.shadow_interconnect is not None or bgp_changed:
                self._require_completed_commit(pending)
                self.commit_proof(phase="saved")
            if trim_guard:
                pending["policy_route_saved"] = True
                self._write_state(state, durable=True)
        self._set_policy_route_guard(state, protected, selector=destination)
        if self.shadow_interconnect is not None and trim_guard:
            self.commit_proof(phase="saved")
        if bgp_changed:
            bgp_key = self._bgp_proof_key(state, None, allow_create=False)
            if bgp_checkpoint(self._read_bgp(bgp_key)) != pending["bgp"]:
                raise ValueError("Saved VyOS BGP differs from the intended configuration")
            self._verify_bgp_import_policy(state.get("verified_bgp", {}), pending["bgp"])
            self.commit_proof(phase="saved")

    def verify_policy_route_for_restart(self, state):
        destination = state.get("verified_policy_route")
        if destination is None:
            return
        running = self.backend.read_complete_configuration()
        if (read_policy_route_state(running) != destination
                or self._observe_policy_route_guard(running) != [destination]):
            raise ValueError("The saved VyOS policy route or forwarding guard is unavailable")
        self._verify_policy_route(destination)

    def _plan_qos(self, intent, qos, running, current, previous):
        if self.qos_kernel_command is None:
            if qos is not None:
                raise ValueError("No VyOS QoS scope is configured")
            return None, ()
        if not isinstance(qos, QosIntent) or qos.revision != intent.revision:
            raise ValueError("Managed QoS needs a complete snapshot from this controller revision")
        if qos_checkpoint(current) != previous:
            raise ValueError("VyOS QoS differs from the last verified configuration")
        commands = plan_qos(qos.limit, running=running, verified=current)
        if current is not None or qos.limit is not None:
            verify_qos_kernel(read_qos_kernel(self.qos_kernel_command), current)
        if qos.limit is not None:
            observed = interface_details(self.backend.show_interfaces())
            for name, address in ((QOS_LAN_INTERFACE, "192.168.110.1/24"), (QOS_WAN_INTERFACE, "198.18.210.1/30")):
                details = observed.get(name)
                if (details is None or not {"UP", "LOWER_UP"}.issubset(details[0])
                        or interface_ipv4_addresses(details[1]) != [IPv4Interface(address)]):
                    raise ValueError("QoS needs the two pinned active VyOS IPv4 links")
        return qos_checkpoint(qos.limit), commands

    def _verify_qos(self, expected):
        limit = limit_from_checkpoint(expected)
        verify_qos_kernel(read_qos_kernel(self.qos_kernel_command), limit)

    def _verify_wan_default(self, expected):
        for attempt in range(5):
            try:
                verify_wan_fib(read_failover_fib(self.wan_fib_command), expected, require_route=True)
                return
            except (VyOSReadError, WanFailoverError):
                if attempt == 4:
                    raise
                time.sleep(1)

    def observe_wan_uplink(self, revision):
        state = self._load_state()
        expected = state["verified_wan_default"]
        if expected is None or state["pending"] is not None or revision != state["verified_revision"]:
            return None
        fib = read_failover_fib(self.wan_fib_command)
        verify_wan_fib(fib, expected, require_route=False)
        lookup = fib["lookup"]
        names = {"eth3.210": "eth0", "eth3.220": "eth2"}
        available = {row["dev"] for row in fib["routes"] if not row["flags"]}
        return {"uplink": names[lookup["dev"]] if lookup else None,
                "availability": {native: actual in available for actual, native in names.items()}}

    def _plan_openvpn(self, intent, openvpn_intent, current, guard_chains, verified):
        scope = self.openvpn_scope
        if scope is None:
            if openvpn_intent is not None:
                raise ValueError("No managed VyOS OpenVPN scope is configured")
            return None, ()
        if not isinstance(openvpn_intent, OpenVpnDesired) or openvpn_intent.revision != intent.revision:
            raise ValueError("Managed OpenVPN requires a complete snapshot from this controller revision")
        active = openvpn_intent.client is not None
        live = interface_details(self.backend.show_interfaces())
        if active:
            self._verify_vpn_guard_path("OpenVPN")
            verify_openvpn_guard_order(guard_chains, self.openvpn_guard)
        plan = plan_openvpn(openvpn_intent.client, scope, current=current, previous=verified,
                            live_interfaces=live)
        return plan.expected, plan.commands

    def _read_destination_nat(self):
        return self._read_rule_collection(_DNAT_PATH) if self.port_forward_scope is not None else {}

    def _read_vlan_ethernet(self):
        if self.vlan_scope is None and self.ospf_scope is None:
            return {}
        config = self.backend.read_config(_ETHERNET_PATH)
        if config is None or set(config) != {"ethernet"} or not isinstance(config["ethernet"], dict):
            raise VyOSReadError("VyOS did not return the managed VLAN Ethernet configuration")
        return config["ethernet"]

    def _ospf_proof_key(self, state, intent, *, allow_create=True):
        scope = self.ospf_scope
        if scope is None:
            return None
        stored = (state["verified_ospf"], (state["pending"] or {}).get("ospf"))
        required = any(ospf_config_has_authentication(scope, config) for config in stored)
        if not required and not (isinstance(intent, OspfIntent) and intent.scope == scope
                                 and intent.settings is not None and intent.settings.has_authentication):
            return None
        return self._credential_proof_key("OSPF", required=required, allow_create=allow_create)

    def _bgp_proof_key(self, state, intent, *, allow_create=True):
        if self.bgp_scope is None:
            return None
        required = any(bgp_checkpoint_has_password(checkpoint) for checkpoint in (
            state.get("verified_bgp", {}), (state["pending"] or {}).get("bgp", {}),
        ))
        policy = intent.policy if isinstance(intent, BgpProvisioningIntent) else None
        if not required and not (isinstance(policy, BgpIntent) and any(peer.password is not None for peer in policy.peers)):
            return None
        return self._credential_proof_key("BGP", required=required, allow_create=allow_create)

    def _credential_proof_key(self, feature, *, required, allow_create):
        path = self.state_path.with_name(f"{self.state_path.name}.{feature.lower()}-proof-key")
        try:
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        except FileNotFoundError:
            if required:
                raise ValueError(f"Restore the {feature} credential proof key that belongs to the provisioning journal") from None
            if not allow_create:
                raise ValueError(f"Prepare the {feature} credential proof key before planning standby authentication") from None
            key = os.urandom(32)
            atomic_write(path, lambda output: output.write(key.hex()), mode=0o600)
            self._sync_state_directory()
            return key
        with os.fdopen(fd, "rb") as source:
            info = os.fstat(source.fileno())
            if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600 or info.st_uid != os.geteuid():
                raise ValueError(f"{feature} credential proof key requires an owned regular file with mode 0600")
            value = source.read(65)
        if re.fullmatch(rb"[0-9a-f]{64}", value) is None:
            raise ValueError(f"{feature} credential proof key is invalid")
        return bytes.fromhex(value.decode("ascii"))

    def _read_bgp(self, proof_key):
        if self.bgp_scope is None:
            return {}
        return redact_bgp_configuration(read_bgp_configuration(self.backend), proof_key)

    def _refresh_bgp_filters(self, previous, desired):
        previous_peers = previous.get("process", {}).get("neighbor", {})
        desired_peers = desired.get("process", {}).get("neighbor", {})
        for name, direction, family, refresh in (
            ("import", "in", "ipv4-unicast", self.backend.soft_refresh_bgp_ipv4),
            ("export", "out", "ipv4-unicast", self.backend.soft_refresh_bgp_ipv4),
            ("import6", "in", "ipv6-unicast", self.backend.soft_refresh_bgp_ipv6),
            ("export6", "out", "ipv6-unicast", self.backend.soft_refresh_bgp_ipv6),
        ):
            if previous.get(name) == desired.get(name):
                continue
            for peer in sorted(previous_peers.keys() & desired_peers.keys()):
                if any(family not in peers[peer].get("address-family", {}) for peers in (previous_peers, desired_peers)):
                    continue
                address = ip_address(peer)
                if address not in self.bgp_scope.peers:
                    raise ValueError("VyOS BGP soft refresh is outside the approved peer scope")
                refresh(address, direction=direction)

    def _verify_bgp_import_policy(self, previous, desired):
        for name, read in (("import", self.backend.show_ipv4_routes), ("import6", self.backend.show_ipv6_routes)):
            if previous and previous.get(name) != desired.get(name):
                allowed = {row["prefix"] for row in desired.get(name, {}).get("rule", {}).values()}
                self._verify_bgp_imported_routes(read, allowed)

    @staticmethod
    def _verify_bgp_imported_routes(read, allowed):
        for attempt in range(6):
            routes = read()
            if not isinstance(routes, dict) or any(
                not isinstance(candidates, list) or any(not isinstance(row, dict) for row in candidates)
                for candidates in routes.values()
            ):
                raise VyOSReadError("VyOS did not return a usable BGP forwarding snapshot")
            installed = {prefix for prefix, candidates in routes.items() if any(
                row.get("protocol") == "bgp" and row.get("table") == 254 and row.get("vrfId") == 0
                and row.get("selected") is True and row.get("installed") is True for row in candidates
            )}
            if installed <= allowed:
                return
            if attempt < 5:
                time.sleep(1)
        raise VyOSReadError("VyOS still forwards BGP routes outside the intended import policy")

    def _plan_bgp(self, revision, intent, current, verified, proof_key):
        if intent is None:
            if current or verified:
                raise ValueError("Managed BGP requires explicit controller intent while configuration is installed")
            return {}, ()
        if (self.bgp_scope is None or not isinstance(intent, BgpProvisioningIntent) or intent.revision != revision
                or intent.policy is not None and not isinstance(intent.policy, BgpIntent)):
            raise ValueError("Managed BGP needs intent from this controller revision and an approved scope")
        if intent.policy is not None:
            self.bgp_scope.require(intent.policy)
        desired = bgp_checkpoint(redact_bgp_configuration(vyos_bgp_configuration(intent.policy), proof_key))
        commands = plan_bgp_commands(intent.policy, current=current, verified=bgp_checkpoint_resources(verified), proof_key=proof_key)
        return desired, commands

    def _read_ospf(self, proof_key):
        if self.ospf_scope is None:
            return None
        return redact_ospf_config(self.backend.read_config(_OSPF_PATH), scope=self.ospf_scope, proof_key=proof_key)

    def _plan_ospf(self, intent, ospf_intent, current, ethernet, verified, proof_key):
        scope = self.ospf_scope
        if scope is None:
            if ospf_intent is not None:
                raise ValueError("No managed VyOS OSPF scope is configured")
            return None, ()
        if not isinstance(ospf_intent, OspfIntent) or ospf_intent.revision != intent.revision or ospf_intent.scope != scope:
            raise ValueError("Managed OSPF needs intent for its pinned scope from this controller revision")
        plan = plan_ospf_commands(
            ospf_intent, scope=scope, current_ospf=current, verified_ospf=verified,
            current_ethernet=ethernet, live_interfaces=interface_details(self.backend.show_interfaces()),
            proof_key=proof_key,
        )
        if current is not None and plan.desired_ospf is not None and current["parameters"] != plan.desired_ospf["parameters"]:
            verify_ospf_router_id_edit(scope, current, self.backend.show_ipv4_ospf_interfaces())
        return plan.desired_ospf, plan.commands

    def _verify_ospf(self, expected, config, ethernet, detail):
        if self.ospf_scope is not None:
            verify_ospf_state(
                scope=self.ospf_scope, expected_ospf=expected, current_ospf=config,
                current_ethernet=ethernet, live_interfaces=interface_details(detail),
            )
            if expected is not None:
                verify_ospf_runtime(self.ospf_scope, expected, self.backend.show_ipv4_ospf_interfaces())

    def _owned_vlan(self, ethernet):
        if self.vlan_scope is None:
            return None
        parent = ethernet.get(self.vlan_scope.parent)
        vifs = parent.get("vif", {}) if isinstance(parent, dict) else None
        if not isinstance(vifs, dict):
            raise VyOSReadError("VyOS did not return the configured trunk for the managed VLAN")
        return vifs.get(str(self.vlan_scope.vlan_id))

    def _plan_vlan(self, intent, vlan_intent, ethernet, verified):
        scope = self.vlan_scope
        if scope is None:
            if vlan_intent is not None:
                raise ValueError("No managed VyOS VLAN scope is configured")
            return None, ()
        if not isinstance(vlan_intent, VlanIntent) or vlan_intent.revision != intent.revision or vlan_intent.scope != scope:
            raise ValueError("Managed VLAN needs intent for its pinned scope from this controller revision")
        plan = plan_vlan_commands(
            scope=scope, present=vlan_intent.present, current_ethernet=ethernet, verified_vif=verified,
            live_interfaces=interface_details(self.backend.show_interfaces()),
        )
        return plan.desired_vif, plan.commands

    def _verify_vlan(self, desired, ethernet, detail):
        if self.vlan_scope is not None:
            verify_vlan_state(
                scope=self.vlan_scope, expected_vif=desired, current_ethernet=ethernet,
                live_interfaces=interface_details(detail),
            )

    def _owned_port_forward(self, rules, guard_chains):
        scope = self.port_forward_scope
        if scope is None:
            return None
        owned = {slot: rules[slot] for slot in scope.slots if slot in rules}
        guards = owned_port_forward_guards(guard_chains, scope, self.port_forward_guard_base)
        return {"rules": owned, "guards": guards} if owned or any(guards.values()) else None

    def _plan_port_forward(self, intent, forward_intent, nat_rules, guard_chains, verified):
        scope = self.port_forward_scope
        if scope is None:
            if forward_intent is not None:
                raise ValueError("No managed VyOS port forwarding scope is configured")
            return None, ()
        if forward_intent is None or forward_intent.revision != intent.revision:
            raise ValueError("Managed port forwarding needs intent from this controller revision")
        previous = verified or {"rules": {}, "guards": {name: {} for name in PORT_FORWARD_GUARD_PATHS}}
        addresses = {}
        if forward_intent.forward is not None:
            live = interface_details(self.backend.show_interfaces())
            for name in (scope.wan_interface, scope.lan_interface):
                flags, body = live.get(name, ([], ""))
                if not {"UP", "LOWER_UP"}.issubset(flags):
                    raise VyOSReadError("A managed port forwarding interface is down on VyOS")
                addresses[name] = [str(address) for address in interface_ipv4_addresses(body)]
        nat = plan_port_forward_commands(
            forward_intent, scope=scope, current_rules=nat_rules, verified_rules=previous["rules"],
            live_interface_addresses=addresses,
        )
        guards = plan_port_forward_guards(
            forward_intent, self.port_forward_guard_base, current=guard_chains, verified=previous["guards"],
        )
        desired = {"rules": nat.desired_rules, "guards": guards.desired} if nat.desired_rules else None
        return desired, (*guards.commands, *nat.commands)

    def _owned_wireguard(self, raw_interfaces, guard_chains):
        scope = self.wireguard_scope
        if scope is None:
            return None
        interface = redact_wireguard_interface(raw_interfaces.get(scope.interface), scope=scope)
        guards = owned_guard_rules(guard_chains, self.wireguard_guard)
        return {"interface": interface, "guards": guards} if interface is not None or any(guards.values()) else None

    def _plan_wireguard(self, intent, wireguard_intent, raw_interfaces, guard_chains, verified):
        scope = self.wireguard_scope
        if scope is None:
            if wireguard_intent is not None:
                raise ValueError("No managed VyOS WireGuard scope is configured")
            return None, ()
        if wireguard_intent is None or wireguard_intent.revision != intent.revision:
            raise ValueError("Managed WireGuard needs intent from this controller revision")
        previous = verified or {"interface": None, "guards": {name: {} for name in GUARD_PATHS}}
        live = interface_details(self.backend.show_interfaces())
        interface_plan = plan_wireguard_commands(
            wireguard_intent, scope=scope, current_interfaces=raw_interfaces,
            verified_interface=previous["interface"], live_interfaces=live,
        )
        port = wireguard_intent.server.port if wireguard_intent.server is not None else None
        guard_plan = plan_wireguard_guards(
            scope, self.wireguard_guard, port, current=guard_chains, verified=previous["guards"],
        )
        desired = None if port is None else {"interface": interface_plan.desired_interface, "guards": guard_plan.desired}
        return desired, (*guard_plan.commands, *interface_plan.commands)

    def _verify_wireguard(self, configuration, detail=None):
        if configuration is None:
            return
        scope = self.wireguard_scope
        if detail is None:
            detail = self.backend.show_interfaces()
        flags, body = interface_details(detail).get(scope.interface, ([], ""))
        if "UP" not in flags or scope.tunnel_cidr not in {str(address) for address in interface_ipv4_addresses(body)}:
            raise VyOSReadError("Managed WireGuard interface has no verified active tunnel address")

    def _plan_routes(self, intent, route_intent, current, verified):
        if self.route_scope is None:
            if route_intent is not None:
                raise ValueError("No VyOS static route scope is configured")
            return {}, ()
        if route_intent is None or route_intent.revision != intent.revision:
            raise ValueError("The managed static route scope needs intent from this controller revision")
        plan = plan_route_commands(
            route_intent, scope=self.route_scope, current_routes=current, verified_routes=verified,
            connected_routes=self._operational_static_routes(self.route_scope.destinations),
        )
        return plan.desired_routes, plan.commands

    def _verify_routes(self, routes, *, withdrawn=frozenset(), previous_static=None):
        if routes or withdrawn:
            verify_route_forwarding(
                self._operational_static_routes(routes.keys() | withdrawn), routes, withdrawn,
                read_interfaces=lambda: interface_details(self.backend.show_interfaces()),
                previous_static=previous_static,
            )

    def _plan_dhcp(self, intent, dhcp_intent, current_networks, verified):
        if self.dhcp_scope is None:
            if dhcp_intent is not None:
                raise ValueError("No VyOS DHCP provisioning scope is configured")
            return None, ()
        if dhcp_intent is None or dhcp_intent.revision != intent.revision:
            raise ValueError("The managed DHCP scope needs intent from this controller revision")
        interface, vlan = self.dhcp_scope.interface.split(".")
        result = self.backend.read_config(["interfaces", "ethernet", interface, "vif", vlan, "address"])
        addresses = result.get("address") if result is not None else None
        if isinstance(addresses, str):
            addresses = [addresses]
        plan = plan_dhcp_commands(
            dhcp_intent, scope=self.dhcp_scope, current_networks=current_networks,
            verified_network=verified, live_interface_addresses={self.dhcp_scope.interface: addresses},
        )
        if plan.desired_network is None and plan.commands and len(current_networks) == 1:
            # VyOS rejects leaving DHCP enabled with no shared networks. Remove
            # the service only when its entire current content is journal-owned.
            service_path = _DHCP_PATH[:-1]
            if self.backend.read_config(service_path) != {"shared-network-name": current_networks}:
                raise ValueError("Removing the last managed DHCP network would change operator settings")
            return None, ({"op": "delete", "path": service_path},)
        return plan.desired_network, plan.commands

    @staticmethod
    def _firewall_rule_label(action):
        if action not in ("drop", "reject", "return"):
            raise ValueError("Unsupported VyOS firewall action")
        return "UniFi managed allow" if action == "return" else "UniFi managed deny"

    def _desired(self, intent):
        if len(intent.rules) > len(self.slots):
            raise ValueError("Policy exceeds the reserved VyOS firewall rule range")
        policy = {"rules": {}, "rules_ipv6": {}}
        for slot, rule in zip(self.slots, intent.rules):
            if type(rule.source) is not type(rule.destination):
                raise ValueError("Policy source and destination must use the same address family")
            is_ipv6 = isinstance(rule.source, IPv6Network)
            interfaces = self.ipv6_interfaces if is_ipv6 else self.interfaces
            family_rules = policy["rules_ipv6" if is_ipv6 else "rules"]
            inbound = interfaces.get(rule.source)
            outbound = interfaces.get(rule.destination)
            if not inbound or not outbound or inbound == outbound:
                raise ValueError("Policy requires two explicitly mapped VyOS LAN prefixes")
            mapped = {
                "action": rule.action,
                "description": self._firewall_rule_label(rule.action),
                "protocol": rule.protocol,
                "inbound-interface": {"name": inbound}, "outbound-interface": {"name": outbound},
                "source": {"address": str(rule.source)},
                "destination": {"address": str(rule.destination)},
            }
            mapped["source" if rule.source_port else "destination"]["port"] = str(rule.port)
            if rule.log:
                mapped["log"] = {}
            if rule.states:
                mapped["state"] = sorted(rule.states)
            family_rules[slot] = mapped
        for name, rules in _LAN_CHAINS.items():
            entries = policy[rules]
            policy[name] = None
            if any(rule["action"] == "return" for rule in entries.values()):
                policy[rules] = self._lan_chain_anchor()
                policy[name] = {"default-action": "return", "rule": entries}
        return policy

    @staticmethod
    def _effective_policy_rules(policy):
        return tuple(policy[name]["rule"] if policy[name] else policy[rules] for name, rules in _LAN_CHAINS.items())

    def _verify_ipv6_paths(self, rules, detail):
        if not rules:
            return
        observed = interface_details(detail)
        for rule in rules.values():
            for side, direction in (("source", "inbound-interface"), ("destination", "outbound-interface")):
                name = rule[direction]["name"]
                path = observed.get(name)
                prefix = IPv6Network(rule[side]["address"])
                if (path is None or not {"UP", "LOWER_UP"}.issubset(path[0])
                        or prefix not in {IPv6Interface(item).network for item in interface_ipv6_observations(path[1])}):
                    raise VyOSReadError("Managed IPv6 firewall prefix lacks its verified active VyOS LAN")

    def _verify_firewall_state_path(self, ipv4, ipv6):
        states_by_family = {
            family: {state for rule in rules.values() for state in rule.get("state", ())}
            for family, rules in (("ipv4", ipv4), ("ipv6", ipv6))
        }
        if not any(states_by_family.values()):
            return
        firewall = self.backend.read_config(["firewall"]) or {}
        ignore = self.backend.read_config(["system", "conntrack", "ignore"]) or {}
        global_policy = firewall.get("global-options", {}).get("state-policy", {})
        for family, states in states_by_family.items():
            if not states:
                continue
            if any(global_policy.get(state, {}).get("action") for state in states):
                raise ValueError(f"VyOS global state policy takes precedence over managed {family} connection states")
            if global_policy.get("offload", {}).get("offload-target"):
                raise ValueError("VyOS global flow offload bypasses managed connection-state rules")
            family_config = firewall.get(family, {})
            forward = family_config.get("forward", {}).get("filter", {})
            raw_rules = family_config.get("prerouting", {}).get("raw", {}).get("rule", {})
            filter_chains = (forward, *family_config.get("name", {}).values())
            if any(
                "disable" not in rule and rule.get("action") == "offload"
                for chain in filter_chains for rule in chain.get("rule", {}).values()
            ):
                raise ValueError(f"VyOS {family} flow offload bypasses managed connection-state rules")
            if (
                "disable-conntrack" in forward or ignore.get(family, {}).get("rule")
                or any("disable" not in rule and rule.get("action") == "notrack" for rule in raw_rules.values())
            ):
                raise ValueError(f"VyOS {family} connection tracking is disabled or excluded on the managed firewall path")

    def _record_verified(self, state, revision, configuration, *, route_identities=None):
        previous = state["verified_revision"]
        policy_route_changed = state["verified_policy_route"] != configuration["policy_route"]
        bgp_changed = state.get("verified_bgp", {}) != configuration.get("bgp", {})
        if previous is not None and previous != revision:
            state["previous_revisions"].append(previous)
        state.update(verified_revision=revision, pending=None)
        state.update({f"verified_{feature}": config for feature, config in configuration.items()})
        if route_identities is None:
            state.pop("verified_route_identities", None)
        else:
            validate_static_route_identities(route_identities, configuration["routes"], self.route_scope)
            state["verified_route_identities"] = route_identities
        self._write_state(state, durable=policy_route_changed or bgp_changed or self.shadow_interconnect is not None)

    def _reconcile_locked(
        self, intent, dhcp_intent, route_intent, dns_intent, nat_intent, wireguard_intent, port_forward_intent,
        vlan_intent, mdns_intent, ospf_intent, ipsec_intent, openvpn_intent, wan_intent, policy_route_intent, qos_intent, state,
        *, verify_unchanged=None, inspection_intent=None, shadow_interconnect_address=None, plan_only=False, bgp_intent=None,
    ):
        if shadow_interconnect_address is not None and (
            self.shadow_interconnect is None or shadow_interconnect_address not in SHADOW_ADDRESSES
        ):
            raise ValueError("Unapproved Shadow Mode interconnect address")
        current_shadow, interconnect_other = (
            read_interconnect(self.backend, self.shadow_interconnect) if self.shadow_interconnect is not None else (None, None)
        )
        if self.stock_inspection_policy is not None:
            if not isinstance(inspection_intent, InspectionIntent) or inspection_intent != self._stock_inspection_intent(
                inspection_intent.mode
            ):
                raise ValueError("Stock VyOS inspection requires authenticated intent for the approved engine")
        elif inspection_intent is not None:
            raise ValueError("Stock VyOS inspection has no approved queue topology")
        desired_inspection_queue = True if inspection_intent is not None and inspection_intent.mode == "block" else None
        desired_policy = self._desired(intent)
        networks = self._read_dhcp_networks()
        static_routes = self._read_static_routes()
        forwarding = self._read_dns()
        mdns = self._read_mdns()
        nat_rules = self._read_nat()
        wg_interfaces = self._read_wireguard()
        wg_guards, forward_guards, ipsec_guards, openvpn_guards = self._read_guards()
        ipsec = self._read_ipsec()
        openvpn = self._read_openvpn()
        running, wan_default, policy_route = self._read_routing_configuration()
        running = self._recover_policy_route_guard(state, running)
        qos_limit = read_qos_state(running) if self.qos_kernel_command is not None else None
        qos = qos_checkpoint(qos_limit)
        destination_nat = self._read_destination_nat()
        ethernet = self._read_vlan_ethernet()
        ospf_proof_key = self._ospf_proof_key(state, ospf_intent, allow_create=not plan_only)
        ospf = self._read_ospf(ospf_proof_key)
        bgp_key = self._bgp_proof_key(state, bgp_intent, allow_create=not plan_only)
        bgp = self._read_bgp(bgp_key)
        pending = state["pending"]
        read_chains = {name for name in _LAN_CHAINS if desired_policy[name] or state[f"verified_{name}"]
                       or pending and pending.get(name)}
        current_policy = self._read_firewall_policy(read_chains)
        current_mdns = mdns.get("repeater") if mdns is not None and self.mdns_container is None else mdns
        current = {**current_policy, "dhcp": self._owned_dhcp(networks),
                   "routes": self._owned_routes(static_routes), "dns": self._owned_dns(forwarding),
                   "nat": self._owned_nat(nat_rules), "wireguard": self._owned_wireguard(wg_interfaces, wg_guards),
                   "port_forward": self._owned_port_forward(destination_nat, forward_guards),
                   "vlan": self._owned_vlan(ethernet), "mdns": current_mdns,
                   "ospf": ospf, "ipsec": self._owned_ipsec(ipsec, ipsec_guards, static_routes),
                   "openvpn": openvpn, "wan_default": wan_default, "policy_route": policy_route, "qos": qos,
                   "inspection_queue": self._read_stock_inspection_queue(), "shadow_interconnect": current_shadow,
                   "bgp": bgp_checkpoint(bgp)}
        if pending is not None:
            pending_configuration = {feature: pending.get(feature, value) for feature, value in _EMPTY_CONFIG.items()}
            if "route_identities" in pending:
                validate_static_route_identities(pending["route_identities"], pending_configuration["routes"], self.route_scope)
            verified = {feature: state[f"verified_{feature}"] for feature in _EMPTY_CONFIG}
            if current == pending_configuration and (pending["confirmed"] or "confirmation_sha256" in pending):
                if not pending.get("policy_route_saved"):
                    self._require_completed_commit(pending)
                pending_inspection = None
                if self.stock_inspection_policy is not None:
                    pending_inspection = self._stock_inspection_intent(pending.get("inspection_mode"))
                    if pending_inspection.mode == "block":
                        self.inspection_controller.prepare_engine(pending_inspection)
                current_ipv4, current_ipv6 = self._effective_policy_rules(current_policy)
                self._verify_firewall_state_path(current_ipv4, current_ipv6)
                previous_routes = verified["routes"] | (verified["ipsec"] or {}).get("routes", {})
                active_routes = current["routes"] | (current["ipsec"] or {}).get("routes", {})
                self._verify_routes(active_routes, withdrawn=previous_routes.keys() - active_routes.keys(),
                                    previous_static=verified["routes"])
                detail = self.backend.show_interfaces()
                self._verify_ipv6_paths(current_ipv6, detail)
                self._verify_wireguard(current["wireguard"], detail)
                self._verify_vlan(current["vlan"], ethernet, detail)
                self._verify_mdns(current["mdns"], mdns, detail)
                self._verify_ospf(current["ospf"], ospf, ethernet, detail)
                if current["ipsec"] is not None:
                    self._verify_vpn_guard_path("IPsec")
                    verify_ipsec_guard_order(ipsec_guards, self.ipsec_guard_base)
                    if nat_rules:
                        raise ValueError("Source NAT overlaps the verified IPsec deployment")
                if current["openvpn"] is not None:
                    self._verify_vpn_guard_path("OpenVPN")
                    verify_openvpn_guard_order(openvpn_guards, self.openvpn_guard)
                    if nat_rules:
                        raise ValueError("Source NAT overlaps the verified OpenVPN deployment")
                elif state["verified_openvpn"] is not None:
                    self._verify_openvpn_removed(detail)
                if wan_default != state["verified_wan_default"]:
                    self._verify_wan_default(wan_default)
                if policy_route is not None or state["verified_policy_route"] is not None:
                    self._verify_policy_route(policy_route)
                if qos is not None or state["verified_qos"] is not None:
                    self._verify_qos(qos)
                if self.shadow_interconnect is not None:
                    verify_interconnect(self.backend, self.shadow_interconnect, current_shadow)
                self._save_and_finish_policy_route(state, pending)
                if self.mdns_container is not None:
                    self._verify_mdns(current["mdns"], self._read_mdns(), self.backend.show_interfaces())
                self._finish_stock_inspection(pending_inspection)
                self._record_verified(state, pending["revision"], current,
                                      route_identities=pending.get("route_identities"))
            elif current == verified and not pending.get("policy_route_saved") and time.time() >= pending["retry_after"]:
                if self.shadow_interconnect is not None:
                    verify_interconnect(self.backend, self.shadow_interconnect, current_shadow)
                if self.shadow_interconnect is not None or self.bgp_scope is not None:
                    self.commit_proof(phase="saved")
                state["pending"] = None
                self._write_state(state, durable=bool(state.get("policy_route_guard")))
                self._set_policy_route_guard(state, [policy_route] if policy_route is not None else [], selector=policy_route)
            else:
                return ApplyResult(state["verified_revision"], error="Prior VyOS transaction still requires recovery")

        revision = state["verified_revision"]
        if any(current_policy[name] != state[f"verified_{name}"] for name in _POLICY_RULE_PATHS):
            return ApplyResult(revision, error="Reserved VyOS rules differ from last verified ownership")
        if any(current_policy[name] != state[f"verified_{name}"] for name in _LAN_CHAINS):
            return ApplyResult(revision, error="Reserved VyOS LAN chain differs from last verified ownership")
        if current["inspection_queue"] is not state["verified_inspection_queue"]:
            return ApplyResult(revision, error="Stock VyOS inspection queue differs from last verified ownership")
        if current_shadow != state["verified_shadow_interconnect"]:
            return ApplyResult(revision, error="VyOS interconnect differs from last verified Shadow Mode ownership")
        shadow_commands = []
        if self.shadow_interconnect is not None:
            verify_interconnect(self.backend, self.shadow_interconnect, current_shadow,
                                reserve_prefix=shadow_interconnect_address is not None)
            shadow_commands = interconnect_commands(self.shadow_interconnect, current_shadow, shadow_interconnect_address)
            if shadow_interconnect_address is not None:
                verify_no_vrrp_interconnect_conflict(self.backend)
        if intent.revision in state["previous_revisions"]:
            return ApplyResult(revision, error="Controller revision was previously applied and needs current-state verification")
        if (wireguard_intent is not None and wireguard_intent.server is not None
                and port_forward_intent is not None and port_forward_intent.forward is not None):
            return ApplyResult(revision, error="Concurrent WireGuard and port forwarding are outside the verified profile")
        desired_dhcp, dhcp_commands = self._plan_dhcp(intent, dhcp_intent, networks, state["verified_dhcp"])
        desired_routes, route_commands = self._plan_routes(intent, route_intent, static_routes, state["verified_routes"])
        route_identities = static_route_identities(route_intent) if route_intent is not None else None
        if route_identities is not None:
            validate_static_route_identities(route_identities, desired_routes, self.route_scope)
        desired_dns, dns_commands = self._plan_dns(intent, dns_intent, forwarding, state["verified_dns"])
        desired_nat, nat_commands = self._plan_nat(intent, nat_intent, nat_rules, state["verified_nat"])
        desired_wg, wg_commands = self._plan_wireguard(
            intent, wireguard_intent, wg_interfaces, wg_guards, state["verified_wireguard"],
        )
        desired_forward, forward_commands = self._plan_port_forward(
            intent, port_forward_intent, destination_nat, forward_guards, state["verified_port_forward"],
        )
        desired_vlan, vlan_commands = self._plan_vlan(intent, vlan_intent, ethernet, state["verified_vlan"])
        desired_mdns, mdns_commands = self._plan_mdns(intent, mdns_intent, mdns, state["verified_mdns"])
        desired_ospf, ospf_commands = self._plan_ospf(
            intent, ospf_intent, ospf, ethernet, state["verified_ospf"], ospf_proof_key,
        )
        desired_bgp, bgp_commands = self._plan_bgp(intent.revision, bgp_intent, bgp, state.get("verified_bgp", {}), bgp_key)
        desired_ipsec, ipsec_commands = self._plan_ipsec(
            intent, ipsec_intent, ipsec, ipsec_guards, static_routes, state["verified_ipsec"],
        )
        desired_openvpn, openvpn_commands = self._plan_openvpn(
            intent, openvpn_intent, openvpn, openvpn_guards, state["verified_openvpn"],
        )
        desired_wan, wan_commands = self._plan_wan_default(
            intent, wan_intent, running, wan_default, state["verified_wan_default"], policy_route,
        )
        prepare_table = (
            self.policy_route_fib_command is not None and policy_route is None and state["verified_policy_route"] is None
            and desired_wan is not None and intent.revision != revision
            and isinstance(policy_route_intent, PolicyRouteIntent) and policy_route_intent.revision == intent.revision
            and policy_route_intent.destination in POLICY_ROUTE_DESTINATIONS
        )
        prepare_or_recover = prepare_table or "policy_table_setup" in state
        policy_running = prepare_policy_table(running)[0] if prepare_or_recover else running
        desired_policy_route, policy_route_commands = self._plan_policy_route(
            intent, policy_route_intent, policy_running, policy_route, state["verified_policy_route"],
            wan_active=desired_wan is not None,
        )
        desired_qos, qos_commands = self._plan_qos(intent, qos_intent, running, qos_limit, state["verified_qos"])
        if (qos is not None or desired_qos is not None) and any((
            desired_nat, desired_forward, desired_wan, policy_route, desired_policy_route,
            desired_ipsec, desired_openvpn, desired_wg,
        )):
            return ApplyResult(revision, error="QoS requires separate NAT, WAN failover, policy route and VPN revisions")
        if (wan_default is not None or desired_wan is not None) and any((
            desired_nat, desired_wg, desired_forward, desired_vlan, desired_ipsec, desired_ospf, desired_openvpn, desired_bgp,
        )):
            return ApplyResult(revision, error="Apply WAN failover separately from NAT, VPN, VLAN or dynamic routing changes")
        if desired_ipsec is not None and (nat_rules or desired_nat or desired_wg or desired_forward):
            return ApplyResult(revision, error="Concurrent source NAT, WireGuard or port forwarding are outside the verified IPsec profile")
        if desired_openvpn is not None and (nat_rules or desired_nat or desired_wg or desired_forward or desired_ipsec):
            return ApplyResult(revision, error="Concurrent NAT or another VPN is outside the verified OpenVPN profile")
        desired = {**desired_policy, "dhcp": desired_dhcp, "routes": desired_routes,
                   "dns": desired_dns, "nat": desired_nat, "wireguard": desired_wg, "port_forward": desired_forward,
                   "vlan": desired_vlan, "mdns": desired_mdns, "ospf": desired_ospf, "ipsec": desired_ipsec,
                   "openvpn": desired_openvpn, "wan_default": desired_wan, "policy_route": desired_policy_route,
                   "qos": desired_qos, "inspection_queue": desired_inspection_queue,
                   "shadow_interconnect": shadow_interconnect_address, "bgp": desired_bgp}
        if verify_unchanged is not None and current != desired:
            return ApplyResult(revision, error="Apply inspection mode and router configuration changes in separate revisions")
        desired_ipv4, desired_ipv6 = self._effective_policy_rules(desired_policy)
        self._verify_firewall_state_path(desired_ipv4, desired_ipv6)
        if (policy_route is not None or desired_policy_route is not None) and (
            read_policy_route_guard(running) != state.get("policy_route_guard", [])
        ):
            raise ValueError("The VyOS policy route guard differs from last verified ownership")
        commands = [
            *shadow_commands, *vlan_commands, *wg_commands, *forward_commands, *dhcp_commands, *route_commands,
            *dns_commands, *nat_commands, *mdns_commands, *ospf_commands, *ipsec_commands, *openvpn_commands,
            *wan_commands, *policy_route_commands, *qos_commands, *bgp_commands,
            *self._firewall_commands(current_policy, desired_policy),
        ]
        if plan_only:
            if bgp_commands:
                raise ValueError("Shadow Mode standby cannot provision a BGP change independently")
            if prepare_or_recover or policy_route is not None or desired_policy_route is not None or inspection_intent is not None:
                raise ValueError("Shadow Mode standby policy needs coordinated policy routing or inspection preparation")
            if current != desired and intent.revision == revision:
                raise ValueError("Controller reused a revision for different VyOS configuration")
            return commands, desired
        if prepare_or_recover:
            self._ensure_policy_route_table(state, running, requested=prepare_table)
        if policy_route is not None or desired_policy_route is not None:
            self._verify_policy_route(policy_route)
        active_routes = desired_routes | (desired_ipsec or {}).get("routes", {})
        if current == desired:
            if self.shadow_interconnect is not None or desired_bgp:
                self.commit_proof(phase="saved")
            known_ids = state.get("verified_route_identities")
            if intent.revision == revision and known_ids is not None and known_ids != route_identities:
                return ApplyResult(revision, error="Controller reused a revision for different static route identities")
            self._verify_routes(active_routes, previous_static=state["verified_routes"])
            if desired_ipv6:
                self._verify_ipv6_paths(desired_ipv6, self.backend.show_interfaces())
            if desired_wg is not None:
                self._verify_wireguard(desired_wg)
            if desired_ospf is not None:
                verify_ospf_runtime(self.ospf_scope, desired_ospf, self.backend.show_ipv4_ospf_interfaces())
            if verify_unchanged is not None:
                verify_unchanged()
            if desired_inspection_queue:
                self.inspection_controller.prepare_engine(inspection_intent)
            self._finish_stock_inspection(inspection_intent)
            self._set_policy_route_guard(state, [policy_route] if policy_route is not None else [], selector=policy_route)
            if intent.revision != revision or route_identities != known_ids:
                self._record_verified(state, intent.revision, current, route_identities=route_identities)
            return ApplyResult(intent.revision)
        if intent.revision == revision:
            return ApplyResult(revision, error="Controller reused a revision for different VyOS configuration")

        if self.commit_proof is not None:
            self.commit_proof(phase="saved")
        if desired_ipv6 and current_policy != desired_policy:
            self._verify_ipv6_paths(desired_ipv6, self.backend.show_interfaces())
        inspection_commands = ()
        if current["inspection_queue"] is not desired_inspection_queue:
            inspection_commands = self.stock_inspection_policy.commands(bool(current["inspection_queue"]), bool(desired_inspection_queue))
        if desired_inspection_queue:
            self.inspection_controller.prepare_engine(inspection_intent)
        self._verify_stock_inspection_queue(current["inspection_queue"])
        protected = sorted({destination for destination in (policy_route, desired_policy_route) if destination is not None})
        self._set_policy_route_guard(state, protected, selector=policy_route)
        pending = {"revision": intent.revision, **desired, "confirmed": False,
                   "retry_after": time.time() + 60 * _CONFIRM_MINUTES + 15}
        if route_identities is not None:
            pending["route_identities"] = route_identities
        if inspection_intent is not None:
            pending["inspection_mode"] = inspection_intent.mode
        state["pending"] = pending
        self._write_state(state, durable=bool(protected) or ospf_proof_key is not None or self.commit_proof is not None)
        try:
            self.backend.stage_configuration([*commands, *inspection_commands], confirm_minutes=_CONFIRM_MINUTES)
        except VyOSWriteError:
            if self.shadow_interconnect is not None:
                read_interconnect(self.backend, self.shadow_interconnect)
            self._read_firewall_policy(read_chains)
            self._read_stock_inspection_queue()
            self._read_dhcp_networks()
            self._read_static_routes()
            self._read_dns()
            self._read_nat()
            self._read_wireguard()
            self._read_guards()
            self._read_destination_nat()
            self._read_vlan_ethernet()
            self._read_mdns()
            self._read_ospf(ospf_proof_key)
            self._read_bgp(bgp_key)
            self._read_ipsec()
            self._read_openvpn()
            if self.wan_fib_command is not None or qos_commands:
                staged_running, _, _ = self._read_routing_configuration()
            if self.wan_fib_command is not None:
                read_failover_fib(self.wan_fib_command)
            if policy_route_commands:
                read_policy_route_fib(self.policy_route_fib_command)
            if qos_commands:
                read_qos_state(staged_running)
                read_qos_kernel(self.qos_kernel_command)
            return ApplyResult(revision, error="VyOS staging outcome is uncertain and awaits timed recovery")
        staged_fingerprint = self.commit_proof(phase="staged") if self.commit_proof is not None else None
        if bgp_commands and (not isinstance(staged_fingerprint, str) or re.fullmatch("[0-9a-f]{64}", staged_fingerprint) is None):
            raise ValueError("VyOS BGP changes require a verified staged configuration fingerprint")
        if self.shadow_interconnect is not None:
            if read_interconnect(self.backend, self.shadow_interconnect) != (shadow_interconnect_address, interconnect_other):
                raise ValueError("Staged Shadow Mode interconnect or adjacent port configuration differs from intent")
            verify_interconnect(self.backend, self.shadow_interconnect, shadow_interconnect_address)
            if shadow_interconnect_address is not None:
                verify_no_vrrp_interconnect_conflict(self.backend)
        wg_guards, forward_guards, ipsec_guards, openvpn_guards = self._read_guards()
        ethernet = self._read_vlan_ethernet()
        nat_readback = self._read_nat()
        static_readback = self._read_static_routes()
        if (
            self._read_firewall_policy(read_chains) != desired_policy
            or self._owned_dhcp(self._read_dhcp_networks()) != desired_dhcp
            or self._owned_routes(static_readback) != desired_routes
            or self._owned_dns(self._read_dns()) != desired_dns
            or self._owned_nat(nat_readback) != desired_nat
            or self._owned_wireguard(self._read_wireguard(), wg_guards) != desired_wg
            or self._owned_port_forward(self._read_destination_nat(), forward_guards) != desired_forward
            or self._owned_vlan(ethernet) != desired_vlan
            or self._owned_ipsec(self._read_ipsec(), ipsec_guards, static_readback) != desired_ipsec
            or self._read_openvpn() != desired_openvpn
            or bgp_checkpoint(self._read_bgp(bgp_key)) != desired_bgp
        ):
            return ApplyResult(revision, error="Staged VyOS read-back differs from intended configuration")
        self._verify_firewall_state_path(desired_ipv4, desired_ipv6)
        staged_running, staged_wan, staged_policy_route = self._read_routing_configuration()
        if self.wan_fib_command is not None:
            if staged_wan != desired_wan:
                return ApplyResult(revision, error="Staged WAN failover or NAT differs from the intended configuration")
            if staged_policy_route != desired_policy_route:
                return ApplyResult(revision, error="Staged policy route differs from the intended configuration")
            if wan_default != desired_wan:
                self._verify_wan_default(desired_wan)
            if policy_route is not None or desired_policy_route is not None:
                self._verify_policy_route(staged_policy_route)
                if self._observe_policy_route_guard(staged_running) != protected:
                    raise ValueError("The verified forwarding guard changed during VyOS policy provisioning")
        if self.qos_kernel_command is not None:
            staged_qos = read_qos_state(staged_running)
            if qos_checkpoint(staged_qos) != desired_qos:
                return ApplyResult(revision, error="Staged QoS read-back differs from the intended configuration")
            if qos is not None or desired_qos is not None:
                self._verify_qos(desired_qos)
        previous_routes = current["routes"] | (current["ipsec"] or {}).get("routes", {})
        self._verify_routes(active_routes, withdrawn=previous_routes.keys() - active_routes.keys(),
                            previous_static=current["routes"])
        detail = self.backend.show_interfaces()
        self._verify_ipv6_paths(desired_ipv6, detail)
        self._verify_wireguard(desired_wg, detail)
        self._verify_vlan(desired_vlan, ethernet, detail)
        self._verify_mdns(desired_mdns, self._read_mdns(), detail)
        self._verify_ospf(desired_ospf, self._read_ospf(ospf_proof_key), ethernet, detail)
        if desired_ipsec is not None:
            self._verify_vpn_guard_path("IPsec")
            verify_ipsec_guard_order(ipsec_guards, self.ipsec_guard_base)
            if nat_readback:
                raise ValueError("Source NAT overlaps the staged IPsec deployment")
        if desired_openvpn is not None:
            self._verify_vpn_guard_path("OpenVPN")
            verify_openvpn_guard_order(openvpn_guards, self.openvpn_guard)
            if nat_readback:
                raise ValueError("Source NAT overlaps the staged OpenVPN deployment")
        elif current["openvpn"] is not None:
            self._verify_openvpn_removed(detail)
        self._verify_stock_inspection_queue(desired_inspection_queue)
        if desired_inspection_queue:
            self.inspection_controller.verify_engine(inspection_intent)
        if staged_fingerprint is not None:
            if bgp_commands:
                previous_bgp = state.get("verified_bgp", {})
                self._refresh_bgp_filters(previous_bgp, desired_bgp)
                self._verify_bgp_import_policy(previous_bgp, desired_bgp)
            if self.commit_proof(phase="staged") != staged_fingerprint:
                raise ValueError("VyOS staged configuration changed during verification")
            pending["confirmation_sha256"] = staged_fingerprint
            self._write_state(state, durable=True)
        self.backend.confirm_configuration()
        pending["confirmed"] = True
        self._write_state(state, durable=bool(protected) or ospf_proof_key is not None or staged_fingerprint is not None)
        self._save_and_finish_policy_route(state, pending)
        if self.mdns_container is not None:
            self._verify_mdns(desired_mdns, self._read_mdns(), self.backend.show_interfaces())
        self._finish_stock_inspection(inspection_intent)
        self._record_verified(state, intent.revision, desired, route_identities=route_identities)
        return ApplyResult(intent.revision, changed=True)

    def _verify_openvpn_removed(self, interfaces):
        if self.openvpn_scope.interface in interface_details(interfaces):
            raise VyOSReadError("The withdrawn OpenVPN interface is still present on VyOS")


def normalize_ospf_policy(system_cfg, *, revision, schema, scope):
    if scope is None:
        return system_cfg, None
    ospf = decode_ospf_intent(system_cfg, revision=revision, scope=scope, **schema)
    document = json.loads(system_cfg)
    document["udapi"] = scrub_ospf_policy(document["udapi"], ospf)
    return json.dumps(document), ospf


def normalize_ipsec_policy(system_cfg, *, revision, schema, scope):
    if scope is None:
        return system_cfg, None
    ipsec = decode_ipsec_intent(system_cfg, revision=revision, scope=scope, expected_versions=selected_schema(**schema))
    document = json.loads(system_cfg)
    document["udapi"] = scrub_ipsec_policy(document["udapi"], ipsec)
    return json.dumps(document), ipsec


def normalize_scoped_policy(system_cfg, *, revision, schema, port_forward_scope=None, vlan_scope=None, mdns_scope=None):
    """Strip only exact generated projections before decoding adjacent managed scopes."""
    if vlan_scope is None and port_forward_scope is None and mdns_scope is None:
        return system_cfg, None, None, None
    document = json.loads(system_cfg)
    vlan = forward = mdns = None
    if mdns_scope is not None:
        mdns = decode_mdns_intent(system_cfg, revision=revision, scope=mdns_scope, **schema)
        document["udapi"] = scrub_mdns_policy(document["udapi"], mdns)
        system_cfg = json.dumps(document)
    if vlan_scope is not None:
        vlan = decode_vlan_intent(system_cfg, revision=revision, scope=vlan_scope, **schema)
        document["udapi"] = scrub_vlan_policy(document["udapi"], vlan, managed_mdns=mdns_scope is not None)
        system_cfg = json.dumps(document)
    if port_forward_scope is not None:
        forward = decode_port_forward_intent(
            system_cfg, revision=revision, scope=port_forward_scope, message_broker=schema["message_broker"],
            dns_forwarder=schema["dns_forwarder"], wireguard=schema["wireguard"],
        )
        document["udapi"] = port_forward_remainder(document["udapi"], forward)
        system_cfg = json.dumps(document)
    return system_cfg, vlan, forward, mdns


def unmanaged_config_fingerprint(
    system_cfg: str, *, revision: str, dhcp_scope: DhcpScope | None = None,
    broker_trust: BrokerTrust | None = None, route_scope: StaticRouteScope | None = None,
    dns_scope: DnsScope | None = None, nat_scope: NatScope | None = None,
    wireguard_scope: WireGuardScope | None = None, port_forward_scope: PortForwardScope | None = None,
    vlan_scope: VlanScope | None = None,
    mdns_scope: MdnsScope | None = None,
    ospf_scope: OspfScope | None = None,
    ipsec_scope: IpsecScope | None = None,
) -> str:
    """Fingerprint the portion of a verified snapshot outside the owned policy."""
    schema = {"message_broker": broker_trust is not None, "dns_forwarder": dns_scope is not None,
              "nat": nat_scope is not None or port_forward_scope is not None, "wireguard": wireguard_scope is not None}
    if mdns_scope is not None:
        system_cfg = normalize_mdns_service_version(system_cfg)
    system_cfg, _ = normalize_ospf_policy(system_cfg, revision=revision, schema=schema, scope=ospf_scope)
    system_cfg, _ = normalize_ipsec_policy(system_cfg, revision=revision, schema=schema, scope=ipsec_scope)
    decode_firewall_intent(system_cfg, revision=revision, **schema)
    system_cfg, _, _, _ = normalize_scoped_policy(
        system_cfg, revision=revision, schema=schema, port_forward_scope=port_forward_scope,
        vlan_scope=vlan_scope, mdns_scope=mdns_scope,
    )
    document = json.loads(system_cfg)
    udapi = document["udapi"]
    if wireguard_scope is not None:
        vpn = decode_wireguard_intent(
            system_cfg, revision=revision, scope=wireguard_scope, message_broker=schema["message_broker"],
            dns_forwarder=schema["dns_forwarder"], nat=schema["nat"],
        )
        udapi = document["udapi"] = scrub_wireguard_policy(udapi, vpn)
    owned = next(row for row in udapi["firewall/filter"] if row["config"]["name"] == "LAN_LAN")
    names = {name for rule in owned["rules"][:-1] for key in ("source", "destination") for name in rule[key]["sets"]}
    udapi["firewall/filter"].remove(owned)
    udapi["firewall/sets"] = [row for row in udapi["firewall/sets"] if row["identification"]["name"] not in names]
    dhcp_domain = None
    if dhcp_scope is not None:
        dhcp_intent = decode_dhcp_intent(system_cfg, revision=revision, scope=dhcp_scope)
        if dhcp_intent.server is not None:
            dhcp_domain = dhcp_intent.server.domain
        servers = udapi["services"]["dhcpServers"]
        udapi["services"]["dhcpServers"] = [row for row in servers if {"id": dhcp_scope.bridge} not in row["interfaces"]]
    if route_scope is not None:
        decode_route_intent(system_cfg, revision=revision, scope=route_scope, **schema)
        udapi["routes/static"] = []
    if dns_scope is not None:
        decode_dns_intent(system_cfg, revision=revision, scope=dns_scope,
                          message_broker=schema["message_broker"], nat=schema["nat"], wireguard=schema["wireguard"],
                          dhcp_domain=dhcp_domain)
        dns = udapi["services"]["dnsForwarder"]
        dns["hostRecords"] = outside_dns_records(dns["hostRecords"], dns_scope)
    if nat_scope is not None:
        decode_nat_intent(system_cfg, revision=revision, scope=nat_scope,
                          message_broker=schema["message_broker"], dns_forwarder=schema["dns_forwarder"],
                          wireguard=schema["wireguard"])
        udapi["firewall/nat"] = outside_nat_rules(udapi["firewall/nat"])
    if broker_trust is not None:
        decode_broker_provisioning(system_cfg, trust=broker_trust)
        rabbit = udapi["services"]["messageBroker"]["rabbitMq"]
        del rabbit["authentication"], rabbit["tls"]["clientCertificate"]
    canonical = json.dumps(document, sort_keys=True, separators=(",", ":"))
    if any(json.dumps(name) in canonical for name in names):
        raise ValueError("The managed firewall rule references a set shared by another policy")
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()
