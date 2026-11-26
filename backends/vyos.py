"""Certificate-verified access to the VyOS management API."""
from ipaddress import IPv4Address, IPv6Address, ip_address, ip_network
import json
from pathlib import Path
import re
import ssl
from urllib.parse import urlencode, urlsplit
from urllib.request import (
    HTTPRedirectHandler,
    HTTPSHandler,
    ProxyHandler,
    Request,
    build_opener,
)


class VyOSReadError(RuntimeError):
    """VyOS did not return a usable operational snapshot."""


class VyOSWriteError(RuntimeError):
    """A configuration operation lacked a successful response."""


_STATIC_TABLE_ROW = re.compile(r"S>\*\s+(\S+)\s+\[([0-9]+)/([0-9]+)\]\s+(.+)")
_STATIC_TABLE_CONTINUATION = re.compile(r"\s+\*\s+(.+)")
_STATIC_TABLE_HOP = re.compile(r"(.+), weight ([1-9][0-9]{0,2})(?:, [0-9:wdhms]+)?")


def _parse_static_table_hop(value, version):
    match = _STATIC_TABLE_HOP.fullmatch(value)
    if match is None or int(match[2]) > 255:
        raise VyOSReadError("VyOS returned an unsupported installed static table nexthop")
    path, weight = match[1], int(match[2])
    hop = {"active": True, "fib": True, "weight": weight}
    if path == "unreachable (blackhole)":
        return {**hop, "blackhole": True}
    subject, separator, interface = path.partition(", ")
    if not separator or re.fullmatch(r"[A-Za-z0-9_.-]{1,15}", interface) is None:
        raise VyOSReadError("VyOS returned an invalid static table egress")
    hop["interfaceName"] = interface
    if subject == "is directly connected":
        return {**hop, "directlyConnected": True}
    if not subject.startswith("via "):
        raise VyOSReadError("VyOS returned an unsupported installed static table nexthop")
    try:
        gateway = ip_address(subject[4:])
    except ValueError as error:
        raise VyOSReadError("VyOS returned an invalid static table gateway") from error
    if gateway.version != version or str(gateway) != subject[4:]:
        raise VyOSReadError("VyOS returned an inconsistent static table gateway")
    return {**hop, "ip": str(gateway)}


def _parse_static_route_table(text, *, version, table):
    if not text.strip():
        return {}
    lines = text.splitlines()
    headers = [(index, line) for index, line in enumerate(lines) if re.match(r"IPv[46] .*table", line)]
    if len(headers) != 1 or headers[0][1] != f"IPv{version} unicast table {table}:":
        raise VyOSReadError("VyOS returned a different or missing route table identity")
    items = {}
    last_hops = None
    for line in lines[headers[0][0] + 1:]:
        if continuation := _STATIC_TABLE_CONTINUATION.fullmatch(line):
            if last_hops is not None:
                last_hops.append(_parse_static_table_hop(continuation[1], version))
            continue
        last_hops = None
        if not line.startswith("S>*"):
            continue
        match = _STATIC_TABLE_ROW.fullmatch(line)
        if match is None:
            raise VyOSReadError("VyOS returned an unsupported installed static table row")
        prefix, distance, metric, path = match.groups()
        try:
            network = ip_network(prefix)
        except ValueError as error:
            raise VyOSReadError("VyOS returned an invalid static table destination") from error
        if network.version != version or str(network) != prefix or prefix in items or not 1 <= int(distance) < 255:
            raise VyOSReadError("VyOS returned an inconsistent installed static table row")
        last_hops = [_parse_static_table_hop(path, version)]
        items[prefix] = [{
            "protocol": "static", "table": table, "vrfId": 0, "vrfName": "default",
            "prefix": prefix, "prefixLen": network.prefixlen, "distance": int(distance), "metric": int(metric),
            "selected": True, "installed": True, "nexthops": last_hops,
        }]
    return items


class _NoRedirects(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise OSError("VyOS API redirected a management request")


class VyOSBackend:
    def __init__(self, *, api_url, ca_file, key_file):
        url = urlsplit(api_url)
        if (
            url.scheme != "https" or not url.hostname or url.username is not None
            or url.path not in ("", "/") or url.query or url.fragment
        ):
            raise ValueError("VyOS api_url must be an HTTPS origin")
        self._origin = f"https://{url.netloc}"
        self._key = Path(key_file).read_text(encoding="utf-8").strip()
        if not self._key:
            raise ValueError("VyOS API key file is empty")
        if not ca_file:
            raise ValueError("VyOS ca_file is required")
        self._opener = build_opener(
            ProxyHandler({}),
            HTTPSHandler(context=ssl.create_default_context(cafile=ca_file)),
            _NoRedirects(),
        )

    @property
    def management_origin(self):
        return self._origin

    def show_interfaces(self):
        return self._show(["interfaces", "detail"])

    def show_vrrp_detail(self):
        return self._show(["vrrp", "detail"])

    def show_kernel_interfaces(self):
        try:
            rows = json.loads(self._show(["interfaces", "kernel", "json"]))
        except ValueError as error:
            raise VyOSReadError("VyOS did not return JSON kernel interfaces") from error
        if not isinstance(rows, list):
            raise VyOSReadError("VyOS returned invalid kernel interfaces")
        for row in rows:
            if (not isinstance(row, dict) or not isinstance(row.get("ifname"), str)
                    or not isinstance(row.get("flags"), list) or any(not isinstance(flag, str) for flag in row["flags"])
                    or not isinstance(row.get("addr_info"), list)):
                raise VyOSReadError("VyOS returned an invalid kernel interface")
            for address in row["addr_info"]:
                if (not isinstance(address, dict) or (address.get("family") == "inet"
                        and (not isinstance(address.get("local"), str) or type(address.get("prefixlen")) is not int))):
                    raise VyOSReadError("VyOS returned an invalid kernel address")
        return rows

    def show_ethernet_physical(self, interface):
        if not isinstance(interface, str) or re.fullmatch(r"eth[0-9]+", interface) is None:
            raise ValueError("VyOS physical status requires a base Ethernet interface")
        return self._show(["interfaces", "ethernet", interface, "physical"])

    def show_ipv4_neighbors(self):
        return self._show(["ip", "neighbors"])

    def show_ipv6_neighbors(self):
        return self._show(["ipv6", "neighbors"])

    def show_ipsec_connections(self):
        return self._show(["vpn", "ipsec", "connections"])

    def show_ipsec_sas(self):
        return self._show(["vpn", "ipsec", "sa"])

    def ping_ipv4_once(self, address):
        if not isinstance(address, IPv4Address):
            raise ValueError("VyOS probe requires a validated IPv4 address")
        data = self._request("ping", {"op": "ping", "host": str(address), "count": 1}, VyOSReadError)
        if isinstance(data, str):
            for line in data.splitlines():
                match = re.fullmatch(r"1 packets transmitted, ([01]) received, .*", line)
                if match:
                    return match[1] == "1"
        raise VyOSReadError("VyOS did not return the IPv4 probe packet summary")

    def show_ipv4_ospf_neighbors(self):
        try:
            neighbors = json.loads(self._show(["ip", "ospf", "neighbor", "json"]))
        except ValueError as error:
            raise VyOSReadError("VyOS API did not return JSON OSPF neighbors") from error
        if not isinstance(neighbors, dict):
            raise VyOSReadError("VyOS API did not return an OSPF neighbor table")
        return neighbors

    def show_ipv4_ospf_interfaces(self):
        try:
            state = json.loads(self._show(["ip", "ospf", "interface", "json"]))
        except ValueError as error:
            raise VyOSReadError("VyOS API did not return JSON OSPF interface state") from error
        if not isinstance(state, dict) or not isinstance(state.get("interfaces"), dict):
            raise VyOSReadError("VyOS API did not return OSPF interface state")
        return state

    def show_dhcpv4_leases(self):
        return self._show(["dhcp", "server", "leases"])

    def show_uptime(self):
        return self._show(["system", "uptime"])

    def show_cpu_states(self):
        return self._show(["system", "processes", "extensive"])

    def show_memory_detail(self):
        return self._show(["system", "memory", "detail"])

    def has_mdns_listener(self):
        rows = self._show(["system", "connections", "udp"]).strip().splitlines()
        if not rows or rows[0].split() != ["State", "Recv-Q", "Send-Q", "Local", "Address:Port", "Peer", "Address:Port"]:
            raise VyOSReadError("VyOS did not return the expected UDP socket table")
        ports = []
        for row in rows[1:]:
            fields = row.split()
            if len(fields) != 5 or ":" not in fields[3]:
                raise VyOSReadError("VyOS returned an invalid UDP socket table row")
            ports.append(fields[3].rsplit(":", 1)[1].lower())
        return "5353" in ports or "mdns" in ports

    def mdns_multicast_interfaces(self):
        rows = self._show(["ip", "groups"]).strip().splitlines()
        headings = [index for index, row in enumerate(rows)
                    if row.strip() in {"IPv4 Group Memberships", "IPv6/IPv4 Group Memberships"}]
        if len(headings) != 1:
            raise VyOSReadError("VyOS did not return the expected IPv4 multicast memberships")
        table = rows[headings[0] + 1:]
        if (len(table) < 2 or table[0].split() != ["Interface", "RefCnt", "Group"]
                or table[1].split() != ["---------------", "------", "---------------------"]):
            raise VyOSReadError("VyOS returned an invalid multicast membership table")
        memberships = set()
        for row in table[2:]:
            match = re.fullmatch(r"([A-Za-z0-9_.-]{1,15})\s+[1-9][0-9]*\s+([0-9A-Fa-f:.]+)", row.strip())
            if match is None:
                raise VyOSReadError("VyOS returned an invalid IPv4 multicast membership row")
            try:
                if not ip_address(match[2]).is_multicast:
                    raise ValueError
            except ValueError as error:
                raise VyOSReadError("VyOS returned an invalid multicast group address") from error
            if match[2] == "224.0.0.251":
                memberships.add(match[1])
        return memberships

    def show_containers(self):
        return self._show_container_inventory(["container", "json"])

    def show_container_images(self):
        return self._show_container_inventory(["container", "image", "json"])

    def _show_container_inventory(self, path):
        try:
            rows = json.loads(self._show(path))
        except ValueError as error:
            raise VyOSReadError("VyOS did not return JSON container inventory") from error
        if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
            raise VyOSReadError("VyOS returned an invalid container inventory")
        return rows

    def show_ipv4_routes(self):
        return self._show_routes("ip")

    def show_ipv6_routes(self):
        return self._show_routes("ipv6")

    def soft_refresh_bgp_ipv4(self, peer, *, direction):
        """Reapply IPv4 policy for one configured peer through the stock reset endpoint."""
        self._soft_refresh_bgp(peer, "ipv4", direction)

    def soft_refresh_bgp_ipv6(self, peer, *, direction):
        """Reapply IPv6 policy for one configured peer through the stock reset endpoint."""
        self._soft_refresh_bgp(peer, "ipv6", direction)

    def _soft_refresh_bgp(self, peer, family, direction):
        if not isinstance(peer, IPv4Address) and (
            not isinstance(peer, IPv6Address) or peer.scope_id or peer.ipv4_mapped or peer.is_link_local
        ):
            raise ValueError("BGP soft refresh requires an IPv4 or unscoped IPv6 peer")
        if direction not in ("in", "out"):
            raise ValueError("BGP soft refresh requires an in or out direction")
        path = ["bgp", family, str(peer), "soft", direction]
        result = self._request("reset", {"op": "reset", "path": path}, VyOSWriteError)
        if not isinstance(result, str) or result.strip():
            raise VyOSWriteError("VyOS did not verify the requested BGP soft refresh")

    def configured_static_route_tables(self):
        config = self.read_config(["protocols", "static", "table"])
        if config is None:
            return {}
        if not isinstance(config, dict) or config.keys() != {"table"} or not isinstance(config["table"], dict):
            raise VyOSReadError("VyOS returned an invalid static route table configuration")
        tables = {}
        for name, node in config["table"].items():
            if (not isinstance(name, str) or re.fullmatch(r"[1-9][0-9]{0,2}", name) is None
                    or not 1 <= int(name) <= 200 or not isinstance(node, dict)):
                raise VyOSReadError("VyOS returned an invalid configured static table identifier")
            families = []
            for version, key in ((4, "route"), (6, "route6")):
                configured = node.get(key, {})
                if not isinstance(configured, dict):
                    raise VyOSReadError("VyOS returned an invalid static table route family")
                if configured:
                    families.append(version)
            if families:
                tables[int(name)] = tuple(families)
        return tables

    def show_static_route_table(self, table, *, version):
        if type(table) is not int or not 1 <= table <= 200 or version not in (4, 6):
            raise ValueError("VyOS static route table read requires table 1–200 and an IP family")
        family = "ip" if version == 4 else "ipv6"
        return _parse_static_route_table(self._show([family, "route", "table", str(table)]), version=version, table=table)

    def _show_routes(self, family):
        try:
            routes = json.loads(self._show([family, "route", "json"]))
        except ValueError as error:
            raise VyOSReadError("VyOS API did not return JSON routes") from error
        if not isinstance(routes, dict):
            raise VyOSReadError("VyOS API did not return a route table")
        return routes

    def read_config(self, path):
        exists = self._request("retrieve", {"op": "exists", "path": path}, VyOSReadError)
        if exists is False:
            return None
        if exists is not True:
            raise VyOSReadError("VyOS retrieve did not return a path existence result")
        return self._read_tree(path)

    def read_complete_configuration(self):
        return self._read_tree([])

    def _read_tree(self, path):
        config = self._request("retrieve", {"op": "showConfig", "path": path}, VyOSReadError)
        if not isinstance(config, dict):
            raise VyOSReadError("VyOS retrieve did not return a configuration subtree")
        return config

    def stage_configuration(self, commands, *, confirm_minutes):
        """Commit one timed batch. A failed response requires read-back before retrying."""
        if not commands or type(confirm_minutes) is not int or confirm_minutes < 1:
            raise ValueError("A staged VyOS configuration requires commands and a positive confirmation timeout")
        self._request("configure", {"commands": commands, "confirm_time": confirm_minutes}, VyOSWriteError, timeout=30)

    def confirm_configuration(self):
        result = self._request("config-file", {"op": "confirm"}, VyOSWriteError)
        if not isinstance(result, str) or result.strip() not in {"Reload timer stopped", "Reboot timer stopped"}:
            raise VyOSWriteError("VyOS did not acknowledge an active commit-confirm timer")

    def save_configuration(self):
        self._request("config-file", {"op": "save"}, VyOSWriteError)

    def reboot(self):
        self._request("reboot", {"op": "reboot", "path": ["now"]}, VyOSWriteError)

    def _show(self, path):
        data = self._request("show", {"op": "show", "path": path}, VyOSReadError)
        if not isinstance(data, str):
            raise VyOSReadError("VyOS show did not return operational data")
        return data

    def _request(self, endpoint, command, error_type, *, timeout=8):
        form = urlencode({
            "key": self._key,
            "data": json.dumps(command),
        }).encode("utf-8")
        request = Request(f"{self._origin}/{endpoint}", data=form)
        max_bytes = 4 * 1024 * 1024
        try:
            with self._opener.open(request, timeout=timeout) as response:
                body = response.read(max_bytes + 1)
            if len(body) > max_bytes:
                raise error_type(f"VyOS {endpoint} response exceeds the size limit")
            payload = json.loads(body)
        except (OSError, ValueError) as error:
            raise error_type(f"VyOS {endpoint} request failed") from error
        if (
            not isinstance(payload, dict) or payload.get("success") is not True
            or "data" not in payload
        ):
            raise error_type(f"VyOS {endpoint} did not return a successful response")
        return payload["data"]
