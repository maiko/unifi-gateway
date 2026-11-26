"""Collect mapped interfaces and LAN clients from live VyOS operational state."""
import ast
from concurrent.futures import ThreadPoolExecutor
import ipaddress
import logging
import re
import time

from backends.vyos import VyOSBackend, VyOSReadError
from backends.vyos_wan_quality import configured_wan_probes
from gateway_profiles.uxg_wan_status import project_wan_durations

logger = logging.getLogger("unifi-gateway")

_INTERFACE = re.compile(r"^([^\s:@]+)(?:@[^\s:]+)?: <([^>]*)>[^\n]*", re.M)
_MAC = re.compile(r"^[ \t]+link/ether ([0-9a-f:]{17})(?:[ \t]|$)", re.I | re.M)
_IPV4 = re.compile(r"^[ \t]+inet (\S+)", re.M)
_IPV6 = re.compile(r"^[ \t]+inet6 (\S+)([^\n]*)", re.M)
_COUNTERS = re.compile(
    r"^[ \t]+(RX|TX):[ \t]+bytes[ \t]+packets[ \t]+errors[ \t]+dropped[^\n]*"
    r"\n[ \t]+(\d+)[ \t]+(\d+)[ \t]+(\d+)[ \t]+(\d+)",
    re.M,
)
_NEIGHBOR_COLUMNS = ("Address", "Interface", "Link layer address", "State")
_VALID_NEIGHBOR_STATES = {"REACHABLE", "STALE", "DELAY", "PROBE", "PERMANENT"}
_LEASE_COLUMNS = (
    "IP Address", "MAC address", "State", "Lease start", "Lease expiration",
    "Remaining", "Pool", "Hostname", "Origin",
)
_MAC_ADDRESS = re.compile(r"[0-9a-f]{2}(?::[0-9a-f]{2}){5}", re.I)
_UPTIME_COMPONENT = re.compile(r"([0-9]+)([ywdhms])")
# VyOS uses a 365.25-day year when formatting uptime.
_UPTIME_SECONDS = {"y": 31557600, "w": 604800, "d": 86400, "h": 3600, "m": 60, "s": 1}
_MAX_RATE_SAMPLE_GAP = 60
_CPU_STATES = {"us", "sy", "ni", "id", "wa", "hi", "si", "st"}
_CPU_FIELD = re.compile(r"\s*(\d{1,3}\.\d) ([a-z]{2})\s*")
_MEMORY_FIELD = re.compile(r"^(MemTotal|MemAvailable):[ \t]+(\d+)[ \t]+kB[ \t]*$", re.M)
_ETHERNET_NAME = re.compile(r"eth[0-9]+")
_LINK_SPEED = re.compile(r"^[ \t]*Speed:[ \t]+([0-9]{1,9})Mb/s[ \t]*$", re.M)
_LINK_DUPLEX = re.compile(r"^[ \t]*Duplex:[ \t]+(Full|Half)[ \t]*$", re.M)
_LINK_CARRIER = re.compile(r"^[ \t]*Link detected:[ \t]+yes[ \t]*$", re.M)


def interface_details(detail):
    headers = list(_INTERFACE.finditer(detail))
    return {
        header[1]: (header[2].split(","), detail[header.end():end])
        for header, end in zip(headers, [item.start() for item in headers[1:]] + [len(detail)])
    }


def interface_ipv4_addresses(body):
    return [ipaddress.IPv4Interface(address) for address in _IPV4.findall(body)]


def interface_ipv6_observations(body):
    return [address for address, attributes in _IPV6.findall(body)
            if not {"tentative", "dadfailed"}.intersection(attributes.split())]


def _table_rows(detail, columns):
    """Read tabulate's column positions, including empty cells in lease rows."""
    lines = detail.strip("\n\r").splitlines()
    if len(lines) < 2 or tuple(re.split(r"\s{2,}", lines[0].strip())) != columns:
        raise VyOSReadError("VyOS did not return the expected operational table")
    starts = [column.start() for column in re.finditer(r"-+", lines[1])]
    if len(starts) != len(columns):
        raise VyOSReadError("VyOS operational table has an unexpected column layout")
    boundaries = list(zip(starts, starts[1:] + [None]))
    for line in lines[2:]:
        if line.strip():
            yield tuple(line[start:end].strip() for start, end in boundaries)


def _client_mac(value):
    if not _MAC_ADDRESS.fullmatch(value) or int(value[:2], 16) & 1:
        return None
    if value == "00:00:00:00:00:00":
        return None
    return value.lower()


def _parse_uptime(detail):
    lines = detail.splitlines()
    if not lines or not lines[0].startswith("Uptime: "):
        raise VyOSReadError("VyOS did not return an uptime line")
    components = lines[0].removeprefix("Uptime: ").split()
    if not components and lines[1:3] != ["", "Load averages:"]:
        raise VyOSReadError("VyOS returned an incomplete uptime response")
    seconds = 0
    previous_unit = _UPTIME_SECONDS["y"] + 1
    for component in components:
        match = _UPTIME_COMPONENT.fullmatch(component)
        if match is None:
            raise VyOSReadError("VyOS returned an invalid uptime duration")
        unit = _UPTIME_SECONDS[match[2]]
        if unit >= previous_unit:
            raise VyOSReadError("VyOS returned uptime units out of order")
        seconds += int(match[1]) * unit
        previous_unit = unit
    return seconds


def _parse_cpu_usage(detail):
    rows = [row.removeprefix("%Cpu(s):") for row in detail.splitlines() if row.startswith("%Cpu(s):")]
    if len(rows) != 1:
        raise VyOSReadError("VyOS did not return one aggregate CPU state row")
    fields = [_CPU_FIELD.fullmatch(field) for field in rows[0].strip().split(",")]
    if len(fields) != len(_CPU_STATES) or any(field is None for field in fields):
        raise VyOSReadError("VyOS returned an invalid CPU state row")
    values = {field[2]: float(field[1]) for field in fields}
    if (values.keys() != _CPU_STATES or any(value > 100 for value in values.values())
            or not 99.5 <= sum(values.values()) <= 100.5):
        raise VyOSReadError("VyOS returned inconsistent CPU state percentages")
    busy = sum(value for name, value in values.items() if name not in {"id", "wa"})
    return min(100.0, round(busy, 1))


def _parse_memory_usage(detail):
    fields = _MEMORY_FIELD.findall(detail)
    counters = {name: int(value) for name, value in fields}
    total, available = counters.get("MemTotal"), counters.get("MemAvailable")
    if len(fields) != 2 or total is None or available is None or total <= 0 or available > total:
        raise VyOSReadError("VyOS returned invalid total and available memory")
    return round(100 * (total - available) / total, 1)


def _ethernet_media(detail, interface):
    if not detail.startswith(f"Settings for {interface}:\n") or not _LINK_CARRIER.search(detail):
        return {}
    result = {}
    speed = _LINK_SPEED.search(detail)
    if speed and int(speed[1]) > 0:
        result["speed"] = int(speed[1])
    duplex = _LINK_DUPLEX.search(detail)
    if duplex:
        result["full_duplex"] = duplex[1] == "Full"
    return result


class VyOSCollector:
    def __init__(self, config):
        self.ports = ast.literal_eval(config["gateway"]["ports"])
        options = config["vyos"]
        self.backend = VyOSBackend(
            api_url=options["api_url"], ca_file=options["ca_file"], key_file=options["key_file"],
        )
        self._wan_probes = {}
        self._wan_health_history = {}
        self._last_counters = None
        if "vyos_wan_health" in config:
            health = config["vyos_wan_health"]
            if health.getboolean("enabled", fallback=False):
                self._wan_probes = configured_wan_probes(health, self.ports, api_url=options["api_url"])
        self.data = {}
        self.update_oneshot()

    def update_oneshot(self):
        self.update()

    def update(self) -> None:
        self.data = {}
        unavailable = dict.fromkeys(self._wan_probes)
        if unavailable:
            self.data["wan_health"] = unavailable
        try:
            detail = self.backend.show_interfaces()
        except VyOSReadError as error:
            self._wan_health_history = {}
            self._last_counters = None
            logger.warning("VyOS interface telemetry unavailable: %s", error)
            return

        observed_at = time.monotonic()
        by_name = interface_details(detail)
        data = {"links": {}, "macs": {}, "ip": {}, "ipv4": {}, "ipv6": {}, "ifstat": {}}
        lan_names = {}
        lan_networks = {}
        for port in self.ports:
            name = port["ifname"]
            actual = by_name.get(port["realif"])
            if actual is None:
                continue
            flags, body = actual
            enabled = "UP" in flags
            data["links"][name] = {"enable": enabled, "up": enabled and "LOWER_UP" in flags}
            if data["links"][name]["up"] and _ETHERNET_NAME.fullmatch(port["realif"]):
                try:
                    media = _ethernet_media(self.backend.show_ethernet_physical(port["realif"]), port["realif"])
                except VyOSReadError as error:
                    logger.debug("VyOS Ethernet media unavailable for %s: %s", name, error)
                else:
                    if media:
                        data.setdefault("port_media", {})[name] = media
            mac = _MAC.search(body)
            if mac:
                data["macs"][name] = mac[1].lower()
            addresses = interface_ipv4_addresses(body)
            if addresses:
                primary = addresses[0]
                data["ip"][name] = {"address": str(primary.ip), "netmask": str(primary.netmask)}
                data["ipv4"][name] = [str(address) for address in addresses]
            ipv6 = []
            for address in interface_ipv6_observations(body):
                try:
                    ipv6.append(str(ipaddress.IPv6Interface(address)))
                except ValueError:
                    logger.warning("VyOS IPv6 interface telemetry returned an invalid address for %s", name)
            if ipv6:
                data["ipv6"][name] = ipv6
            if port["type"].lower() in {"lan", "lan2"}:
                lan_names[port["realif"]] = name
                lan_networks[name] = [address.network for address in addresses]
            counters = {
                f"{direction.lower()}_{field}": value
                for direction, *values in _COUNTERS.findall(body)
                for field, value in zip(("bytes", "packets", "errors", "dropped"), values)
            }
            if counters:
                data["ifstat"][name] = counters
        for version, read_routes in ((4, self.backend.show_ipv4_routes), (6, self.backend.show_ipv6_routes)):
            try:
                routes = self._mapped_routes(read_routes(), version=version)
            except (VyOSReadError, ValueError, TypeError, KeyError) as error:
                logger.warning("VyOS IPv%d route telemetry unavailable: %s", version, error)
            else:
                data.setdefault("routes", []).extend(routes)
        if lan_names:
            self._update_clients(data, lan_names, lan_networks)
        if unavailable:
            observations = self._read_wan_health(data["links"], unavailable)
            groups = {name: group for group, (name, _) in self._wan_probes.items()}
            availability = {
                name: observations[group]["received"] > 0
                for name, group in groups.items() if observations[group] is not None
            }
            durations, self._wan_health_history = project_wan_durations(
                availability, data["links"], self._wan_health_history, now=time.monotonic(), groups=groups,
            )
            data.update(wan_health=observations, wan_health_durations=durations)
        try:
            data["uptime"] = _parse_uptime(self.backend.show_uptime())
        except (VyOSReadError, ValueError) as error:
            logger.warning("VyOS uptime telemetry unavailable: %s", error)
        self._update_interface_rates(data, observed_at)
        self._update_system_stats(data)
        self.data = data

    def _update_system_stats(self, data):
        stats = {}
        for name, read, parse in (
            ("cpu", self.backend.show_cpu_states, _parse_cpu_usage),
            ("mem", self.backend.show_memory_detail, _parse_memory_usage),
        ):
            try:
                stats[name] = parse(read())
            except (VyOSReadError, ValueError) as error:
                logger.warning("VyOS %s telemetry unavailable: %s", name, error)
        if stats:
            data["system_stats"] = stats

    def _update_interface_rates(self, data, observed_at):
        uptime = data.get("uptime")
        previous = self._last_counters
        self._last_counters = None
        if uptime is None:
            return

        current = {
            name: (data["macs"].get(name), int(counters["rx_bytes"]), int(counters["tx_bytes"]))
            for name, counters in data["ifstat"].items()
            if data["links"][name]["up"] and {"rx_bytes", "tx_bytes"} <= counters.keys()
        }
        self._last_counters = (observed_at, uptime, current)
        if previous is None:
            return
        prior_at, prior_uptime, prior_counters = previous
        elapsed = observed_at - prior_at
        if not 0 < elapsed <= _MAX_RATE_SAMPLE_GAP or uptime < prior_uptime:
            return

        for name, (mac, rx_bytes, tx_bytes) in current.items():
            old = prior_counters.get(name)
            if old is None or mac != old[0] or rx_bytes < old[1] or tx_bytes < old[2]:
                continue
            data["ifstat"][name].update(
                rx_rate=8 * int((rx_bytes - old[1]) / elapsed),
                tx_rate=8 * int((tx_bytes - old[2]) / elapsed),
            )

    def _read_wan_health(self, links, observations):
        active = {
            group: probe for group, (name, probe) in self._wan_probes.items() if links.get(name, {}).get("up")
        }
        if active:
            with ThreadPoolExecutor(max_workers=len(active), thread_name_prefix="vyos-wan-probe") as executor:
                requests = {group: executor.submit(probe.read) for group, probe in active.items()}
                for group, request in requests.items():
                    try:
                        observations[group] = request.result()
                    except VyOSReadError as error:
                        logger.warning("VyOS %s quality telemetry unavailable: %s", group, error)
        return observations

    def _update_clients(self, data, lan_names, lan_networks):
        sources = (
            ("IPv4", self.backend.show_ipv4_neighbors, ipaddress.IPv4Address),
            ("IPv6", self.backend.show_ipv6_neighbors, ipaddress.IPv6Address),
        )
        for label, read, address_type in sources:
            try:
                fetched = list(self._mapped_neighbors(read(), lan_names, address_type))
            except (VyOSReadError, ValueError) as error:
                logger.warning("VyOS %s neighbor telemetry unavailable: %s", label, error)
                continue
            neighbors = data.setdefault("neighbors", {})
            for name, neighbor in fetched:
                neighbors.setdefault(name, []).append(neighbor)
        try:
            data["dhcp_leases"] = self._mapped_leases(self.backend.show_dhcpv4_leases(), lan_networks)
        except (VyOSReadError, ValueError) as error:
            logger.warning("VyOS DHCPv4 lease telemetry unavailable: %s", error)

    @staticmethod
    def _mapped_neighbors(detail, lan_names, address_type):
        for address, interface, link_address, state in _table_rows(detail, _NEIGHBOR_COLUMNS):
            name = lan_names.get(interface)
            mac = _client_mac(link_address)
            if name and mac and state in _VALID_NEIGHBOR_STATES:
                yield name, {"ip": str(address_type(address)), "mac": mac, "state": state}

    @staticmethod
    def _mapped_leases(detail, lan_networks):
        if detail.strip() == "DHCP server is not configured":
            return []
        leases = []
        for row in _table_rows(detail, _LEASE_COLUMNS):
            address, link_address, state, *_, hostname, _origin = row
            mac = _client_mac(link_address)
            if state != "active" or mac is None:
                continue
            ip = ipaddress.IPv4Address(address)
            matching_ports = [
                name for name, networks in lan_networks.items() if any(ip in network for network in networks)
            ]
            if len(matching_ports) != 1:
                continue
            lease = {"ip": str(ip), "mac": mac, "ifname": matching_ports[0]}
            if hostname and hostname not in {"-", "*"}:
                lease["hostname"] = hostname
            leases.append(lease)
        return leases

    def _mapped_routes(self, routes, *, version):
        names = {port["realif"]: port["ifname"] for port in self.ports}
        protocol_types = {"connected": "C>*", "static": "S>*"}
        mapped = []
        for prefix, candidates in routes.items():
            for route in candidates:
                route_type = protocol_types.get(route.get("protocol"))
                if not route_type or route.get("table") != 254:
                    continue
                if route.get("selected") is not True or route.get("installed") is not True:
                    continue
                hops = [
                    hop for hop in route["nexthops"]
                    if hop.get("active") is True and hop.get("fib") is True
                ]
                if not hops or any(hop.get("interfaceName") not in names for hop in hops):
                    continue
                network = ipaddress.ip_network(prefix)
                if network.version != version:
                    raise ValueError("Route prefix has the wrong address family")
                next_hops = []
                for hop in hops:
                    entry = {"intf": names[hop["interfaceName"]], "t": route_type}
                    if "ip" in hop:
                        gateway = ipaddress.ip_address(hop["ip"])
                        if gateway.version != version:
                            raise ValueError("Route gateway has the wrong address family")
                        entry["via"] = str(gateway)
                    if route_type == "S>*":
                        entry["metric"] = f'{int(route["distance"])}/{int(route["metric"])}'
                    next_hops.append(entry)
                mapped.append({"pfx": str(network), "nh": next_hops})
        return mapped
