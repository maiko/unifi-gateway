"""Read-only peer status for the pinned Enterprise Shadow Mode handshake."""

from ipaddress import IPv4Address, IPv4Interface, IPv4Network
import json
import re
from urllib.parse import urlsplit

from backends.vyos import VyOSReadError
from backends.vyos_failover import _invalid_constant, _run_helper, _unique_fields
from backends.vyos_wan_ping import decode_ping
from backends.vyos_ssh import vyos_ssh_command, vyos_ssh_host_fingerprint
from provisioners.uxg_enterprise_shadow import SHADOW_ADDRESSES
from provisioners.vyos_shadow_binding import ShadowManagementIdentity, _unicast_mac


SHADOW_STATUS_COMMAND = "shadow-mode-adopt"
_COMMAND_FIELDS = {"_type", "cmd", "action", "request_id", "is_secondary"}
_TASK_METADATA = {"_id", "device_id", "datetime", "time", "server_time_in_utc"}
_REQUEST_ID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}")
_ADDRESSES = tuple(map(IPv4Interface, SHADOW_ADDRESSES))
_REQUESTS = ("/bin/false uxg-shadow-peer-primary", "/bin/false uxg-shadow-peer-secondary")
_LAN_SOURCE_REQUEST = "/bin/false uxg-shadow-lan-source"
_LAN_PEER_REQUEST = "/bin/false uxg-shadow-lan-peer"
_ROUTE_FIELDS = {"dst", "dev", "prefsrc", "table", "protocol", "scope", "type", "flags", "metric"}


def decode_shadow_status_request(response):
    """Accept the single observed read action, with a canonical task UUID."""
    if (not isinstance(response, dict) or response.keys() - _TASK_METADATA != _COMMAND_FIELDS
            or response["_type"] != "cmd" or response["cmd"] != SHADOW_STATUS_COMMAND
            or response["action"] != "status" or type(response["is_secondary"]) is not bool
            or not isinstance(response["request_id"], str) or _REQUEST_ID.fullmatch(response["request_id"]) is None):
        raise ValueError("Unsupported Shadow Mode status command")
    return response["request_id"], response["is_secondary"]


def shadow_status_notification(request_id, reachable):
    return {
        "inform_as_notif": True,
        "notif_reason": "cmd",
        "notif_payload": {
            "event_string": SHADOW_STATUS_COMMAND,
            "request_id": request_id,
            "status": {"flags": {"peer_connection_test": {"ping": reachable is True}}},
        },
    }


class ShadowPeerProbe:
    """Bind the check to Enterprise port 2 and the same pinned management host as HTTPS."""

    def __init__(self, backend, ports, config):
        candidates = [port for port in ports if port.get("ifname") == "eth1" or port.get("port_idx") == 2]
        if len(candidates) != 1:
            raise ValueError("Shadow Mode requires one mapped Enterprise port 2")
        port, = candidates
        interface = port.get("realif", "")
        if (port.get("ifname") != "eth1" or port.get("port_idx") != 2 or port.get("type") not in {"lan", "lan2"}
                or not isinstance(interface, str) or re.fullmatch(r"eth[0-9]{1,11}", interface) is None
                or sum(row.get("realif") == interface for row in ports) != 1):
            raise ValueError("Shadow Mode requires a dedicated physical Enterprise port 2 mapping")
        settings = config["vyos_shadow"]
        self._config = config
        self._api_origin = config["vyos"]["api_url"].rstrip("/")
        host = urlsplit(self._api_origin).hostname
        port = settings.getint("ssh_port", 22)
        known_hosts = settings["ssh_known_hosts_file"]
        self._ssh_host_key = host, port, known_hosts
        self._ssh = vyos_ssh_command(host, port, settings["ssh_user"], settings["ssh_key_file"], known_hosts)
        self.interface = interface
        self._backend = backend
        self._lan_interfaces = tuple(row.get("realif") for row in ports if row.get("ifname") == "br0")

    def management_identity(self, *, require_adopted=True):
        """Bind this configured router to the inform identity and management pin."""
        mac = self._config.get("gateway", "lan_mac", fallback="")
        if (not _unicast_mac(mac) or self._config.get("gateway", "device", fallback="") != "UXGENT"
                or self._config.get("gateway", "platform", fallback="").strip().lower() != "vyos"
                or (require_adopted and not (
                    self._config.getboolean("gateway", "is_adopted", fallback=False)
                    and self._config.getboolean("gateway", "use_aes_gcm", fallback=False)
                ))):
            raise ValueError("Shadow Mode requires an adopted Enterprise AES-GCM enrollment")
        origin = self._backend.management_origin
        if origin != self._api_origin or self._config.get("vyos", "api_url", fallback="").rstrip("/") != origin:
            raise ValueError("Shadow Mode HTTPS backend does not match its configured management endpoint")
        host_fingerprint = vyos_ssh_host_fingerprint(*self._ssh_host_key)
        return ShadowManagementIdentity(mac, origin, host_fingerprint)

    def receipt_client(self, *, require_adopted=True):
        from provisioners.vyos_shadow_receipt import ShadowReceiptClient

        settings = self._config["vyos_shadow"]
        key_file = settings.get("receipt_ssh_key_file", "").strip()
        if not key_file or key_file == settings["ssh_key_file"]:
            raise ValueError("Shadow Mode activation reporting requires the dedicated receipt SSH key")
        _, port, known_hosts = self._ssh_host_key
        return ShadowReceiptClient(self.management_identity(require_adopted=require_adopted), port=port, user=settings["ssh_user"],
                                   key_file=key_file, known_hosts_file=known_hosts)

    def _owns_link(self, interface, local, peer):
        rows = self._backend.show_kernel_interfaces()
        owned = [row for row in rows if row.get("ifname") == interface]
        if (len(owned) != 1 or owned[0].get("master") is not None
                or not {"UP", "LOWER_UP"}.issubset(owned[0]["flags"])):
            return False
        assignments = {str(address.ip): [] for address in (local, peer)}
        for row in rows:
            for address in row["addr_info"]:
                if address.get("family") == "inet" and address.get("local") in assignments:
                    assignments[address["local"]].append((row["ifname"], address["prefixlen"]))
        return (assignments[str(local.ip)] == [(interface, local.network.prefixlen)]
                and not assignments[str(peer.ip)])

    def reachable(self, *, is_secondary):
        local, peer = (_ADDRESSES[1], _ADDRESSES[0]) if is_secondary else _ADDRESSES
        return self._peer_reachable(self.interface, local, peer, _REQUESTS[is_secondary])

    def lan_peer_reachable(self, local, peer):
        """Measure the forced-command peer using the locally mapped election LAN."""
        if (len(self._lan_interfaces) != 1 or self._lan_interfaces[0] == self.interface
                or not isinstance(local, IPv4Interface) or not isinstance(peer, IPv4Interface)
                or local.network != peer.network or local.ip == peer.ip):
            raise ValueError("Shadow Mode LAN readiness requires two distinct enrolled election addresses")
        return self._peer_reachable(self._lan_interfaces[0], local, peer, _LAN_PEER_REQUEST)

    def _peer_reachable(self, interface, local, peer, request):
        if not self._owns_link(interface, local, peer):
            return False
        body, status = _run_helper([*self._ssh[:-1], request], reader="VyOS Shadow peer probe", limit=4096)
        try:
            _, received, _ = decode_ping(body, interface, str(peer.ip), status, source=str(local.ip))
        except ValueError as error:
            raise VyOSReadError("VyOS Shadow peer probe did not return a matching measurement") from error
        return received > 0 and self._owns_link(interface, local, peer)

    def lan_preferred_source(self, network, *, interface, destination):
        """Read the kernel-selected source using the exact mapped LAN's connected IPv4 prefix."""
        network = IPv4Network(network)
        destination = IPv4Address(destination)
        if (not isinstance(interface, str) or re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,14}", interface) is None
                or interface == self.interface or (self._lan_interfaces and self._lan_interfaces != (interface,))
                or not 0 < network.prefixlen < 32 or destination not in network
                or (network.prefixlen < 31 and destination in (network.network_address, network.broadcast_address))):
            raise ValueError("Expected a mapped VyOS Shadow LAN and a host on its exact IPv4 prefix")

        reader = "VyOS Shadow LAN source probe"
        body, status = _run_helper([*self._ssh[:-1], _LAN_SOURCE_REQUEST], reader=reader, limit=4096)
        if status != 0:
            raise VyOSReadError(f"{reader} exited unsuccessfully")
        try:
            routes = json.loads(body.decode("utf-8"), object_pairs_hook=_unique_fields, parse_constant=_invalid_constant)
        except (ValueError, RecursionError):
            raise VyOSReadError(f"{reader} returned invalid JSON") from None
        try:
            return _lan_source_from_routes(routes, network, interface, destination)
        except ValueError as error:
            raise VyOSReadError(f"{reader} did not verify the connected IPv4 route") from error


def _lan_source_from_routes(data, network, interface, destination):
    if not isinstance(data, dict) or data.keys() != {"fib", "route"}:
        raise ValueError("Expected two kernel route observations")
    fib, route = data["fib"], data["route"]
    for row, target, fields in (
        (fib, network, _ROUTE_FIELDS),
        (route, destination, _ROUTE_FIELDS | {"uid", "cache"}),
    ):
        if (not isinstance(row, dict) or not row.keys() <= fields
                or row.get("dst") != str(target) or row.get("dev") != interface
                or row.get("type", "unicast") != "unicast" or row.get("flags", []) != []
                or row.get("table", "main") not in ("main", 254)):
            raise ValueError("Unexpected kernel route properties")

    source = route.get("prefsrc")
    if (fib.get("protocol") != "kernel" or fib.get("scope") != "link"
            or not isinstance(source, str) or fib.get("prefsrc") != source):
        raise ValueError("Expected a connected kernel route with matching preferred sources")
    address = IPv4Address(source)
    if (address not in network or address == destination
            or (network.prefixlen < 31 and address in (network.network_address, network.broadcast_address))):
        raise ValueError("Kernel selected a source outside the expected LAN hosts")
    return source
