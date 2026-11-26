"""Plan one VyOS OpenVPN client and verify ownership without retaining its private keys."""

from base64 import b64decode, b64encode
from dataclasses import dataclass, field
from hashlib import sha256
from ipaddress import IPv4Address, IPv4Interface
import re

from collectors.vyos import interface_ipv4_addresses
from provisioners.uxg_openvpn import OpenVpnClientIntent, valid_openvpn_server_name


_PKI_NAME = re.compile(r"[A-Za-z][A-Za-z0-9_-]{0,31}")
_CREDENTIAL = re.compile(r"[!-~]{1,128}")
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
_PASSWORD_PATH = ("authentication", "password")
_USERNAME_PATH = ("authentication", "username")
_SECRET_FIELDS = {"username", "password", "ca", "certificate", "private_key"}


class OpenVpnPlanError(ValueError):
    """The OpenVPN client configuration or ownership is outside the approved scope."""


@dataclass(frozen=True, slots=True)
class OpenVpnScope:
    server_name: str
    interface: str = "vtun246"
    wan_interface: str = "eth3.210"
    local_address: str = "198.18.210.1"
    remote_host: str = "198.18.210.2"
    remote_ports: tuple[int, ...] = (19443, 19444)
    tunnel_cidr: str = "172.29.94.2/29"
    tunnel_peer: str = "172.29.94.1"
    ca_name: str = "UNIFI-OPENVPN-CA"
    certificate_name: str = "UNIFI-OPENVPN-CLIENT"

    def __post_init__(self):
        if (
            (
                self.interface, self.wan_interface, self.local_address, self.remote_host,
                self.remote_ports, self.tunnel_cidr, self.tunnel_peer,
            ) != (
                "vtun246", "eth3.210", "198.18.210.1", "198.18.210.2",
                (19443, 19444), "172.29.94.2/29", "172.29.94.1",
            )
            or not valid_openvpn_server_name(self.server_name)
            or any(
                type(name) is not str or not _PKI_NAME.fullmatch(name)
                for name in (self.ca_name, self.certificate_name)
            )
            or self.ca_name == self.certificate_name
        ):
            raise OpenVpnPlanError("OpenVPN scope differs from the supported endpoints and certificate identities")

    @property
    def wan_cidr(self) -> str:
        return f"{self.local_address}/30"


OpenVpnState = dict


@dataclass(frozen=True, slots=True)
class OpenVpnPlan:
    commands: tuple[dict, ...] = field(repr=False)
    expected: OpenVpnState | None


def _paths(scope):
    return {
        "interface": ("interfaces", "openvpn", scope.interface),
        "ca": ("pki", "ca", scope.ca_name),
        "certificate": ("pki", "certificate", scope.certificate_name),
    }


def _static_interface(scope):
    tunnel = IPv4Interface(scope.tunnel_cidr)
    return {
        "mode": "client",
        "device-type": "tun",
        "protocol": "udp",
        "ip-version": "ipv4",
        "remote-host": scope.remote_host,
        "hash": "sha256",
        "tls": {
            "ca-certificate": scope.ca_name,
            "certificate": scope.certificate_name,
            "tls-version-min": "1.2",
        },
        "encryption": {"data-ciphers": "aes256gcm"},
        # A TUN has no MAC for VyOS to use when removing an EUI-64 address.
        "ipv6": {"disable-forwarding": {}},
        "openvpn-option": [
            f"--bind-dev {scope.wan_interface}",
            f"--verify-x509-name {scope.server_name} name",
            "--remote-cert-tls server",
            "--auth-nocache",
            "--allow-compression no",
            "--topology subnet",
            f"--ifconfig {tunnel.ip} {tunnel.netmask}",
            "--route-nopull",
            "--route-noexec",
            "--pull-filter ignore ifconfig",
            "--pull-filter ignore topology",
            "--pull-filter ignore route",
            "--pull-filter ignore redirect-",
            "--pull-filter ignore dhcp-option",
            "--pull-filter ignore dns",
            "--pull-filter ignore bind-dev",
        ],
    }


def _value_at(tree, path):
    for key in path:
        if type(tree) is not dict:
            raise OpenVpnPlanError("Invalid VyOS OpenVPN configuration snapshot")
        if key not in tree:
            return None, False
        tree = tree[key]
    return tree, True


def _references_reserved_pki(tree, paths, names):
    pending = [((), tree)]
    while pending:
        path, value = pending.pop()
        if isinstance(value, dict):
            for key, child in value.items():
                child_path = (*path, key)
                if child_path in paths:
                    continue
                if key in names:
                    return True
                pending.append((child_path, child))
        elif isinstance(value, list):
            pending.extend((path, child) for child in value)
        elif isinstance(value, str) and value in names:
            return True
    return False


def _one_value(value):
    return value[0] if type(value) is list and len(value) == 1 else value


def _normalize_interface(tree, scope):
    expected = _static_interface(scope)
    if type(tree) is not dict or tree.keys() != expected.keys() | {"remote-port", "authentication"}:
        raise OpenVpnPlanError("Unexpected VyOS OpenVPN interface configuration")
    public = {key: tree[key] for key in expected}
    expected_options = set(expected.pop("openvpn-option"))
    options = public.pop("openvpn-option")
    if (
        type(options) is not list
        or any(type(option) is not str for option in options)
        or len(options) != len(expected_options)
        or set(options) != expected_options
    ):
        raise OpenVpnPlanError("Unexpected VyOS OpenVPN interface options")
    for branch, key in (("tls", "ca-certificate"), ("encryption", "data-ciphers")):
        node = public.get(branch)
        if type(node) is not dict or key not in node:
            raise OpenVpnPlanError("Unexpected VyOS OpenVPN interface configuration")
        public[branch] = {**node, key: _one_value(node[key])}
    public["remote-host"] = _one_value(public["remote-host"])
    if public != expected or tree["remote-port"] not in tuple(map(str, scope.remote_ports)):
        raise OpenVpnPlanError("Unexpected VyOS OpenVPN interface configuration")
    auth = tree["authentication"]
    if type(auth) is not dict or auth.keys() != {"username", "password"}:
        raise OpenVpnPlanError("Unexpected VyOS OpenVPN authentication configuration")
    return int(tree["remote-port"]), auth


def _credential(value):
    if type(value) is not str or not _CREDENTIAL.fullmatch(value):
        raise OpenVpnPlanError("Unsupported OpenVPN credential representation")
    return value.encode("ascii")


def _base64_material(value):
    if type(value) is str and 0 < len(value) <= 16_384:
        try:
            raw = b64decode(value, validate=True)
            if raw and b64encode(raw).decode("ascii") == value:
                return raw
        except ValueError:
            pass
    raise OpenVpnPlanError("Unsupported OpenVPN key or certificate representation")


def _pem_body(value, label):
    if type(value) is not bytes or not 0 < len(value) <= 16_384:
        raise OpenVpnPlanError("Unsupported OpenVPN key or certificate representation")
    try:
        lines = value.decode("ascii").splitlines()
    except UnicodeError:
        raise OpenVpnPlanError("Unsupported OpenVPN key or certificate representation") from None
    if (
        len(lines) < 3
        or lines[0] != f"-----BEGIN {label}-----"
        or lines[-1] != f"-----END {label}-----"
        or any(re.fullmatch(r"[A-Za-z0-9+/=]{1,64}", line) is None for line in lines[1:-1])
    ):
        raise OpenVpnPlanError("Unsupported OpenVPN key or certificate representation")
    body = "".join(lines[1:-1])
    _base64_material(body)
    return body


def _state(scope, port, material):
    return {
        "resources": [scope.interface, scope.ca_name, scope.certificate_name],
        "remote_port": port,
        "digests": {
            name: "sha256:" + sha256(body).hexdigest()
            for name, body in material.items()
        },
    }


def read_openvpn_state(config_tree: dict, scope: OpenVpnScope) -> OpenVpnState | None:
    """Check the complete running tree and return only exact owned state and digests."""
    if type(config_tree) is not dict or not isinstance(scope, OpenVpnScope):
        raise OpenVpnPlanError("OpenVPN needs the complete VyOS configuration tree and scope")
    paths = _paths(scope)
    trees = {name: _value_at(config_tree, path) for name, path in paths.items()}
    present = {name for name, (_, exists) in trees.items() if exists}
    if _references_reserved_pki(config_tree, set(paths.values()), {scope.ca_name, scope.certificate_name}):
        raise OpenVpnPlanError("Dedicated OpenVPN PKI names are referenced by outside configuration")
    if not present:
        return None
    if present != paths.keys():
        raise OpenVpnPlanError("VyOS OpenVPN ownership configuration is incomplete")
    port, auth = _normalize_interface(trees["interface"][0], scope)
    ca = trees["ca"][0]
    certificate = trees["certificate"][0]
    if (
        type(ca) is not dict or ca.keys() != {"certificate"}
        or type(certificate) is not dict or certificate.keys() != {"certificate", "private"}
        or type(certificate["private"]) is not dict or certificate["private"].keys() != {"key"}
    ):
        raise OpenVpnPlanError("Unexpected VyOS OpenVPN PKI object configuration")
    material = {
        "username": _credential(auth["username"]),
        "password": _credential(auth["password"]),
        "ca": _base64_material(ca["certificate"]),
        "certificate": _base64_material(certificate["certificate"]),
        "private_key": _base64_material(certificate["private"]["key"]),
    }
    return _state(scope, port, material)


def _prove_live_wan(scope, live_interfaces):
    def addresses(record):
        if (
            not isinstance(record, (tuple, list)) or len(record) != 2
            or not isinstance(record[0], (tuple, list)) or type(record[1]) is not str
        ):
            raise OpenVpnPlanError("Unexpected live OpenVPN WAN interface read-back")
        try:
            return interface_ipv4_addresses(record[1])
        except ValueError:
            raise OpenVpnPlanError("Invalid live OpenVPN WAN interface address") from None

    wan = live_interfaces.get(scope.wan_interface)
    expected = IPv4Interface(scope.wan_cidr)
    peer = IPv4Address(scope.remote_host)
    outside = [
        address.network
        for name, record in live_interfaces.items()
        if name not in {scope.interface, scope.wan_interface}
        for address in addresses(record)
    ]
    if (
        wan is None or addresses(wan) != [expected] or not {"UP", "LOWER_UP"}.issubset(wan[0])
        or any(peer in network or expected.ip in network for network in outside)
    ):
        raise OpenVpnPlanError("Pinned OpenVPN WAN lacks an exclusive active IPv4 path")
    tunnel = IPv4Interface(scope.tunnel_cidr).network
    if any(tunnel.overlaps(network) for network in outside):
        raise OpenVpnPlanError("Pinned OpenVPN tunnel prefix overlaps another interface")


def _verified_state(state, scope):
    return state is None or (
        type(state) is dict
        and state.keys() == {"resources", "remote_port", "digests"}
        and state["resources"] == [scope.interface, scope.ca_name, scope.certificate_name]
        and type(state["remote_port"]) is int
        and state["remote_port"] in scope.remote_ports
        and type(state["digests"]) is dict
        and state["digests"].keys() == _SECRET_FIELDS
        and all(type(digest) is str and _DIGEST.fullmatch(digest) for digest in state["digests"].values())
    )


def _set(path, value):
    return {"op": "set", "path": [*path, value]}


def _static_commands(tree, path):
    commands = []
    for key, value in tree.items():
        leaf = (*path, key)
        if value == {}:
            commands.append({"op": "set", "path": list(leaf)})
        elif type(value) is dict:
            commands.extend(_static_commands(value, leaf))
        elif type(value) is list:
            commands.extend(_set(leaf, entry) for entry in value)
        else:
            commands.append(_set(leaf, value))
    return commands


def plan_openvpn(
    intent: OpenVpnClientIntent | None,
    scope: OpenVpnScope,
    *,
    current: OpenVpnState | None,
    previous: OpenVpnState | None,
    live_interfaces: dict,
) -> OpenVpnPlan:
    """Plan one timed transaction with the caller's separately verified traffic guards."""
    if not isinstance(scope, OpenVpnScope) or type(live_interfaces) is not dict:
        raise OpenVpnPlanError("OpenVPN planning requires live interface evidence for its scope")
    if not _verified_state(current, scope) or current != previous:
        raise OpenVpnPlanError("VyOS OpenVPN configuration differs from verified ownership")
    if current is None and scope.interface in live_interfaces:
        raise OpenVpnPlanError("VyOS OpenVPN live interface lacks verified ownership")

    paths = _paths(scope)
    if intent is None:
        deletes = ({"op": "delete", "path": list(path)} for path in paths.values())
        return OpenVpnPlan(tuple(deletes) if current is not None else (), None)
    if (
        not isinstance(intent, OpenVpnClientIntent)
        or intent.remote_host != scope.remote_host
        or type(intent.remote_port) is not int or intent.remote_port not in scope.remote_ports
        or intent.server_name != scope.server_name
    ):
        raise OpenVpnPlanError("OpenVPN intent differs from the approved endpoints")
    _prove_live_wan(scope, live_interfaces)

    ca = _pem_body(intent.ca_pem, "CERTIFICATE")
    certificate = _pem_body(intent.client_certificate_pem, "CERTIFICATE")
    private_key = _pem_body(intent.client_private_key_pem, "PRIVATE KEY")
    desired = _state(scope, intent.remote_port, {
        "username": _credential(intent.username),
        "password": _credential(intent.password),
        "ca": _base64_material(ca),
        "certificate": _base64_material(certificate),
        "private_key": _base64_material(private_key),
    })
    before = current["digests"] if current is not None else {}
    path = paths["interface"]
    commands = []
    for name, leaf, value in (
        ("ca", (*paths["ca"], "certificate"), ca),
        ("certificate", (*paths["certificate"], "certificate"), certificate),
        ("private_key", (*paths["certificate"], "private", "key"), private_key),
        ("username", (*path, *_USERNAME_PATH), intent.username),
        ("password", (*path, *_PASSWORD_PATH), intent.password),
    ):
        if before.get(name) != desired["digests"][name]:
            commands.append(_set(leaf, value))
    if current is None:
        commands.extend(_static_commands(_static_interface(scope), path))
    if current is None or current["remote_port"] != intent.remote_port:
        commands.append(_set((*path, "remote-port"), str(intent.remote_port)))
    return OpenVpnPlan(tuple(commands), desired)
