"""Extract public pairing evidence from authenticated Enterprise COMPLETE snapshots."""

from base64 import b64decode
from dataclasses import asdict, dataclass, replace
from hashlib import sha256
from ipaddress import IPv4Interface, IPv6Address
import json
import ssl

from Crypto.Util.asn1 import DerSequence

from backends.vyos_failover import _invalid_constant, _unique_fields
from provisioners.vyos_shadow_binding import ShadowEnrollmentPair
from provisioners.uxg_enterprise_shadow import SHADOW_ADDRESSES, shadow_management_port
from provisioners.vyos_shadow_complete import (
    ShadowElection, _absent_vrrp_parent, _verify_controller_alias, decode_shadow_vrrp, prepare_shadow_primary_lan_handoff,
)
from provisioners.vyos_shadow_guard import normalize_shadow_management_guard


_STUNNEL_SCHEMA = "services/stunnel"
_VRRP_SCHEMA = "services/vrrp"
_TUNNEL_PORT = 31000
_CLIENT_SOCKET = "/var/run/ubnt-udapi-server-peer.sock"
_SERVER_SOCKET = "/var/run/ubnt-udapi-server.sock"
_MAX_ENCODED_CERT = 16384


@dataclass(frozen=True)
class ShadowCompleteSnapshot:
    election: ShadowElection
    local_certificate_sha256: str
    peer_certificate_sha256: str


def _complete_document(system_cfg):
    if not isinstance(system_cfg, str):
        raise ValueError("Expected an authenticated Shadow Mode COMPLETE snapshot")
    try:
        document = json.loads(system_cfg, object_pairs_hook=_unique_fields, parse_constant=_invalid_constant)
    except (ValueError, RecursionError):
        raise ValueError("Invalid Shadow Mode COMPLETE snapshot JSON") from None

    if not isinstance(document, dict):
        raise ValueError("Invalid Shadow Mode COMPLETE snapshot document")
    return document


def _complete_fingerprint(document):
    try:
        canonical = json.dumps(document, sort_keys=True, separators=(",", ":"), allow_nan=False)
    except (ValueError, RecursionError):
        raise ValueError("Invalid Shadow Mode COMPLETE snapshot values") from None
    return sha256(canonical.encode()).hexdigest()


def complete_snapshot_fingerprint(system_cfg):
    """Fingerprint all snapshot fields without retaining the snapshot or its secrets."""
    return _complete_fingerprint(_complete_document(system_cfg))


def requests_shadow_completion(system_cfg):
    if system_cfg is None:
        return False
    udapi = _complete_document(system_cfg).get("udapi")
    services = udapi.get("services") if isinstance(udapi, dict) else None
    return isinstance(services, dict) and any(
        isinstance(resource, dict) and resource.get("enabled") is True
        for resource in (services.get("vrrp"), services.get("stunnel"))
    )


def primary_shadow_policy_fingerprint(system_cfg, ordinary, *, complete):
    """Compare all policy outside the verified address transfer and Shadow resources."""
    document, _ = _ordinary_policy_document(_complete_document(system_cfg), ordinary, complete=complete)
    return _complete_fingerprint(document)


def _ordinary_policy_document(document, ordinary, *, complete):
    bridge = _primary_bridge(document)
    if not isinstance(ordinary, list) or not ordinary or not isinstance(ordinary[0], dict):
        raise ValueError("Shadow Mode requires the verified ordinary LAN address snapshot")
    management_guard = None
    if complete:
        gateway = IPv4Interface(ordinary[0].get("cidr", ""))
        _verify_controller_alias(ordinary, bridge.get("addresses"), gateway)
        bridge["addresses"] = ordinary
        management_guard = _normalize_primary_management_guard(document)
    elif bridge.get("addresses") != ordinary:
        raise ValueError("Shadow Mode phase-one LAN addresses differ from the verified ordinary addresses")
    udapi = document["udapi"]
    for field, names in (("services", ("vrrp", "stunnel")), ("versionDetail", (_VRRP_SCHEMA, _STUNNEL_SCHEMA))):
        inventory = udapi.get(field, {}) if field == "services" and not complete else udapi.get(field)
        if not isinstance(inventory, dict):
            raise ValueError("Invalid Shadow Mode policy inventory")
        for name in names:
            inventory.pop(name, None)
        if field == "services" and not inventory:
            udapi.pop(field, None)
    return document, management_guard


def shadow_site_policy_fingerprint(system_cfg, *, election):
    """Compare full site policy while preserving every other device-specific field."""
    document, guard, port_index = _site_policy_document(system_cfg, election)
    document["udapi"]["interfaces"][port_index] = shadow_management_port(SHADOW_ADDRESSES[0])
    return _complete_fingerprint({"format": 1, "policy": document, "guard_networks": guard.networks if guard else None})


def standby_policy_snapshot(system_cfg, *, election):
    """Project ordinary intent and return the guard for the standby election transaction."""
    if election.priority != 100:
        raise ValueError("Shadow Mode standby policy requires a standby election")
    document, guard, _ = _site_policy_document(system_cfg, election)
    return json.dumps(document), guard


def _site_policy_document(system_cfg, election):
    document = _complete_document(system_cfg)
    addresses = _primary_bridge(document).get("addresses")
    gateway = dict(election.virtual_ips).get("br0")
    if not isinstance(addresses, list) or gateway is None:
        raise ValueError("Shadow Mode site policy requires the authenticated LAN gateway transfer")
    ordinary = [{"type": "static", "cidr": str(gateway), "version": "v4"}, *addresses[1:]]
    document, guard = _ordinary_policy_document(document, ordinary, complete=True)
    interfaces = document["udapi"]["interfaces"]
    selected = [index for index, row in enumerate(interfaces)
                if isinstance(row.get("identification"), dict) and row["identification"].get("id") == "eth1"]
    expected = shadow_management_port(f"{election.source}/24")
    if (len(selected) != 1 or interfaces[selected[0]] != expected
            or interfaces[selected[0]]["status"]["enabled"] is not True):
        raise ValueError("Shadow Mode site policy requires the authenticated role's exact management port")
    if any(row.get("status", {}).get("comment") == "MGMT_SHADOW" for index, row in enumerate(interfaces)
           if index != selected[0] and isinstance(row.get("status"), dict)):
        raise ValueError("Shadow Mode site policy has more than one management port")
    return document, guard, selected[0]


def _normalize_primary_management_guard(document):
    udapi = document.get("udapi")
    sets = udapi.get("firewall/sets", []) if isinstance(udapi, dict) else None
    if not isinstance(sets, list) or not all(isinstance(row, dict) for row in sets):
        raise ValueError("Invalid Shadow management firewall sets")
    if not any(row.get("identification", {}).get("name") == "vrrp_mgmt_addr"
               for row in sets if isinstance(row.get("identification"), dict)):
        return None
    services, versions = udapi.get("services"), udapi.get("versionDetail")
    if not isinstance(services, dict) or not isinstance(versions, dict):
        raise ValueError("Invalid Shadow management firewall service inventory")
    election = decode_shadow_vrrp(services.get("vrrp"), version=versions.get(_VRRP_SCHEMA))
    return normalize_shadow_management_guard(udapi, source=election.source, peer=election.peer)


def decode_primary_management_guard(system_cfg):
    """Read only the stock management isolation required by this native COMPLETE snapshot."""
    return _normalize_primary_management_guard(_complete_document(system_cfg))


def _primary_bridge(document):
    udapi = document.get("udapi")
    rows = udapi.get("interfaces") if isinstance(udapi, dict) else None
    if not isinstance(rows, list) or not all(isinstance(row, dict) for row in rows):
        raise ValueError("Invalid Shadow Mode COMPLETE interface inventory")
    bridges = [row for row in rows if row.get("identification") == {"id": "br0", "type": "bridge"}]
    if len(bridges) != 1:
        raise ValueError("Shadow Mode COMPLETE requires a unique br0 bridge")
    return bridges[0]


def decode_shadow_complete_snapshot(system_cfg: str) -> ShadowCompleteSnapshot:
    """Read the pinned resources from an already authenticated controller snapshot."""
    udapi = _complete_document(system_cfg).get("udapi")
    versions = udapi.get("versionDetail") if isinstance(udapi, dict) else None
    services = udapi.get("services") if isinstance(udapi, dict) else None
    if not isinstance(versions, dict) or not isinstance(services, dict):
        raise ValueError("Missing Shadow Mode COMPLETE resource inventory")
    stunnel_version = versions.get(_STUNNEL_SCHEMA)
    if type(stunnel_version) is not int or stunnel_version != 1:
        raise ValueError("Unsupported Shadow Mode tunnel schema")

    election = decode_shadow_vrrp(services.get("vrrp"), version=versions.get(_VRRP_SCHEMA))
    if "br0" not in dict(election.virtual_ips) or (election.priority == 100 and election.peer_lan is None):
        raise ValueError("Shadow Mode COMPLETE requires the br0 VIP and standby LAN guard")
    local, peer = _decode_tunnel(services.get("stunnel"), election.peer)
    return ShadowCompleteSnapshot(election, local, peer)


def verify_shadow_complete_pair(
    primary_response: dict, standby_response: dict, *, primary_head: str, standby_head: str,
) -> tuple[ShadowCompleteSnapshot, ShadowCompleteSnapshot]:
    """Correlate the current snapshots of two independently authenticated enrollments."""
    primary = _decode_complete_response(primary_response, primary_head)
    standby = _decode_complete_response(standby_response, standby_head)
    return _verify_reciprocal_snapshots(primary, standby)


def _decode_complete_response(response, head):
    if (not isinstance(head, str) or not head or not isinstance(response, dict)
            or response.get("_type") != "setparam" or response.get("cfgversion") != head):
        raise ValueError("Shadow Mode COMPLETE snapshot does not match its controller head")
    return decode_shadow_complete_snapshot(response.get("system_cfg"))


def _verify_reciprocal_snapshots(primary, standby):
    first, second = primary.election, standby.election
    if (first.priority not in {120, 255} or second.priority != 100
            or first.source != second.peer or first.peer != second.source
            or dict(first.virtual_ips) != dict(second.virtual_ips)
            or primary.local_certificate_sha256 != standby.peer_certificate_sha256
            or primary.peer_certificate_sha256 != standby.local_certificate_sha256):
        raise ValueError("Shadow Mode COMPLETE snapshots do not describe a reciprocal pair")
    return primary, standby


def verify_bound_shadow_complete(binding: ShadowEnrollmentPair, *, authenticated_responses):
    """Match each response to its bound issuer and controller desired revision."""
    nodes = binding.primary, binding.standby
    device_ids = {node.device_id for node in nodes}
    if (len(device_ids) != 2 or not isinstance(authenticated_responses, dict)
            or authenticated_responses.keys() != device_ids):
        raise ValueError("Shadow Mode requires one authenticated response for each bound device")
    primary, standby = (_decode_bound_response(node, authenticated_responses[node.device_id]) for node in nodes)
    return _verify_reciprocal_snapshots(primary, standby)


def verify_bound_shadow_primary_complete(binding: ShadowEnrollmentPair, *, authenticated_response):
    """Verify the initial primary snapshot while Network is still waiting for MASTER."""
    if binding.state != "IN_PROGRESS":
        raise ValueError("Shadow Mode initial primary COMPLETE requires an in-progress setup")
    snapshot = _decode_bound_response(binding.primary, authenticated_response)
    if snapshot.election.priority != 255:
        raise ValueError("Shadow Mode initial primary COMPLETE has the wrong role or priority")
    return snapshot


def _standby_resources_fingerprint(binding, snapshot):
    election = snapshot.election
    return _complete_fingerprint({
        "format": 1,
        "site": binding.site_id,
        "firmware": binding.firmware,
        "roles": [[node.device_id, asdict(node.management)] for node in (binding.primary, binding.standby)],
        "standby": {
            "source": election.source,
            "peer": election.peer,
            "priority": election.priority,
            "virtual_ips": {name: str(address) for name, address in election.virtual_ips},
            "peer_lan": election.peer_lan,
            "local_certificate": snapshot.local_certificate_sha256,
            "peer_certificate": snapshot.peer_certificate_sha256,
        },
    })


def expected_standby_resources(binding, primary_snapshot, primary_lan_link_local):
    """Commit to the reciprocal standby resources without keeping certificates or keys."""
    primary = primary_snapshot.election
    link_local = IPv6Address(primary_lan_link_local)
    if not link_local.is_link_local or link_local.scope_id is not None:
        raise ValueError("Shadow Mode standby requires the unscoped primary LAN link-local address")
    standby = ShadowCompleteSnapshot(
        replace(primary, source=primary.peer, peer=primary.source, priority=100,
                peer_lan=("br0", str(link_local))),
        primary_snapshot.peer_certificate_sha256, primary_snapshot.local_certificate_sha256,
    )
    return _standby_resources_fingerprint(binding, standby)


def verify_bound_shadow_standby_complete(binding, *, authenticated_response, expected_resources):
    if binding.state not in ("IN_PROGRESS", "SETUP_COMPLETED"):
        raise ValueError("Shadow Mode standby COMPLETE requires a controller setup phase")
    snapshot = _decode_bound_response(binding.standby, authenticated_response)
    if snapshot.election.priority != 100 or _standby_resources_fingerprint(binding, snapshot) != expected_resources:
        raise ValueError("Shadow Mode standby COMPLETE does not match the verified primary resources")
    return snapshot


def prepare_bound_shadow_primary_lan_handoff(binding, *, authenticated_response, nodes, primary_lan_link_local,
                                             ordinary, local, peer, route_source, reservation=None, stock_configuration=None):
    """Bind the exact controller snapshot to the planned primary handoff."""
    snapshot = verify_bound_shadow_primary_complete(binding, authenticated_response=authenticated_response)
    document = _complete_document(authenticated_response[1]["system_cfg"])
    fingerprint = _complete_fingerprint(document)
    management_guard = _normalize_primary_management_guard(document)
    recovery = None
    if reservation is not None:
        from provisioners.vyos_shadow_handoff import read_shadow_lan_preimage

        recovery = read_shadow_lan_preimage(reservation)
    handoff = prepare_shadow_primary_lan_handoff(
        snapshot.election, nodes=nodes, primary_lan_link_local=primary_lan_link_local, ordinary=ordinary,
        complete=_primary_bridge(document).get("addresses"), local=local, peer=peer, route_source=route_source,
        recovery=recovery,
    )
    if recovery is None and stock_configuration is not None:
        handoff = replace(handoff, created_vrrp_parent=_absent_vrrp_parent(stock_configuration))
    if recovery is None and management_guard is not None:
        preimage = stock_configuration if stock_configuration is not None else local.saved
        handoff = replace(handoff, guard_containers=management_guard.created_containers(preimage))
    standby_resources = expected_standby_resources(binding, snapshot, primary_lan_link_local)
    site_policy = shadow_site_policy_fingerprint(authenticated_response[1]["system_cfg"], election=snapshot.election)
    return replace(handoff, complete_snapshot_sha256=fingerprint, complete_binding=binding,
                   standby_resources_sha256=standby_resources, management_guard=management_guard,
                   site_policy_sha256=site_policy)


def _decode_bound_response(node, observation):
    if not isinstance(observation, tuple) or len(observation) != 2 or observation[0] != node.management:
        raise ValueError("Shadow Mode response came from a different authenticated device")
    return _decode_complete_response(observation[1], node.desired_revision)


def _decode_tunnel(tunnel, peer_ip):
    if (not isinstance(tunnel, dict) or tunnel.keys() != {"enabled", "clients", "servers"}
            or tunnel["enabled"] is not True):
        raise ValueError("Expected one enabled Shadow Mode tunnel")
    client = _single_endpoint(tunnel["clients"], "uuspeersock", "serverPort", _CLIENT_SOCKET, server=peer_ip)
    server = _single_endpoint(tunnel["servers"], "uuslocalsock", "listenPort", _SERVER_SOCKET)
    local = _certificate_digest(client["clientCert"], local=True)
    peer = _certificate_digest(client["serverCert"], local=False)
    if (local == peer or local != _certificate_digest(server["serverCert"], local=True)
            or peer != _certificate_digest(server["clientCert"], local=False)):
        raise ValueError("Shadow Mode tunnel certificates disagree across its endpoints")
    return local, peer


def _single_endpoint(rows, identity, port, socket, **extra):
    fields = {"id", port, "localSocket", "clientCert", "serverCert", *extra}
    if not isinstance(rows, list) or len(rows) != 1 or not isinstance(rows[0], dict):
        raise ValueError("Expected a single Shadow Mode tunnel endpoint")
    endpoint, = rows
    if (endpoint.keys() != fields or endpoint["id"] != identity
            or type(endpoint[port]) is not int or endpoint[port] != _TUNNEL_PORT
            or endpoint["localSocket"] != socket or any(endpoint[key] != value for key, value in extra.items())):
        raise ValueError("Invalid Shadow Mode tunnel endpoint")
    return endpoint


def _certificate_digest(wrapper, *, local):
    fields = {"crt", "key"} if local else {"crt"}
    if not isinstance(wrapper, dict) or wrapper.keys() != fields:
        raise ValueError("Invalid Shadow Mode tunnel certificate wrapper")
    encoded = wrapper["crt"]
    if not isinstance(encoded, str) or not 0 < len(encoded) <= _MAX_ENCODED_CERT:
        raise ValueError("Invalid Shadow Mode tunnel certificate length")
    try:
        begin, *body, end = b64decode(encoded, validate=True).splitlines()
        if begin != b"-----BEGIN CERTIFICATE-----" or end != b"-----END CERTIFICATE-----" or not all(body):
            raise ValueError("Expected one certificate PEM")
        der = b64decode(b"".join(body), validate=True)
        DerSequence().decode(der, strict=True, nr_elements=3)
        parser = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        parser.load_verify_locations(cadata=der)
        if parser.cert_store_stats()["x509"] != 1:
            raise ValueError("Expected one complete X.509 certificate")
    except (ValueError, ssl.SSLError):
        raise ValueError("Invalid Shadow Mode tunnel certificate") from None
    return sha256(der).hexdigest()
