"""Bind controller Shadow roles to the two independently enrolled VyOS routers."""

from base64 import b64decode, b64encode
from binascii import Error as Base64Error
from dataclasses import dataclass
from ipaddress import IPv6Address
import re
from urllib.parse import urlsplit


_IDENTIFIER = re.compile(r"[A-Za-z0-9_.:-]{1,128}")
_MAC = re.compile(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}")


@dataclass(frozen=True)
class ShadowManagementIdentity:
    # The caller supplies the authenticated local inform MAC and the prepared management pin.
    mac: str
    https_origin: str
    ssh_host_key: str


@dataclass(frozen=True)
class ShadowEnrolledNode:
    device_id: str
    management: ShadowManagementIdentity
    desired_revision: str


@dataclass(frozen=True)
class ShadowEnrollmentPair:
    site_id: str
    firmware: str
    primary: ShadowEnrolledNode
    standby: ShadowEnrolledNode
    state: str | None = None


def _identifier(value):
    return isinstance(value, str) and _IDENTIFIER.fullmatch(value) is not None


def _unicast_mac(value):
    return (isinstance(value, str) and _MAC.fullmatch(value) is not None
            and value != "00:00:00:00:00:00" and not int(value[:2], 16) & 1)


def _management_origin(origin):
    try:
        if not isinstance(origin, str) or not re.fullmatch(r"https://[\x21-\x7e]+", origin):
            raise ValueError
        url = urlsplit(origin)
        host, port = url.hostname, url.port
        if (not host or url.username is not None or url.path not in ("", "/")
                or "?" in origin or "#" in origin or port == 0 or url.netloc.endswith(":")):
            raise ValueError
        if ":" in host:
            if "%" in host:
                raise ValueError
            host = str(IPv6Address(host))
        elif re.fullmatch(r"[a-z0-9][a-z0-9.-]{0,252}", host) is None:
            raise ValueError
    except ValueError:
        raise ValueError("Shadow Mode requires a valid HTTPS management origin") from None
    return host.rstrip("."), port or 443


def _validate_ssh_pin(fingerprint):
    if not isinstance(fingerprint, str) or re.fullmatch(r"SHA256:[A-Za-z0-9+/]{43}", fingerprint) is None:
        raise ValueError("Shadow Mode requires a pinned management SSH host key")
    try:
        raw = b64decode(fingerprint.removeprefix("SHA256:") + "=", validate=True)
    except Base64Error:
        raise ValueError("Shadow Mode requires a canonical management SSH host key") from None
    if len(raw) != 32 or b64encode(raw).decode("ascii")[:-1] != fingerprint.removeprefix("SHA256:"):
        raise ValueError("Shadow Mode requires a canonical management SSH host key")


def _bind_router(site_id, inventory, router):
    if not isinstance(inventory, list) or not all(isinstance(row, dict) for row in inventory):
        raise ValueError("Shadow Mode requires the current UniFi device inventory")
    matches = [row for row in inventory if row.get("mac") == router.mac]
    if len(matches) != 1:
        raise ValueError("Shadow Mode requires a unique controller record for each role")
    record, = matches
    if (record.get("site_id") != site_id or record.get("adopted") is not True or record.get("model") != "UXGENT"
            or not _identifier(record.get("_id")) or not _identifier(record.get("version"))):
        raise ValueError("Shadow Mode requires same-site adopted Enterprise device records")
    desired_revision = record.get("cfgversion")
    if not _identifier(desired_revision):
        raise ValueError("Shadow Mode requires the desired revision of each Enterprise device")
    return ShadowEnrolledNode(record["_id"], router, desired_revision), record


def bind_shadow_primary_admission(*, site_id, group, inventory, router, firmware, applied_revision):
    """Verify the observed initial group and its exact converged primary."""
    if (not _identifier(site_id) or not isinstance(group, dict) or not isinstance(router, ShadowManagementIdentity)
            or not _unicast_mac(router.mac) or group.get("primary_mac") != router.mac
            or group.get("state") != "NO_SHADOW_CANDIDATE_ADOPTED" or group.get("interface_name") != "eth1"
            or group.get("secondary_mac") is not None
            or any(group.get(field, False) is not False for field in ("waitingForManagementInterface", "waitingForVrrpStatus"))
            or not _identifier(applied_revision) or not _identifier(firmware)):
        raise ValueError("Shadow Mode admission requires the expected primary on port 2 with no standby")
    _management_origin(router.https_origin)
    _validate_ssh_pin(router.ssh_host_key)
    binding, record = _bind_router(site_id, inventory, router)
    if (record["version"] != firmware or record.get("known_cfgversion") != applied_revision
            or binding.desired_revision != applied_revision):
        raise ValueError("Shadow Mode admission requires the verified primary firmware and applied revision")
    return binding


def bind_shadow_enrollments(*, site_id, pair, inventory, routers):
    """Bind the controller's role MACs and desired revisions to the router identities."""
    if not _identifier(site_id) or not isinstance(pair, dict):
        raise ValueError("Shadow Mode requires a verified UniFi site and pair record")
    state = pair.get("state")
    if state is not None and not _identifier(state):
        raise ValueError("Shadow Mode requires a valid controller group state")
    macs = pair.get("primary_mac"), pair.get("secondary_mac")
    if not all(_unicast_mac(mac) for mac in macs) or macs[0] == macs[1]:
        raise ValueError("Shadow Mode requires two distinct controller role MACs")
    if (not isinstance(routers, (tuple, list)) or len(routers) != 2
            or not all(isinstance(router, ShadowManagementIdentity) for router in routers)
            or tuple(router.mac for router in routers) != macs):
        raise ValueError("Shadow Mode controller roles do not match the local device enrollments")
    origins = tuple(_management_origin(router.https_origin) for router in routers)
    for router in routers:
        _validate_ssh_pin(router.ssh_host_key)
    if origins[0] == origins[1] or routers[0].ssh_host_key == routers[1].ssh_host_key:
        raise ValueError("Shadow Mode requires separate VyOS management identities")
    (primary, left), (standby, right) = (_bind_router(site_id, inventory, router) for router in routers)
    if primary.device_id == standby.device_id or left["version"] != right["version"]:
        raise ValueError("Shadow Mode requires separate device records and matching full firmware versions")
    return ShadowEnrollmentPair(site_id, left["version"], primary, standby, state)
