"""Load packaged enrollment and preserve the separately owned gateway state."""
from configparser import Error, RawConfigParser
from ipaddress import IPv4Address
import json
from pathlib import Path
import re
from secrets import token_bytes
from urllib.parse import urlsplit

from backends.vyos_failover import _invalid_constant, _unique_fields
from gateway_profiles.enterprise import FIRMWARE, require_enterprise
from provisioners import JOURNAL_SCHEMA_VERSION
from provisioners.vyos_shadow_binding import _management_origin
from tools import atomic_write

_ADOPTION_FIELDS = ("is_adopted", "use_aes_gcm", "key", "locating")
_STATE_SECTIONS = ("provisioned", "vyos_applied", "vyos_shadow_applied")
_MAC = re.compile(r"[0-9a-f]{2}(?::[0-9a-f]{2}){5}")
_WAN_SSH_KEYS = {"wan1-ssh-key", "wan2-ssh-key", "wan3-ssh-key"}


def load_enrolled_config(
    site_path: str, state_path: str, *, require_existing=False, credential_prefix="",
    initialize_state=True,
) -> RawConfigParser:
    """Combine site-owned settings with state bound to this controller and router."""
    site_file = Path(site_path)
    state_file = Path(state_path)
    journal = state_file.with_name("firewall.json")
    if credential_prefix not in {"", "primary_", "standby_"}:
        raise ValueError("Invalid Shadow Mode credential role")
    if credential_prefix and site_file.name != f"{credential_prefix}site.conf":
        raise ValueError("Shadow Mode enrollment must match its credential role")

    def credential(name):
        return site_file.with_name(credential_prefix + name)

    config = _read_ini(site_file, "enrollment")
    require_enterprise(config)
    gateway = config["gateway"]
    if any(key in gateway for key in _ADOPTION_FIELDS) or any(config.has_section(key) for key in _STATE_SECTIONS):
        raise ValueError("VyOS gateway enrollment must omit adoption state")
    _validate_url(gateway.get("url", ""), {"http", "https"}, {"/inform"}, "controller inform URL")
    _validate_url(config.get("vyos", "api_url", fallback=""), {"https"}, {"", "/"}, "VyOS HTTPS origin")
    _validate_lan_ip(gateway.get("lan_ip", ""))
    if "ports" not in gateway:
        raise ValueError("VyOS gateway enrollment needs explicit port mappings")

    if not config.has_section("global"):
        config.add_section("global")
    config["global"].setdefault("disable_broadcast", "False")
    config["vyos"]["ca_file"] = str(credential("vyos-ca.pem"))
    config["vyos"]["key_file"] = str(credential("vyos-api-key"))
    if config.has_section("vyos_firewall"):
        config["vyos_firewall"]["state_path"] = str(journal)
    if config.has_option("vyos_inspection", "ssh_host"):
        inspection = config["vyos_inspection"]
        inspection["ssh_key_file"] = str(credential("inspection-ssh-key"))
        inspection["ssh_known_hosts_file"] = str(credential("inspection-ssh-known-hosts"))
    if config.getboolean("vyos_wan_health", "enabled", fallback=False):
        _resolve_wan_credentials(config["vyos_wan_health"], credential)
    if config.getboolean("vyos_routing_ssh", "enabled", fallback=False):
        routing = config["vyos_routing_ssh"]
        routing["ssh_key_file"] = str(credential("routing-ssh-key"))
        routing["ssh_known_hosts_file"] = str(credential("routing-ssh-known-hosts"))
    if (config.getboolean("vyos_restart", "enabled", fallback=False)
            or config.getboolean("vyos_restart", "recover_provisioning", fallback=False)):
        restart = config["vyos_restart"]
        restart["ssh_key_file"] = str(credential("restart-ssh-key"))
        restart["ssh_known_hosts_file"] = str(credential("restart-ssh-known-hosts"))
    if config.getboolean("vyos_shadow", "probe_enabled", fallback=False):
        shadow = config["vyos_shadow"]
        shadow["ssh_key_file"] = str(credential("shadow-ssh-key"))
        shadow["ssh_known_hosts_file"] = str(credential("shadow-ssh-known-hosts"))
        receipt_key = credential("shadow-receipt-ssh-key")
        shadow.pop("receipt_ssh_key_file", None)
        if receipt_key.is_file():
            shadow["receipt_ssh_key_file"] = str(receipt_key)
    if credential_prefix == "standby_" and config.getboolean("vyos_shadow_primary", "enabled", fallback=False):
        raise ValueError("Shadow Mode standby enrollment cannot enable the primary coordinator")
    if credential_prefix == "primary_" and config.getboolean("vyos_shadow_primary", "enabled", fallback=False):
        primary = config["vyos_shadow_primary"]
        primary["standby_enrollment"] = str(site_file.with_name("standby_site.conf"))
        primary["standby_state"] = str(state_file.parent.with_name("standby") / state_file.name)
        primary["controller_ca_file"] = str(credential("controller-ca.pem"))
        primary["controller_session_file"] = str(credential("network-session.cookies"))

    gateway["is_adopted"] = "False"
    gateway["use_aes_gcm"] = "False"
    gateway["firmware"] = FIRMWARE
    configured_mac = _validate_mac(gateway["lan_mac"]) if gateway.get("lan_mac") else None
    saved = _read_ini(state_file, "state", optional=not require_existing)
    if saved is None:
        if journal.exists() or journal.is_symlink():
            raise ValueError("Incomplete enrollment state. Please restore gateway.conf with firewall.json before starting")
        if initialize_state:
            gateway["lan_mac"] = configured_mac or _new_mac()
            atomic_write(state_file, config.write, mode=0o600)
    else:
        if saved.get("gateway", "device", fallback=None) != gateway["device"]:
            raise ValueError("Gateway state belongs to another model. Use a separate enrollment and state directory")
        if (saved.get("gateway", "url", fallback=None) != gateway["url"]
                or saved.get("vyos", "api_url", fallback=None) != config["vyos"]["api_url"]):
            raise ValueError("VyOS gateway state belongs to another controller or VyOS management endpoint")
        gateway["lan_mac"] = _validate_mac(saved.get("gateway", "lan_mac", fallback=""))
        if configured_mac is not None and configured_mac != gateway["lan_mac"]:
            raise ValueError("VyOS gateway state belongs to another MAC address")
        applied = saved.get("vyos_applied", "cfgversion", fallback="")
        if applied and config.getboolean("vyos_firewall", "enabled", fallback=False):
            _verify_applied_revision(journal, applied)
        for key in _ADOPTION_FIELDS:
            if saved.has_option("gateway", key):
                gateway[key] = saved["gateway"][key]
        for section in _STATE_SECTIONS:
            if saved.has_section(section):
                config[section] = dict(saved[section])
    return config


def check_shadow_pair_enrollment(credential_dir: Path, state_dir: Path):
    """Validate the two packaged enrollments together before either worker starts."""
    primary, standby = (
        load_enrolled_config(
            str(credential_dir / f"{role}_site.conf"), str(state_dir / role / "gateway.conf"),
            credential_prefix=f"{role}_", initialize_state=False,
        )
        for role in ("primary", "standby")
    )
    if primary["gateway"]["url"] != standby["gateway"]["url"]:
        raise ValueError("Shadow Mode routers must use the same inform endpoint")
    if _management_origin(primary["vyos"]["api_url"]) == _management_origin(standby["vyos"]["api_url"]):
        raise ValueError("Shadow Mode routers require distinct VyOS management endpoints")
    primary_mac = primary["gateway"].get("lan_mac")
    standby_mac = standby["gateway"].get("lan_mac")
    if primary_mac and standby_mac and _validate_mac(primary_mac) == _validate_mac(standby_mac):
        raise ValueError("Shadow Mode routers require distinct gateway MAC addresses")


def _verify_applied_revision(journal, applied):
    try:
        state = json.loads(journal.read_text(encoding="utf-8"), object_pairs_hook=_unique_fields,
                           parse_constant=_invalid_constant)
    except FileNotFoundError:
        raise ValueError("Incomplete enrollment state. Please restore firewall.json with gateway.conf before starting") from None
    except (IsADirectoryError, ValueError, RecursionError):
        raise ValueError("Invalid provisioning journal. Restore a valid firewall.json before starting") from None

    if (not isinstance(state, dict) or type(state.get("schema_version")) is not int
            or state["schema_version"] != JOURNAL_SCHEMA_VERSION):
        raise ValueError(f"Invalid provisioning journal format. Expected schema version {JOURNAL_SCHEMA_VERSION}")
    revision = state.get("verified_revision")
    history = state.get("previous_revisions")
    if (not isinstance(revision, str) or not revision or not isinstance(history, list)
            or any(not isinstance(item, str) or not item for item in history)):
        raise ValueError("Invalid provisioning journal. Restore a valid firewall.json before starting")
    # The journal is committed before the gateway's acknowledgement is saved.
    if applied != revision and applied not in history:
        raise ValueError("Provisioning journal does not contain the gateway's applied revision. Restore both files together")


def _resolve_wan_credentials(section, credential):
    try:
        probes = json.loads(section["probes"], object_pairs_hook=_unique_fields, parse_constant=_invalid_constant)
        if type(probes) is not dict or any(type(options) is not dict for options in probes.values()):
            raise ValueError
    except (KeyError, ValueError, RecursionError):
        raise ValueError("Invalid packaged WAN probe mapping") from None
    keys = set()
    for options in probes.values():
        if "ssh_key_file" not in options:
            continue
        key = options["ssh_key_file"]
        if type(key) is not str or key not in _WAN_SSH_KEYS or key in keys:
            raise ValueError("Each packaged WAN probe needs its own named systemd credential")
        keys.add(key)
        options["ssh_key_file"] = str(credential(key))
    if keys:
        section["ssh_known_hosts_file"] = str(credential("wan-ssh-known-hosts"))
        section["probes"] = json.dumps(probes)


def _read_ini(path, label, *, optional=False):
    config = RawConfigParser()
    try:
        with path.open(encoding="utf-8") as handle:
            config.read_file(handle)
    except FileNotFoundError:
        if optional:
            return None
        raise
    except (Error, UnicodeError):
        raise ValueError(f"Invalid VyOS gateway {label} INI") from None
    if config.defaults():
        raise ValueError(f"VyOS gateway {label} must omit DEFAULT values")
    return config


def _validate_url(value, schemes, paths, label):
    try:
        url = urlsplit(value)
        if (url.scheme in schemes and url.hostname and url.username is None and not url.query
                and not url.fragment and url.path in paths and url.port != 0
                and not any(character.isspace() for character in value)):
            return
    except ValueError:
        raise ValueError(f"Invalid VyOS gateway {label}") from None
    raise ValueError(f"Invalid VyOS gateway {label}")


def _validate_lan_ip(value):
    try:
        address = IPv4Address(value)
    except ValueError:
        raise ValueError("VyOS gateway enrollment needs a valid LAN IPv4 address") from None
    if address.is_multicast or address.is_unspecified or str(address) == "255.255.255.255":
        raise ValueError("VyOS gateway enrollment needs a unicast LAN IPv4 address")


def _validate_mac(value):
    mac = value.lower()
    if not _MAC.fullmatch(mac) or mac == "00:00:00:00:00:00" or int(mac[:2], 16) & 1:
        raise ValueError("VyOS gateway enrollment needs a nonzero unicast MAC address")
    return mac


def _new_mac():
    random = token_bytes(6)
    return bytes([random[0] & 0xFC | 2, *random[1:]]).hex(":")
