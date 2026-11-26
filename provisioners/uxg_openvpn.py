"""Decode the supported UniFi Network 11 OpenVPN TLS client profile."""

import base64
import json
import os
import re
import ssl
from dataclasses import dataclass, field
from pathlib import Path
from tempfile import TemporaryDirectory


OPENVPN_CLIENT_CAPABILITY = 0x80
_SECTION = "vpn/openvpn/raws"
OPENVPN_VERSIONS = {_SECTION: 6}
_REMOTE = "198.18.210.2"
_APPROVED_REMOTES = {f"{_REMOTE} {port}": port for port in (19443, 19444)}
# Existing enrollments without an explicit pin retain their original peer identity.
_CERTIFICATE_LABEL = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?")
_SNAPSHOT_BYTES = 1_048_576
_PROFILE_BYTES = 16_384
_PROFILE_BASE64 = ((_PROFILE_BYTES + 2) // 3) * 4
_DIRECTIVES = {
    "client": "",
    "dev": "tun",
    "proto": "udp",
    "nobind": "",
    "persist-key": "",
    "persist-tun": "",
    "remote-cert-tls": "server",
    "tls-version-min": "1.2",
    "data-ciphers": "AES-256-GCM",
    "auth": "SHA256",
    "verb": "3",
}
_OPTIONAL_DIRECTIVES = {"auth-user-pass": ""}
_PEM_TYPES = {"ca": "CERTIFICATE", "cert": "CERTIFICATE", "key": "PRIVATE KEY"}
_INLINE_TAGS = {f"<{tag}>": tag for tag in _PEM_TYPES}
_PEM_LINE = re.compile(r"[A-Za-z0-9+/=]{1,64}")
_NATIVE_ID = re.compile(r"[1-9][0-9]{0,9}")
_CREDENTIAL = re.compile(r"[!-~]{1,128}")


class OpenVpnIntentError(ValueError):
    """The native OpenVPN snapshot cannot be applied within the approved scope."""


@dataclass(frozen=True, slots=True)
class OpenVpnClientIntent:
    """One certificate-authenticated OpenVPN client and its native credentials."""

    native_id: str
    remote_host: str
    remote_port: int
    server_name: str
    username: str = field(repr=False)
    password: str = field(repr=False)
    ca_pem: bytes = field(repr=False)
    client_certificate_pem: bytes = field(repr=False)
    client_private_key_pem: bytes = field(repr=False)


def valid_openvpn_server_name(name: object) -> bool:
    """Accept a literal, case-sensitive DNS-style certificate common name."""
    return (
        isinstance(name, str)
        and 0 < len(name) <= 64
        and all(_CERTIFICATE_LABEL.fullmatch(label) for label in name.split("."))
    )


def _unique_fields(pairs):
    document = {}
    for name, value in pairs:
        if name in document:
            raise OpenVpnIntentError("OpenVPN snapshot contains a duplicate field")
        document[name] = value
    return document


def _invalid_constant(_value):
    raise OpenVpnIntentError("OpenVPN snapshot contains a non-JSON constant")


def _snapshot(system_cfg: str, udapi_caps: int) -> dict:
    if (
        type(udapi_caps) is not int
        or not 0 <= udapi_caps <= 0xFFFFFFFF
        or not udapi_caps & OPENVPN_CLIENT_CAPABILITY
    ):
        raise OpenVpnIntentError(
            "OpenVPN snapshot requires the native client capability"
        )
    if type(system_cfg) is not str or len(system_cfg) > _SNAPSHOT_BYTES:
        raise OpenVpnIntentError("OpenVPN snapshot exceeds the supported input size")
    try:
        if len(system_cfg.encode("utf-8")) > _SNAPSHOT_BYTES:
            raise OpenVpnIntentError(
                "OpenVPN snapshot exceeds the supported input size"
            )
        document = json.loads(
            system_cfg,
            object_pairs_hook=_unique_fields,
            parse_constant=_invalid_constant,
        )
    except OpenVpnIntentError:
        raise
    except (ValueError, RecursionError):
        raise OpenVpnIntentError("OpenVPN snapshot is not valid JSON") from None
    udapi = document.get("udapi") if type(document) is dict else None
    versions = udapi.get("versionDetail") if type(udapi) is dict else None
    if (
        type(udapi) is not dict
        or type(udapi.get("version")) is not int
        or udapi["version"] != 48
        or udapi.get("versionFormat") != "v2"
        or type(versions) is not dict
        or type(versions.get(_SECTION)) is not int
        or versions[_SECTION] != OPENVPN_VERSIONS[_SECTION]
        or any(
            key == "vpn/openvpn" or (key.startswith("vpn/openvpn/") and key != _SECTION)
            for key in udapi
        )
    ):
        raise OpenVpnIntentError("Unsupported OpenVPN UDAPI schema or section")
    return udapi


def _verify_wan(interfaces: object) -> None:
    if type(interfaces) is not list:
        raise OpenVpnIntentError("OpenVPN snapshot lacks the approved WAN interface")
    candidates = []
    for interface in interfaces:
        identity = interface.get("identification") if type(interface) is dict else None
        if type(identity) is dict and identity.get("id") == "eth0":
            candidates.append(interface)
    if len(candidates) == 1:
        candidate = candidates[0]
        status = candidate.get("status")
        expected_address = {
            "type": "static",
            "cidr": "198.18.210.1/30",
            "version": "v4",
        }
        if (
            candidate["identification"].get("type") == "ethernet"
            and type(status) is dict
            and status.get("enabled") is True
            and candidate.get("addresses") == [expected_address]
        ):
            return
    raise OpenVpnIntentError("OpenVPN snapshot lacks the approved WAN interface")


def _base64(value):
    try:
        decoded = base64.b64decode(value, validate=True)
        if base64.b64encode(decoded).decode("ascii") == value:
            return decoded
    except ValueError:
        pass
    raise OpenVpnIntentError("OpenVPN profile contains invalid Base64")


def _pem(lines, tag: str) -> bytes:
    block = []
    for line in lines:
        if line == f"</{tag}>":
            break
        block.append(line)
    else:
        raise OpenVpnIntentError("OpenVPN profile contains an unclosed PEM block")
    kind = _PEM_TYPES[tag]
    if (
        len(block) < 3
        or block[0] != f"-----BEGIN {kind}-----"
        or block[-1] != f"-----END {kind}-----"
        or any(_PEM_LINE.fullmatch(line) is None for line in block[1:-1])
    ):
        raise OpenVpnIntentError("OpenVPN profile contains an unexpected PEM form")
    _base64("".join(block[1:-1]))
    return ("\n".join(block) + "\n").encode("ascii")


def _profile(configuration: object, server_name: str) -> tuple[int, dict[str, bytes]]:
    if type(configuration) is not str or not 0 < len(configuration) <= _PROFILE_BASE64:
        raise OpenVpnIntentError(
            "OpenVPN imported profile exceeds the supported input size"
        )
    decoded = _base64(configuration)
    if not 0 < len(decoded) <= _PROFILE_BYTES:
        raise OpenVpnIntentError(
            "OpenVPN imported profile exceeds the supported input size"
        )
    try:
        content = decoded.decode("ascii")
    except UnicodeError:
        raise OpenVpnIntentError("OpenVPN imported profile is not ASCII text") from None

    rows = content.removesuffix("\n").split("\n")
    if any(line.endswith(" ") for line in rows):
        raise OpenVpnIntentError(
            "OpenVPN profile differs from the approved TLS directives"
        )
    lines = iter(rows)
    options = {}
    material = {}
    for line in lines:
        if line in _INLINE_TAGS:
            tag = _INLINE_TAGS[line]
            if tag in material:
                raise OpenVpnIntentError(
                    "OpenVPN profile contains duplicate PEM blocks"
                )
            material[tag] = _pem(lines, tag)
            continue
        name, _, argument = line.partition(" ")
        if name in options:
            raise OpenVpnIntentError("OpenVPN profile contains duplicate directives")
        options[name] = argument

    remote = options.pop("remote", "")
    for name, argument in _OPTIONAL_DIRECTIVES.items():
        if name in options and options.pop(name) != argument:
            raise OpenVpnIntentError(
                "OpenVPN profile contains an unsupported directive"
            )
    if (
        options != {**_DIRECTIVES, "verify-x509-name": f"{server_name} name"}
        or remote not in _APPROVED_REMOTES
        or material.keys() != _PEM_TYPES.keys()
    ):
        raise OpenVpnIntentError(
            "OpenVPN profile differs from the approved TLS directives"
        )
    return _APPROVED_REMOTES[remote], material


def _verify_pki(material: dict[str, bytes]) -> None:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    try:
        context.load_verify_locations(cadata=material["ca"].decode("ascii"))
        if context.cert_store_stats()["x509_ca"] != 1:
            raise OpenVpnIntentError(
                "OpenVPN trust block must contain one CA certificate"
            )
        with TemporaryDirectory(prefix="unifi-openvpn-pki-", dir="/tmp") as directory:
            paths = []
            for name in ("cert", "key"):
                path = Path(directory) / name
                descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(descriptor, "wb") as handle:
                    handle.write(material[name])
                paths.append(path)
            context.load_cert_chain(*paths, password=lambda: b"")
    except OpenVpnIntentError:
        raise
    except (OSError, ValueError):
        raise OpenVpnIntentError(
            "OpenVPN certificates or private key could not be validated"
        ) from None


def decode_openvpn_intent(
    system_cfg: str, *, udapi_caps: int, server_name: str
) -> OpenVpnClientIntent | None:
    """Read one imported certificate-authenticated client or its verified removal.

    The caller supplies the negotiated capability bits for this adopted gateway.
    Only parsed, allowlisted fields are returned. The input profile is never
    passed through to OpenVPN.
    """
    if not valid_openvpn_server_name(server_name):
        raise OpenVpnIntentError("OpenVPN requires a literal DNS-style server certificate common name")
    udapi = _snapshot(system_cfg, udapi_caps)
    _verify_wan(udapi.get("interfaces"))
    if _SECTION not in udapi:
        return None
    rows = udapi[_SECTION]
    if type(rows) is not list or len(rows) != 1 or type(rows[0]) is not dict:
        raise OpenVpnIntentError("OpenVPN snapshot must contain one native client")
    row = rows[0]
    if (
        row.keys()
        != {"id", "enabled", "localAddress", "authentication", "configuration"}
        or row["enabled"] is not True
        or row["localAddress"] != {"source": "wan", "ipVersion": "v4"}
        or type(row["id"]) is not str
        or _NATIVE_ID.fullmatch(row["id"]) is None
        or int(row["id"]) > 0x7FFFFFFF
    ):
        raise OpenVpnIntentError("OpenVPN client differs from the approved scope")
    auth = row["authentication"]
    if (
        type(auth) is not dict
        or auth.keys() != {"username", "password"}
        or any(
            type(value) is not str or _CREDENTIAL.fullmatch(value) is None
            for value in auth.values()
        )
    ):
        raise OpenVpnIntentError("OpenVPN client credentials have an unsupported form")
    port, material = _profile(row["configuration"], server_name)
    _verify_pki(material)
    return OpenVpnClientIntent(
        row["id"],
        _REMOTE,
        port,
        server_name,
        auth["username"],
        auth["password"],
        material["ca"],
        material["cert"],
        material["key"],
    )
