"""Report the verified policy-based VyOS tunnel through the native VPN inform list."""

import re
from uuid import UUID

from provisioners.vyos_ipsec import IpsecIntent, IpsecPeer, IpsecScope


_CONNECTION_HEADERS = (
    "Connection", "State", "Type", "Remote address", "Local TS", "Remote TS",
    "Local id", "Remote id", "Proposal", "PPK",
)
_SA_HEADERS = (
    "Connection", "State", "Uptime", "Bytes In/Out", "Packets In/Out", "Remote address", "Remote ID", "Proposal",
)
_PPK_BANNER = (
    "PPK Codes: none - Not Configured, opt - PPK is Optional, req - PPK is required, "
    "no - PPK not negotiated, yes - PPK negotiated"
)
_CONNECTION_PROPOSAL = "AES_CBC/256/HMAC_SHA2_256_128/MODP_2048"
_CHILD_PROPOSALS = {
    "AES_CBC/256/HMAC_SHA2_256_128/None": "AES_CBC_256/HMAC_SHA2_256_128",
    _CONNECTION_PROPOSAL: "AES_CBC_256/HMAC_SHA2_256_128/MODP_2048",
}
_DURATION = re.compile(r"(?:(?P<h>[1-9][0-9]{0,3})h)?(?:(?P<m>[1-9][0-9]?)m)?(?:(?P<s>[1-9][0-9]?)s)?")


class IpsecStatusError(ValueError):
    """The read-back does not prove the state of the applied native IPsec tunnel."""


def project_ipsec_status(
    intent: IpsecIntent, *, applied_revision: str, connections: str | None, sas: str | None,
) -> list[dict]:
    """Build a native VPN inform list from fresh VyOS connection and child-SA output."""
    if (
        not isinstance(intent, IpsecIntent) or not isinstance(intent.scope, IpsecScope)
        or not isinstance(applied_revision, str) or not applied_revision or intent.revision != applied_revision
    ):
        raise IpsecStatusError("IPsec telemetry requires the verified applied tunnel revision")
    if intent.peer is None:
        return []
    if not isinstance(intent.peer, IpsecPeer):
        raise IpsecStatusError("IPsec telemetry needs the decoded native peer")
    native_id = _native_id(intent.peer.native_id)
    scope = intent.scope
    child_name = f"{scope.name}-tunnel-0"
    configured = _table(connections, _CONNECTION_HEADERS, banner=_PPK_BANNER)
    active = _table(sas, _SA_HEADERS)
    if configured.keys() != {scope.name, child_name}:
        raise IpsecStatusError("VyOS IPsec connection list differs from the owned IKE and CHILD pair")

    ike, child = configured[scope.name], configured[child_name]
    peers = [scope.local_ip, scope.remote_peer]
    if (
        ike[1] not in {"up", "down"} or child[1] not in {"up", "down"}
        or ike[2:8] != ["IKEv2", scope.remote_peer, "-", "-", *peers]
        or child[2:8] != ["IPsec", scope.remote_peer, scope.local_selector, scope.remote_selector, *peers]
    ):
        raise IpsecStatusError("VyOS IPsec read-back does not match the pinned endpoints and selectors")

    result = {"id": f"/vpn/ipsec/site-to-site/{native_id}", "remotes": []}
    if child[1] == "down" and not active:
        return [result]
    child_proposal = _CHILD_PROPOSALS.get(child[8])
    if (
        ike[1] != "up" or child[1] != "up" or active.keys() != {child_name}
        or ike[8:] != [_CONNECTION_PROPOSAL, "none/no"] or child_proposal is None or child[9] != "-"
    ):
        raise IpsecStatusError("VyOS does not show the coordinated owned IKE and CHILD SAs")

    sa = active[child_name]
    if sa[1] != "up" or sa[5:] != [scope.remote_peer, scope.remote_peer, child_proposal]:
        raise IpsecStatusError("VyOS installed CHILD SA differs from the scoped peer or proposal")
    age = _uptime_seconds(sa[2])
    if type(intent.peer.esp_lifetime) is not int or age > intent.peer.esp_lifetime:
        raise IpsecStatusError("VyOS CHILD SA age exceeds the applied ESP lifetime")
    result["remotes"] = [{"ip": scope.remote_peer, "uptime": age}]
    return [result]


def _table(output, headers, *, banner=None):
    if not isinstance(output, str):
        raise IpsecStatusError("VyOS IPsec command did not return a table")
    lines = [line.strip() for line in output.splitlines() if line.strip()]
    if banner is not None:
        if not lines or lines[0] != banner:
            raise IpsecStatusError("VyOS IPsec connection table banner is unavailable")
        lines = lines[1:]
    if (len(lines) < 2 or tuple(re.split(r" {2,}", lines[0])) != headers
            or len(re.split(r" {2,}", lines[1])) != len(headers)
            or re.fullmatch(r"[- ]+", lines[1]) is None):
        raise IpsecStatusError("Unexpected VyOS IPsec table format")
    rows = {}
    for line in lines[2:]:
        columns = re.split(r" {2,}", line)
        if len(columns) != len(headers) or columns[0] in rows:
            raise IpsecStatusError("Unexpected or ambiguous row in VyOS IPsec table")
        rows[columns[0]] = columns
    return rows


def _native_id(value):
    try:
        identity = UUID(value) if isinstance(value, str) else None
    except ValueError:
        identity = None
    if identity is None or identity.version != 4 or str(identity) != value:
        raise IpsecStatusError("IPsec telemetry needs the canonical native network UUID")
    return value


def _uptime_seconds(value):
    duration = _DURATION.fullmatch(value)
    if not value or duration is None:
        raise IpsecStatusError("VyOS CHILD SA age is unavailable")
    hours, minutes, seconds = (int(item or 0) for item in duration.groups())
    if minutes >= 60 or seconds >= 60:
        raise IpsecStatusError("VyOS CHILD SA age is not a valid elapsed duration")
    return hours * 3600 + minutes * 60 + seconds
