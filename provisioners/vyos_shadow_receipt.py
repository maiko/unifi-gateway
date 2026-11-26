"""Operate the Shadow policy receipt with a dedicated pinned router SSH key."""

from dataclasses import asdict, dataclass
from ipaddress import ip_interface
import json
import re
from tempfile import TemporaryFile
from urllib.parse import urlsplit

from backends.vyos import VyOSReadError
from backends.vyos_failover import _invalid_constant, _run_helper, _unique_fields
from gateway_profiles.vyos_vrrp import observe_shadow_role
from backends.vyos_ssh import vyos_ssh_command, vyos_ssh_host_fingerprint
from provisioners.vyos_shadow_binding import ShadowManagementIdentity
from provisioners.vyos_shadow_complete import ShadowStockState


_DIGEST = re.compile(r"[a-f0-9]{64}")
_UUID = re.compile(r"[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}")
_HANDOFF_LIMIT = 256 * 1024
_HANDOFF_ROOTS = {"interfaces", "high-availability", "service"}


class ShadowReceiptError(RuntimeError):
    """The router did not verify the result. Read status after an ambiguous write."""


def _matches(pattern, value):
    return isinstance(value, str) and pattern.fullmatch(value) is not None


@dataclass(frozen=True)
class ShadowReceiptCandidate:
    boot_id: str
    sha256: str
    generation: str
    config_sha256: str

    def __post_init__(self):
        if (not _matches(_UUID, self.boot_id)
                or any(not _matches(_DIGEST, value) for value in (self.sha256, self.generation, self.config_sha256))):
            raise ValueError("Invalid Shadow receipt candidate")


@dataclass(frozen=True)
class ShadowPolicyReceipt:
    id: str
    sha256: str
    transaction: str | None
    config_sha256: str | None


@dataclass(frozen=True)
class ShadowReceiptStatus:
    generation: str
    receipt: ShadowPolicyReceipt | None


@dataclass(frozen=True)
class ShadowHandoffObservation:
    state: ShadowStockState
    role: str
    boot_id: str
    saved_sha256: str
    config_sha256: str
    rollback_action: str
    phase: str


def _handoff_fingerprint(commit_proof, *, phase, expected_boot_id):
    try:
        proof = commit_proof(phase=phase)
    except VyOSReadError as error:
        raise ShadowReceiptError("VyOS did not verify the commit for the Shadow handoff observation") from error
    if phase == "saved_commit":
        if not isinstance(proof, tuple) or len(proof) != 2:
            raise ShadowReceiptError("VyOS returned an invalid saved commit proof")
        boot_id, proof = proof
        if boot_id != expected_boot_id:
            raise ShadowReceiptError("Router boot changed during the saved commit proof")
    if not _matches(_DIGEST, proof):
        raise ShadowReceiptError("VyOS returned an invalid configuration fingerprint")
    return proof


def _handoff_tree(tree):
    if (not isinstance(tree, dict) or tree.keys() - _HANDOFF_ROOTS
            or any(not isinstance(branch, dict) for branch in tree.values())):
        return False
    availability = tree.get("high-availability", {})
    services = tree.get("service", {})
    return (not (availability.keys() - {"vrrp"} or services.keys() - {"conntrack-sync"})
            and all(isinstance(branch, dict) for branch in (*availability.values(), *services.values())))


def _handoff_kernel(rows):
    kernel = {}
    for row in rows:
        name = row["ifname"]
        if not isinstance(name, str) or not name or name in kernel:
            raise ValueError("Invalid Shadow kernel interface identity")
        addresses = []
        for entry in row["addr_info"]:
            version = {"inet": 4, "inet6": 6}.get(entry.get("family"))
            if version is None:
                continue
            local, prefix = entry["local"], entry["prefixlen"]
            if not isinstance(local, str) or "%" in local or type(prefix) is not int:
                raise ValueError("Invalid Shadow kernel address")
            address = ip_interface(f"{local}/{prefix}")
            if address.version != version:
                raise ValueError("Shadow kernel address does not match its family")
            addresses.append(address)
        kernel[name] = tuple(addresses)
    return kernel


class ShadowReceiptClient:
    def __init__(self, identity: ShadowManagementIdentity, *, port, user, key_file, known_hosts_file):
        host = urlsplit(identity.https_origin).hostname
        if vyos_ssh_host_fingerprint(host, port, known_hosts_file) != identity.ssh_host_key:
            raise ValueError("Shadow receipt SSH must pin the enrolled router host key")
        self._ssh = vyos_ssh_command(host, port, user, key_file, known_hosts_file)
        self._identity = identity

    @property
    def management_identity(self):
        return self._identity

    def status(self):
        return self._status(self._request({"op": "status"}))

    def verify_admission(self, *, boot_id, config_sha256, required_paths):
        if not _matches(_UUID, boot_id) or not _matches(_DIGEST, config_sha256):
            raise ValueError("Shadow admission requires the verified saved configuration")
        try:
            response = self._request({
                "op": "check-admission", "boot_id": boot_id, "config_sha256": config_sha256,
                "required_paths": [list(path) for path in required_paths],
            })
        except ShadowReceiptError as error:
            raise ShadowReceiptError("VyOS Shadow admission could not verify the receipt scope and saved preflight") from error
        if response.keys() != {"ready"} or response["ready"] is not True:
            raise ShadowReceiptError("VyOS did not return a valid Shadow admission result")

    def observe_standby_vrrp(self, *, boot_id, config_sha256, generation, interface, local, peer):
        if not _matches(_UUID, boot_id) or any(not _matches(_DIGEST, value) for value in (config_sha256, generation)):
            raise ValueError("Shadow VRRP observation requires the verified saved standby and receipt generation")
        response = self._request({"op": "observe-vrrp", "boot_id": boot_id, "config_sha256": config_sha256,
                                  "generation": generation})
        if (response.keys() != {"interface", "local", "peer", "version", "received"}
                or (response["interface"], response["local"], response["peer"]) != (interface, str(local), str(peer))
                or type(response["version"]) is not int or response["version"] not in (2, 3)
                or type(response["received"]) is not int or not 0 <= response["received"] <= 2):
            raise ShadowReceiptError("Router returned a mismatched Shadow VRRP observation")
        return response["received"] == 2

    def candidate(self, *, expected_boot_id, expected_config_sha256, required_paths=()):
        if not _matches(_UUID, expected_boot_id) or not _matches(_DIGEST, expected_config_sha256):
            raise ValueError("Shadow receipt preparation requires the verified router boot ID and commit fingerprint")
        request = {"op": "candidate"}
        if required_paths:
            request["required_paths"] = [list(path) for path in required_paths]
        result = self._request(request)
        try:
            candidate = ShadowReceiptCandidate(**result)
        except (TypeError, ValueError):
            raise ShadowReceiptError("Router returned an invalid Shadow receipt candidate") from None
        if candidate.boot_id != expected_boot_id:
            raise ShadowReceiptError("Router boot changed before the Shadow receipt was prepared")
        if candidate.config_sha256 != expected_config_sha256:
            raise ShadowReceiptError("Router saved commit changed before the Shadow receipt was prepared")
        return candidate

    def publish(self, transaction, candidate):
        if not _matches(_UUID, transaction) or not isinstance(candidate, ShadowReceiptCandidate):
            raise ValueError("Shadow receipt publication requires a transaction ID and a verified candidate")
        response = self._request({"op": "publish", "transaction": transaction, **asdict(candidate)})
        status = self._status(response)
        receipt = status.receipt
        if (receipt is None or status.generation != candidate.generation
                or (receipt.transaction, receipt.sha256, receipt.config_sha256)
                != (transaction, candidate.sha256, candidate.config_sha256)):
            raise ShadowReceiptError("Router did not verify the requested Shadow receipt publication")
        return receipt

    def revoke(self, receipt_id):
        if not _matches(_DIGEST, receipt_id):
            raise ValueError("Shadow receipt revocation requires the observed receipt ID")
        status = self._status(self._request({"op": "revoke", "receipt_id": receipt_id}))
        if status.receipt is not None:
            raise ShadowReceiptError("Router still reports an installed Shadow receipt")
        return status

    def fence(self, generation):
        if not _matches(_DIGEST, generation):
            raise ValueError("Shadow receipt fencing requires the observed generation")
        status = self._status(self._request({"op": "fence", "generation": generation}))
        if status.receipt is not None or status.generation == generation:
            raise ShadowReceiptError("Router did not fence the observed Shadow receipt generation")
        return status

    def observe_handoff_state(self, backend, commit_proof, *, phase, expected_boot_id, expected_saved_sha256=None):
        """Bind live role and addresses to the same router configuration and saved preimage."""
        if backend.management_origin != self._identity.https_origin:
            raise ValueError("Shadow observation must use the enrolled HTTPS management origin")
        if phase not in ("saved_commit", "staged", "staged_reboot", "completed") or not _matches(_UUID, expected_boot_id):
            raise ValueError("Shadow observation requires a commit phase and verified router boot ID")
        if (phase in ("staged", "staged_reboot") or expected_saved_sha256 is not None) and not _matches(_DIGEST, expected_saved_sha256):
            raise ValueError("Shadow observation requires the verified saved configuration digest")

        fingerprint = _handoff_fingerprint(commit_proof, phase=phase, expected_boot_id=expected_boot_id)
        observed = self._observe_handoff_projection(expected_boot_id, expected_saved_sha256)
        if phase == "saved_commit" and observed["running"] != observed["saved"]:
            raise ShadowReceiptError("Running and saved Shadow configurations disagree after the saved commit proof")
        try:
            rollback = backend.read_config(["system", "config-management", "commit-confirm"])
            kernel = _handoff_kernel(backend.show_kernel_interfaces())
            role = observe_shadow_role(backend)
        except (KeyError, TypeError, ValueError, VyOSReadError) as error:
            raise ShadowReceiptError("VyOS live state could not be verified during the Shadow handoff observation") from error
        action = "reboot" if rollback is None else rollback.get("action")
        if action not in ("reboot", "reload"):
            raise ShadowReceiptError("VyOS returned an unknown commit-confirm rollback action")
        if phase == "staged_reboot" and action != "reboot":
            raise ShadowReceiptError("VyOS configured rollback action disagrees with the armed reboot")
        final = self._observe_handoff_projection(expected_boot_id, expected_saved_sha256)
        confirmed = _handoff_fingerprint(commit_proof, phase=phase, expected_boot_id=expected_boot_id)
        if observed != final or fingerprint != confirmed:
            raise ShadowReceiptError("Router configuration changed during the Shadow handoff observation")
        return ShadowHandoffObservation(ShadowStockState(observed["running"], observed["saved"], kernel, projected=True), role,
                                        expected_boot_id, observed["saved_sha256"], fingerprint, action, phase)

    def _observe_handoff_projection(self, boot_id, saved_sha256):
        response = self._request({"op": "observe"}, limit=_HANDOFF_LIMIT)
        if (response.keys() != {"boot_id", "saved_sha256", "running", "saved"}
                or not _matches(_UUID, response["boot_id"]) or not _matches(_DIGEST, response["saved_sha256"])
                or not all(_handoff_tree(response[view]) for view in ("running", "saved"))):
            raise ShadowReceiptError("Router returned an invalid Shadow handoff projection")
        if response["boot_id"] != boot_id:
            raise ShadowReceiptError("Router boot changed during the Shadow handoff observation")
        if saved_sha256 is not None and response["saved_sha256"] != saved_sha256:
            raise ShadowReceiptError("Router saved configuration changed during the Shadow handoff observation")
        return response

    @staticmethod
    def _status(response):
        if response.keys() != {"receipt", "generation"} or not _matches(_DIGEST, response["generation"]):
            raise ShadowReceiptError("Router returned an invalid Shadow receipt status")
        receipt = response["receipt"]
        if receipt is None:
            return ShadowReceiptStatus(response["generation"], None)
        if (not isinstance(receipt, dict) or receipt.keys() != {"id", "sha256", "transaction", "config_sha256"}
                or not _matches(_DIGEST, receipt["id"]) or not _matches(_DIGEST, receipt["sha256"])
                or (receipt["transaction"] is not None and not _matches(_UUID, receipt["transaction"]))
                or (receipt["config_sha256"] is not None and (
                    receipt["transaction"] is None or not _matches(_DIGEST, receipt["config_sha256"])))):
            raise ShadowReceiptError("Router returned an invalid Shadow receipt record")
        return ShadowReceiptStatus(response["generation"], ShadowPolicyReceipt(**receipt))

    def _request(self, request, *, limit=4096):
        try:
            with TemporaryFile() as source:
                source.write(json.dumps(request).encode("ascii"))
                source.seek(0)
                body, status = _run_helper(self._ssh, reader="VyOS Shadow receipt SSH", limit=limit,
                                           stdin=source, timeout=22)
            if status != 0 or not body:
                raise ValueError
            response = json.loads(body, object_pairs_hook=_unique_fields, parse_constant=_invalid_constant)
            if not isinstance(response, dict):
                raise ValueError
        except (OSError, ValueError, RecursionError, VyOSReadError):
            raise ShadowReceiptError("VyOS did not verify the Shadow receipt request over pinned SSH") from None
        return response
