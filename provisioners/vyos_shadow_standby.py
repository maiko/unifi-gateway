"""Apply scoped firewall policy while a Shadow Mode standby remains fenced."""

from copy import deepcopy
from hashlib import sha256
from ipaddress import ip_interface
import json

from backends.vyos import VyOSReadError
from provisioners.uxg_enterprise_shadow import verify_interconnect, verify_no_vrrp_interconnect_conflict
from provisioners.vyos_shadow_complete import (
    SHADOW_SYNC_GROUP, SHADOW_VRRP_GROUP, SHADOW_VRRP_PARENTS, ShadowStockState,
    _absent_vrrp_parent, _address_leaf, _remove_config_subtree, _verify_configured_vips,
    standby_election_commands, verify_standby_backup, verify_standby_election_candidate,
)
from provisioners.vyos_shadow_handoff import SHADOW_HANDOFF, _DIGEST, _UUID, _identifier

STANDBY_POLICY = "shadow_standby_policy"
STANDBY_ELECTION = "shadow_standby_election"
STANDBY_POLICY_ROLLBACK = "last_shadow_standby_policy_rollback"
_PATHS = {"rules": ("firewall", "ipv4", "forward", "filter", "rule"),
          "rules_ipv6": ("firewall", "ipv6", "forward", "filter", "rule")}
_PROOFS = {"target", "snapshot_sha256", "config_sha256", "saved_sha256", "outside_sha256", "rules_sha256",
           "receipt_generation", "outside_scope_sha256"}
_PHASES = ("armed", "staged", "confirming", "saving", "saved", "unchanged")
_ELECTION_PATHS = (("high-availability", "vrrp", "group", SHADOW_VRRP_GROUP),
                   ("high-availability", "vrrp", "sync-group", SHADOW_SYNC_GROUP),
                   ("service", "conntrack-sync"))
_WITHDRAWING_ELECTION_PHASES = ("revoking", "revoked", "released")
_SAVED_ELECTION_PHASES = ("saved", "publishing", "published", *_WITHDRAWING_ELECTION_PHASES)
_VRRP_PARENT = "created_vrrp_parent"


def required_receipt_paths(interfaces, *, ipv6_enabled, management_guard=None):
    paths = (*_ELECTION_PATHS, *(_address_leaf(interface)[:-1] for interface in sorted(interfaces)), _PATHS["rules"][:-1])
    if ipv6_enabled:
        paths = (*paths, _PATHS["rules_ipv6"][:-1])
    if management_guard is not None:
        paths = (*paths, *management_guard.eligibility_paths)
    return tuple(dict.fromkeys(paths))


class ShadowStandbyPending(RuntimeError):
    """The standby is still converging after promotion eligibility changed."""


class _ShadowConcurrentMaster(ValueError):
    """The standby has taken ownership while the verified primary is still active."""


def validate_standby_rollback(record):
    if (not isinstance(record, dict) or record.keys() != {"target", "controller_revision"}
            or not isinstance(record["target"], str) or _DIGEST.fullmatch(record["target"]) is None
            or not _identifier(record["controller_revision"])):
        raise ValueError("Invalid saved Shadow Mode standby policy rollback")


def validate_standby_policy(record, reservation, fallback_revision):
    if (not isinstance(record, dict) or record.get("phase") not in _PHASES
            or not isinstance(reservation, dict) or reservation.get("phase") != "standby"):
        raise ValueError("Invalid Shadow Mode standby policy reservation")
    digests = _PROOFS.copy()
    if "mapped_resources_sha256" in record:
        digests.add("mapped_resources_sha256")
    if record["phase"] not in ("armed", "unchanged"):
        digests.add("staged_sha256")
    if record["phase"] == "saved":
        digests.add("final_saved_sha256")
    if (record.keys() != digests | {"phase", "boot_id", "fallback_revision", "controller_revision"}
            or record["target"] != reservation["target"] or record["fallback_revision"] != fallback_revision
            or not all(_identifier(record[key]) for key in ("fallback_revision", "controller_revision"))
            or not isinstance(record["boot_id"], str) or _UUID.fullmatch(record["boot_id"]) is None
            or any(not isinstance(record[key], str) or _DIGEST.fullmatch(record[key]) is None for key in digests)):
        raise ValueError("Invalid saved Shadow Mode standby policy")
    if (record.get("staged_sha256") == record["config_sha256"]
            or record.get("final_saved_sha256") == record["saved_sha256"]):
        raise ValueError("Shadow Mode standby policy checkpoint has an unchanged digest")


def _digest(value):
    return sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()).hexdigest()


def validate_standby_election(record, policy):
    if (not isinstance(policy, dict) or policy.get("phase") not in ("saved", "unchanged")
            or not isinstance(record, dict)
            or record.get("phase") not in ("armed", "staged", "confirming", "saving", "rolled_back", *_SAVED_ELECTION_PHASES)):
        raise ValueError("Shadow Mode standby election requires a saved policy checkpoint")
    digests = {"policy_sha256", "plan_sha256", "outside_sha256"}
    if record["phase"] not in ("armed", "rolled_back"):
        digests.add("candidate_sha256")
    if record["phase"] in _SAVED_ELECTION_PHASES:
        digests.add("final_saved_sha256")
    if record["phase"] in ("publishing", "published", *_WITHDRAWING_ELECTION_PHASES):
        digests.add("receipt_policy_sha256")
    if record["phase"] in ("published", *_WITHDRAWING_ELECTION_PHASES):
        digests.add("receipt_id")
        if "inform_binding_sha256" in record:
            digests.add("inform_binding_sha256")
    if record["phase"] == "released" or (record["phase"] == "revoked" and "revoked_generation" in record):
        digests.add("revoked_generation")
        if record.get("revoked_generation") == policy["receipt_generation"]:
            raise ValueError("Shadow Mode standby receipt generation did not change after withdrawal")
    fields = digests | {"phase"}
    if _VRRP_PARENT in record:
        ancestry = record[_VRRP_PARENT]
        if not isinstance(ancestry, list) or tuple(ancestry) not in ((), *SHADOW_VRRP_PARENTS):
            raise ValueError("Invalid saved Shadow Mode standby VRRP ancestry")
        fields.add(_VRRP_PARENT)
    if record["phase"] == "rolled_back" or (record["phase"] in _SAVED_ELECTION_PHASES and "boot_id" in record):
        if not isinstance(record.get("boot_id"), str) or _UUID.fullmatch(record["boot_id"]) is None:
            raise ValueError("Invalid Shadow Mode standby election recovery boot")
        fields.add("boot_id")
    if (record.keys() != fields
            or any(not isinstance(record[key], str) or _DIGEST.fullmatch(record[key]) is None for key in digests)
            or record["policy_sha256"] != _digest(policy)):
        raise ValueError("Invalid saved Shadow Mode standby election checkpoint")


def _election_outside(writer, management_guard, interconnect, created_vrrp_parent):
    current = deepcopy(writer.backend.read_complete_configuration())
    guard_paths = ()
    if management_guard is not None:
        management_guard.verify_stock(current, installed=True, interconnect=interconnect)
        guard_paths = management_guard.paths
    for path in (*_ELECTION_PATHS, *guard_paths):
        _remove_config_subtree(current, path)
    if created_vrrp_parent == []:
        current.setdefault("high-availability", {}).setdefault("vrrp", {})
    elif created_vrrp_parent == ["high-availability", "vrrp"]:
        current.setdefault("high-availability", {})
    return _digest(current)


def _election_plan_sha(plan, management_guard=None, created_vrrp_parent=None):
    resources = [plan.group, plan.sync_group, plan.conntrack]
    if management_guard is not None:
        resources.append(management_guard.create_commands())
    if created_vrrp_parent is not None:
        resources.append({_VRRP_PARENT: created_vrrp_parent})
    return _digest(resources)


def _verify_election_candidate(writer, receipt, plan, policy, checkpoint, verify_primary, *,
                               phase, saved_sha256=None, boot_id=None, installed_receipt=None, management_guard=None):
    boot_id = policy["boot_id"] if boot_id is None else boot_id
    generation = policy["receipt_generation"]
    scope = plan._resource_scope()

    def verify_receipt_slot():
        if installed_receipt is None:
            _check_receipt(receipt, generation)
        else:
            slot = receipt.status()
            if slot.generation != generation or slot.receipt != installed_receipt:
                raise ValueError("Shadow Mode standby receipt changed before BACKUP could be verified")

    verify_primary()
    verify_receipt_slot()
    candidate = receipt.observe_handoff_state(writer.backend, writer.commit_proof, phase=phase,
                                               expected_boot_id=boot_id, expected_saved_sha256=saved_sha256)
    preimage_sha256 = policy.get("final_saved_sha256", policy["saved_sha256"])
    if installed_receipt is None:
        verify_standby_election_candidate(plan, candidate, preimage_sha256=preimage_sha256)
    elif candidate.role == "backup":
        verify_standby_backup(plan, candidate)
    concurrent_master = installed_receipt is not None and candidate.role == "master"
    if not concurrent_master:
        verify_interconnect(writer.backend, scope.interconnect, str(scope.local_sync), require_carrier=True)
        verify_no_vrrp_interconnect_conflict(writer.backend)
    proof = (boot_id, candidate.config_sha256) if phase == "saved_commit" else candidate.config_sha256
    if (candidate.phase != phase or candidate.boot_id != boot_id
            or (saved_sha256 is not None and candidate.saved_sha256 != saved_sha256)
            or candidate.config_sha256 == policy.get("staged_sha256", policy["config_sha256"])
            or candidate.config_sha256 != checkpoint.get("candidate_sha256", candidate.config_sha256)
            or _election_outside(writer, management_guard, scope.interconnect, checkpoint.get(_VRRP_PARENT))
            != checkpoint["outside_sha256"]
            or writer.commit_proof(phase=phase) != proof):
        raise ValueError("Shadow Mode standby election differs from the verified candidate")
    verify_receipt_slot()
    if installed_receipt is not None and candidate.role != "backup":
        if concurrent_master:
            verify_primary()
            verify_receipt_slot()
            raise _ShadowConcurrentMaster("Shadow Mode standby took ownership while the primary was active")
        raise ShadowStandbyPending("Shadow Mode standby is waiting for BACKUP")
    return candidate


def stage_standby_election(writer, state, receipt, plan, *, preimage, verify_primary, management_guard=None):
    """Stage the stock election once under both journal locks, with the receipt kept empty."""
    policy = state.get(STANDBY_POLICY)
    if (not isinstance(policy, dict) or policy.get("phase") not in ("saved", "unchanged")
            or writer.commit_proof is None or writer.backend.management_origin != receipt.management_identity.https_origin):
        raise ValueError("Shadow Mode standby election needs verified saved policy on the enrolled router")
    fingerprint = policy.get("staged_sha256", policy["config_sha256"])
    saved_sha256 = policy.get("final_saved_sha256", policy["saved_sha256"])
    generation = policy["receipt_generation"]
    boot_id = policy["boot_id"]
    checkpoint = state.get(STANDBY_ELECTION)
    scope = plan._resource_scope()

    if checkpoint is None:
        if (preimage is None or preimage.boot_id != boot_id
                or (preimage.config_sha256, preimage.saved_sha256) != (fingerprint, saved_sha256)):
            raise ValueError("Shadow Mode standby election preimage differs from the verified policy")
        commands = standby_election_commands(plan, preimage)
        verify_primary()
        _check_receipt(receipt, generation)
        verify_interconnect(writer.backend, scope.interconnect, str(scope.local_sync), require_carrier=True)
        verify_no_vrrp_interconnect_conflict(writer.backend)
        stock = writer.backend.read_complete_configuration()
        ancestry = list(_absent_vrrp_parent(stock))
        if management_guard is not None:
            management_guard.verify_stock(stock, installed=False, interconnect=scope.interconnect)
            commands.extend(management_guard.create_commands())
        outside = _digest(stock)
        if writer.commit_proof(phase="saved_commit") != (boot_id, fingerprint):
            raise ValueError("Shadow Mode standby saved policy changed before election staging")
        _check_receipt(receipt, generation)
        checkpoint = {"phase": "armed", "policy_sha256": _digest(policy),
                      "plan_sha256": _election_plan_sha(plan, management_guard, ancestry), "outside_sha256": outside,
                      _VRRP_PARENT: ancestry}
        validate_standby_election(checkpoint, policy)
        state[STANDBY_ELECTION] = checkpoint
        writer._write_state(state, durable=True)
        writer.backend.stage_configuration(commands, confirm_minutes=2)
    else:
        validate_standby_election(checkpoint, policy)
        if (checkpoint["phase"] not in ("armed", "staged")
                or checkpoint["plan_sha256"] != _election_plan_sha(plan, management_guard, checkpoint.get(_VRRP_PARENT))):
            raise ValueError("Shadow Mode standby election changed during staging")

    staged = _verify_election_candidate(writer, receipt, plan, policy, checkpoint, verify_primary,
                                        phase="staged_reboot", saved_sha256=saved_sha256, management_guard=management_guard)
    if checkpoint["phase"] == "armed":
        checkpoint = checkpoint | {"phase": "staged", "candidate_sha256": staged.config_sha256}
        validate_standby_election(checkpoint, policy)
        state[STANDBY_ELECTION] = checkpoint
        writer._write_state(state, durable=True)
    return staged


def _confirm_and_save_standby_election(writer, state, receipt, plan, *, verify_primary, saved_proof, management_guard):
    """Verify and save the election while both the old applied revision and the receipt fence hold."""
    policy = state.get(STANDBY_POLICY)
    record = state.get(STANDBY_ELECTION)
    validate_standby_election(record, policy)
    if (record["plan_sha256"] != _election_plan_sha(plan, management_guard, record.get(_VRRP_PARENT))
            or record["phase"] == "armed"):
        raise ValueError("Shadow Mode standby election requires a verified timed stage")
    preimage_sha256 = policy.get("final_saved_sha256", policy["saved_sha256"])

    def verify(phase, *, saved_sha256=None, boot_id=None):
        return _verify_election_candidate(writer, receipt, plan, policy, record, verify_primary,
                                          phase=phase, saved_sha256=saved_sha256, boot_id=boot_id,
                                          management_guard=management_guard)

    def checkpoint(phase, **fields):
        updated = record | {"phase": phase} | fields
        validate_standby_election(updated, policy)
        state[STANDBY_ELECTION] = updated
        writer._write_state(state, durable=True)
        return updated

    if record["phase"] in ("saving", "saved") and saved_proof is not None and saved_proof[1] == record["candidate_sha256"]:
        saved = verify("saved_commit", saved_sha256=record.get("final_saved_sha256"), boot_id=saved_proof[0])
        if saved.saved_sha256 == preimage_sha256:
            raise ValueError("Shadow Mode standby election did not reach saved configuration")
        if record["phase"] == "saving" or saved.boot_id != record.get("boot_id", policy["boot_id"]):
            checkpoint("saved", final_saved_sha256=saved.saved_sha256, boot_id=saved.boot_id)
        return saved
    if record["phase"] == "saved":
        raise ValueError("Shadow Mode standby election saved proof differs from the reserved candidate")
    if record["phase"] == "staged":
        verify("staged_reboot", saved_sha256=preimage_sha256)
        record = checkpoint("confirming")
        writer.backend.confirm_configuration()

    completed = verify("completed")
    if record["phase"] == "confirming":
        if completed.saved_sha256 != preimage_sha256:
            raise ValueError("Shadow Mode standby election saved preimage changed before saving")
        record = checkpoint("saving")
    if completed.saved_sha256 == preimage_sha256:
        writer.backend.save_configuration()
        completed = verify("completed")
        if completed.saved_sha256 == preimage_sha256:
            raise ValueError("Shadow Mode standby election did not reach saved configuration")
    saved = verify("saved_commit", saved_sha256=completed.saved_sha256)
    checkpoint("saved", final_saved_sha256=saved.saved_sha256)
    return saved


def _recover_standby_election_rollback(writer, state, receipt, plan, policy, record, verify_primary, boot_id):
    fingerprint = policy.get("staged_sha256", policy["config_sha256"])
    saved_sha256 = policy.get("final_saved_sha256", policy["saved_sha256"])
    generation = policy["receipt_generation"]
    scope = plan._resource_scope()
    verify_primary()
    _check_receipt(receipt, generation)
    restored = _observe(writer, receipt, lambda stock: stock._verify_fenced(scope),
                        phase="saved_commit", boot_id=boot_id, saved_sha256=saved_sha256)
    standby_election_commands(plan, restored)
    verify_interconnect(writer.backend, scope.interconnect, str(scope.local_sync), require_carrier=True)
    verify_no_vrrp_interconnect_conflict(writer.backend)
    if ((restored.config_sha256, restored.saved_sha256) != (fingerprint, saved_sha256)
            or _digest(writer.backend.read_complete_configuration()) != record["outside_sha256"]
            or writer.commit_proof(phase="saved_commit") != (boot_id, fingerprint)):
        raise ValueError("Shadow Mode standby election rollback did not restore the verified policy preimage")
    _check_receipt(receipt, generation)
    checkpoint = {key: record[key] for key in ("policy_sha256", "plan_sha256", "outside_sha256")}
    if _VRRP_PARENT in record:
        checkpoint[_VRRP_PARENT] = record[_VRRP_PARENT]
    checkpoint.update(phase="rolled_back", boot_id=boot_id)
    validate_standby_election(checkpoint, policy)
    state[STANDBY_ELECTION] = checkpoint
    writer._write_state(state, durable=True)


def advance_standby_election(writer, state, receipt, plan, *, preimage, verify_primary, management_guard=None):
    """Advance or recover a fenced election, with the transaction authenticated by the caller."""
    record = state.get(STANDBY_ELECTION)
    saved = None
    if record is not None:
        policy = state[STANDBY_POLICY]
        validate_standby_election(record, policy)
        if record["plan_sha256"] != _election_plan_sha(plan, management_guard, record.get(_VRRP_PARENT)):
            raise ValueError("Shadow Mode standby election differs from the reserved plan")
        if record["phase"] == "rolled_back":
            raise ValueError("Shadow Mode standby election already rolled back")
        if record["phase"] in ("publishing", "published", *_WITHDRAWING_ELECTION_PHASES):
            raise ValueError("Shadow Mode standby election already entered receipt publication")
        try:
            saved = writer.commit_proof(phase="saved_commit")
        except VyOSReadError:
            if record["phase"] == "saved":
                raise
        if saved is not None and saved[0] != record.get("boot_id", policy["boot_id"]):
            if record["phase"] != "saved" and saved[1] == policy.get("staged_sha256", policy["config_sha256"]):
                _recover_standby_election_rollback(
                    writer, state, receipt, plan, policy, record, verify_primary, saved[0],
                )
                raise ValueError("Shadow Mode standby election already rolled back")
            if record["phase"] not in ("saving", "saved") or saved[1] != record["candidate_sha256"]:
                raise ValueError("Shadow Mode standby reboot differs from the reserved election and policy preimage")
    if record is None or record["phase"] == "armed":
        stage_standby_election(writer, state, receipt, plan, preimage=preimage, verify_primary=verify_primary,
                               management_guard=management_guard)
    return _confirm_and_save_standby_election(writer, state, receipt, plan, verify_primary=verify_primary, saved_proof=saved,
                                             management_guard=management_guard)


def publish_standby_election(writer, state, receipt, plan, *, management_guard, verify_primary, verify_ready):
    """Publish the exact standby activation receipt after an independent readiness check."""
    policy, record, reservation = (state.get(key) for key in (STANDBY_POLICY, STANDBY_ELECTION, SHADOW_HANDOFF))
    validate_standby_election(record, policy)
    transaction = reservation.get("transaction") if isinstance(reservation, dict) else None
    if (record["phase"] not in ("saved", "publishing", "published")
            or record["plan_sha256"] != _election_plan_sha(plan, management_guard, record.get(_VRRP_PARENT))
            or not isinstance(transaction, str) or _UUID.fullmatch(transaction) is None
            or reservation.get("phase") != "standby" or writer.commit_proof is None
            or writer.backend.management_origin != receipt.management_identity.https_origin):
        raise ValueError("Shadow Mode receipt publication requires a saved election on the reserved standby")
    generation = policy["receipt_generation"]
    expected_config = record["candidate_sha256"]

    def checkpoint(phase, **proofs):
        updated = record | {"phase": phase} | proofs
        validate_standby_election(updated, policy)
        state[STANDBY_ELECTION] = updated
        writer._write_state(state, durable=True)
        return updated

    verify_primary()
    slot = receipt.status()
    if slot.generation != generation or (record["phase"] == "saved" and slot.receipt is not None):
        raise ValueError("Shadow Mode standby receipt fence changed before publication")
    if slot.receipt is None and record["phase"] != "published":
        boot_id, live_config = writer.commit_proof(phase="saved_commit")
        if live_config != expected_config:
            raise ValueError("Shadow Mode standby receipt requires the verified saved election")
        _verify_election_candidate(writer, receipt, plan, policy, record, verify_primary,
                                   phase="saved_commit", saved_sha256=record["final_saved_sha256"], boot_id=boot_id,
                                   management_guard=management_guard)
        scope = plan._resource_scope()
        interfaces = {scope.interconnect, scope.election, *(interface for _, interface in scope.vips)}
        if management_guard is not None:
            management_guard.verify_stock(writer.backend.read_complete_configuration(), installed=True,
                                          interconnect=scope.interconnect)
        paths = required_receipt_paths(interfaces, ipv6_enabled=bool(writer.ipv6_interfaces), management_guard=management_guard)
        candidate = receipt.candidate(
            expected_boot_id=boot_id, expected_config_sha256=expected_config, required_paths=paths,
        )
        if candidate.generation != generation or candidate.sha256 != record.get("receipt_policy_sha256", candidate.sha256):
            raise ValueError("Shadow Mode standby receipt candidate changed")
        if verify_ready(boot_id=candidate.boot_id, config_sha256=candidate.config_sha256, generation=candidate.generation) is not True:
            raise ValueError("Shadow Mode standby activation readiness could not be verified")
        verify_primary()
        _check_receipt(receipt, generation)
        if record["phase"] == "saved" or record.get("boot_id", policy["boot_id"]) != boot_id:
            record = checkpoint("publishing", receipt_policy_sha256=candidate.sha256, boot_id=boot_id)
        receipt.publish(transaction, candidate)
        slot = receipt.status()

    installed = _match_standby_receipt(slot, record, transaction, generation)
    if record["phase"] == "publishing":
        checkpoint("published", receipt_id=installed.id)
    return installed


def _match_standby_receipt(slot, record, transaction, generation):
    installed = slot.receipt
    if (slot.generation != generation or installed is None
            or (installed.transaction, installed.sha256, installed.config_sha256)
            != (transaction, record["receipt_policy_sha256"], record["candidate_sha256"])
            or installed.id != record.get("receipt_id", installed.id)):
        raise ValueError("Shadow Mode standby receipt does not match its recorded publication")
    return installed


def verify_published_standby_election(writer, state, receipt, plan, *, management_guard, verify_primary,
                                      inform_binding_sha256):
    """Verify BACKUP against the published receipt and current active primary."""
    policy, record, reservation = (state.get(key) for key in (STANDBY_POLICY, STANDBY_ELECTION, SHADOW_HANDOFF))
    validate_standby_election(record, policy)
    if record["phase"] not in ("published", *_WITHDRAWING_ELECTION_PHASES) or record["plan_sha256"] != _election_plan_sha(
        plan, management_guard, record.get(_VRRP_PARENT),
    ):
        raise ValueError("Shadow Mode BACKUP requires a published standby election")
    if (not isinstance(inform_binding_sha256, str) or _DIGEST.fullmatch(inform_binding_sha256) is None
            or record.get("inform_binding_sha256", inform_binding_sha256) != inform_binding_sha256):
        raise ValueError("Shadow Mode BACKUP acknowledgement identity changed")
    if record["phase"] in _WITHDRAWING_ELECTION_PHASES:
        _finish_concurrent_standby_recovery(writer, state, receipt, policy, record, reservation["transaction"],
                                           verify_primary=verify_primary)
    installed = _match_standby_receipt(receipt.status(), record, reservation["transaction"], policy["receipt_generation"])
    boot_id, fingerprint = writer.commit_proof(phase="saved_commit")
    if fingerprint != record["candidate_sha256"]:
        raise ValueError("Shadow Mode BACKUP differs from the saved election")
    if management_guard is not None:
        management_guard.verify_stock(writer.backend.read_complete_configuration(), installed=True,
                                      interconnect=plan._resource_scope().interconnect)
    try:
        backup = _verify_election_candidate(
            writer, receipt, plan, policy, record, verify_primary, phase="saved_commit",
            saved_sha256=record["final_saved_sha256"], boot_id=boot_id, installed_receipt=installed,
            management_guard=management_guard,
        )
    except _ShadowConcurrentMaster:
        pending = record | {"phase": "revoking"}
        validate_standby_election(pending, policy)
        state[STANDBY_ELECTION] = pending
        writer._write_state(state, durable=True)
        _finish_concurrent_standby_recovery(writer, state, receipt, policy, pending, reservation["transaction"],
                                           verify_primary=verify_primary)
    if "inform_binding_sha256" not in record:
        verified = record | {"inform_binding_sha256": inform_binding_sha256}
        validate_standby_election(verified, policy)
        state[STANDBY_ELECTION] = verified
        writer._write_state(state, durable=True)
    return backup


def verify_standby_inform(writer, state, receipt, *, inform_binding_sha256, expected_role="backup"):
    """Verify the saved election and receipt before acknowledging the applied standby revision."""
    policy, record, reservation = (state.get(key) for key in (STANDBY_POLICY, STANDBY_ELECTION, SHADOW_HANDOFF))
    validate_standby_election(record, policy)
    if (expected_role not in ("master", "backup") or record["phase"] != "published" or "inform_binding_sha256" not in record
            or record["inform_binding_sha256"] != inform_binding_sha256 or writer.commit_proof is None
            or not isinstance(reservation, dict) or reservation.get("phase") != "standby"):
        raise ValueError("Shadow Mode standby lacks a verified BACKUP acknowledgement")
    generation = policy["receipt_generation"]
    transaction = reservation["transaction"]
    installed = _match_standby_receipt(receipt.status(), record, transaction, generation)
    boot_id, fingerprint = writer.commit_proof(phase="saved_commit")
    if fingerprint != record["candidate_sha256"]:
        raise ValueError("Shadow Mode standby applied commit changed")
    live = receipt.observe_handoff_state(
        writer.backend, writer.commit_proof, phase="saved_commit", expected_boot_id=boot_id,
        expected_saved_sha256=record["final_saved_sha256"],
    )
    if (live.role != expected_role or live.phase != "saved_commit" or live.boot_id != boot_id
            or live.config_sha256 != fingerprint or live.saved_sha256 != record["final_saved_sha256"]
            or _match_standby_receipt(receipt.status(), record, transaction, generation) != installed):
        raise ValueError(f"Shadow Mode standby cannot verify current {expected_role.upper()}")
    return policy["controller_revision"]


def _revoke_concurrent_standby(writer, state, receipt, policy, record, transaction, verify_primary):
    """Finish fencing the exact receipt after concurrent ownership was verified."""
    slot = receipt.status()
    generation = policy["receipt_generation"]
    if slot.receipt is not None:
        _match_standby_receipt(slot, record, transaction, generation)
        if verify_primary is None:
            return False
        verify_primary()
    # An empty slot only accepts this request if it holds the exact receipt's tombstone.
    revoked = receipt.revoke(record["receipt_id"])
    if revoked.receipt is not None or revoked.generation == generation or receipt.status() != revoked:
        raise ValueError("Shadow Mode standby receipt revocation could not be verified")
    final = record | {"phase": "revoked", "revoked_generation": revoked.generation}
    validate_standby_election(final, policy)
    state[STANDBY_ELECTION] = final
    writer._write_state(state, durable=True)
    return True


def _finish_concurrent_standby_recovery(writer, state, receipt, policy, record, transaction, *, verify_primary):
    if record["phase"] == "released":
        raise ValueError("Shadow Mode standby released its virtual IPs after concurrent MASTER")
    if "revoked_generation" not in record:
        _revoke_concurrent_standby(writer, state, receipt, policy, record, transaction, verify_primary)
    verify_revoked_standby_release(writer, state, receipt)
    raise ValueError("Shadow Mode standby released its virtual IPs after concurrent MASTER")


def verify_revoked_standby_release(writer, state, receipt):
    """Complete local read-back after receipt withdrawal without requiring a controller response."""
    policy, record = state.get(STANDBY_POLICY), state.get(STANDBY_ELECTION)
    validate_standby_election(record, policy)
    if record["phase"] == "revoking":
        transaction = state[SHADOW_HANDOFF]["transaction"]
        if not _revoke_concurrent_standby(writer, state, receipt, policy, record, transaction, verify_primary=None):
            return
        record = state[STANDBY_ELECTION]
    if record["phase"] != "revoked" or "revoked_generation" not in record:
        raise ValueError("Shadow Mode VIP release requires the verified withdrawn receipt")
    generation = record["revoked_generation"]
    _check_receipt(receipt, generation)
    boot_id, fingerprint = writer.commit_proof(phase="saved_commit")
    if fingerprint != record["candidate_sha256"]:
        raise ValueError("Shadow Mode standby commit changed while verifying VIP release")
    live = receipt.observe_handoff_state(
        writer.backend, writer.commit_proof, phase="saved_commit", expected_boot_id=boot_id,
        expected_saved_sha256=record["final_saved_sha256"],
    )
    if ((live.phase, live.boot_id, live.config_sha256, live.saved_sha256)
            != ("saved_commit", boot_id, fingerprint, record["final_saved_sha256"])):
        raise ValueError("Shadow Mode standby saved proof changed while verifying VIP release")
    group = ShadowStockState.read(live.state.running, _ELECTION_PATHS[0])
    addresses = group.get("address") if isinstance(group, dict) and group.get("priority") == "100" else None
    if not isinstance(addresses, dict) or not addresses:
        raise ValueError("Shadow Mode standby lost its saved election while verifying VIP release")
    vips = {ip_interface(value).ip for value in addresses}
    if live.role != "fault" or any(address.ip in vips for rows in live.state.kernel.values() for address in rows):
        raise ShadowStandbyPending("Shadow Mode standby receipt was withdrawn and VIP release is pending")
    if writer.commit_proof(phase="saved_commit") != (boot_id, fingerprint):
        raise ValueError("Shadow Mode standby configuration changed while verifying VIP release")
    _check_receipt(receipt, generation)
    final = record | {"phase": "released"}
    validate_standby_election(final, policy)
    state[STANDBY_ELECTION] = final
    writer._write_state(state, durable=True)


def standby_election_withdrawal_commands(writer, state, receipt, plan, *, management_guard=None):
    """Plan persistent standby withdrawal from a fresh proof that its election is fenced."""
    policy, record, reservation = (state.get(key) for key in (STANDBY_POLICY, STANDBY_ELECTION, SHADOW_HANDOFF))
    validate_standby_election(record, policy)
    ancestry = record.get(_VRRP_PARENT)
    if (record["phase"] != "released" or not isinstance(reservation, dict) or reservation.get("phase") != "standby"
            or not isinstance(policy.get("target"), str) or _DIGEST.fullmatch(policy["target"]) is None
            or policy["target"] != reservation.get("target")
            or writer.commit_proof is None or writer.backend.management_origin != receipt.management_identity.https_origin
            or record["plan_sha256"] != _election_plan_sha(plan, management_guard, ancestry)):
        raise ValueError("Shadow Mode standby withdrawal requires a matching released election")
    generation = record["revoked_generation"]
    _check_receipt(receipt, generation)
    boot_id, fingerprint = writer.commit_proof(phase="saved_commit")
    if fingerprint != record["candidate_sha256"]:
        raise ValueError("Shadow Mode standby saved election changed before withdrawal")
    live = receipt.observe_handoff_state(
        writer.backend, writer.commit_proof, phase="saved_commit", expected_boot_id=boot_id,
        expected_saved_sha256=record["final_saved_sha256"],
    )
    if ((live.phase, live.role, live.boot_id, live.config_sha256, live.saved_sha256)
            != ("saved_commit", "fault", boot_id, fingerprint, record["final_saved_sha256"])):
        raise ValueError("Shadow Mode standby withdrawal requires a current fenced observation")
    # The settled commit proof attests that the complete running tree matches saved.
    current = writer.backend.read_complete_configuration()
    scope = plan._resource_scope()
    scope.verify_kernel(live.state.kernel, expected=())
    _verify_configured_vips(current, scope.vips, None)
    commands = plan.withdraw_stock_commands(ShadowStockState(current, current, live.state.kernel),
                                           created_vrrp_parent=tuple(ancestry or ()))
    if writer.commit_proof(phase="saved_commit") != (boot_id, fingerprint):
        raise ValueError("Shadow Mode standby saved election changed during withdrawal planning")
    _check_receipt(receipt, generation)
    return commands


def _firewall_proofs(writer):
    config = writer.backend.read_complete_configuration()
    outside = deepcopy(config)
    managed = {}
    for name, path in _PATHS.items():
        owns_family = name == "rules" or bool(writer.ipv6_interfaces)
        raw = ShadowStockState.read(config, path)
        if raw is not None and not isinstance(raw, dict):
            raise ValueError("VyOS returned invalid standby firewall rules")
        rules = {slot: raw[slot] for slot in writer.slots if raw is not None and owns_family and slot in raw}
        managed[name] = writer._normalize_firewall_rules(rules)
        for slot in rules:
            _remove_config_subtree(outside, (*path, slot))
    return _digest(outside), _digest(managed)


def _verify_plan(writer, state, plan, revision):
    families = tuple(_PATHS[name] for name in _PATHS if name == "rules" or writer.ipv6_interfaces)
    if (plan is None or plan.revision != revision
            or state.get("verified_lan_chain") is not None or state.get("verified_lan_chain_ipv6") is not None
            or any(set(plan.desired[name]) - set(writer.slots) for name in _PATHS)
            or any(rule.get("action") == "jump" for name in _PATHS for rule in plan.desired[name].values())
            or any(value != state[f"verified_{name}"] for name, value in plan.desired.items() if name not in _PATHS)):
        raise ValueError("Shadow Mode standby requires a verified owned flat firewall policy")
    changed = {path: {slot for slot in state[f"verified_{name}"].keys() | plan.desired[name].keys()
                      if state[f"verified_{name}"].get(slot) != plan.desired[name].get(slot)}
               for name, path in _PATHS.items()}
    for command in plan.commands:
        path = command["path"]
        if command["op"] not in ("set", "delete") or not any(
            len(path) > len(prefix) and tuple(path[:len(prefix)]) == prefix and path[len(prefix)] != "1"
            and path[len(prefix)] in writer.slots and path[len(prefix)] in changed[prefix] for prefix in families
        ):
            raise ValueError("Shadow Mode standby command falls outside the changed owned forwarding rules")


def _check_receipt(receipt, generation):
    slot = receipt.status()
    if slot.receipt is not None or slot.generation != generation:
        raise ValueError("Shadow Mode standby receipt fence changed during the policy transaction")


def _observe(writer, receipt, verify_fenced, *, phase, boot_id, saved_sha256=None):
    evidence = receipt.observe_handoff_state(writer.backend, writer.commit_proof, phase=phase,
                                             expected_boot_id=boot_id, expected_saved_sha256=saved_sha256)
    if evidence.phase != phase or evidence.boot_id != boot_id or evidence.role not in ("unknown", "fault"):
        raise ValueError("Shadow Mode standby observation does not prove a fenced router")
    verify_fenced(evidence.state)
    return evidence


def _policy_reservation(writer, state, receipt, revision, snapshot_sha256, approved_outside_scope, outside_scope,
                        mapped_resources_sha256):
    reservation = state.get(SHADOW_HANDOFF)
    if (not isinstance(reservation, dict) or reservation.get("phase") != "standby"
            or state.get("pending") is not None or writer.commit_proof is None
            or writer.backend.management_origin != receipt.management_identity.https_origin):
        raise ValueError("Shadow Mode policy requires the reserved standby")
    if (not isinstance(approved_outside_scope, str) or _DIGEST.fullmatch(approved_outside_scope) is None
            or outside_scope != approved_outside_scope):
        raise ValueError("Shadow Mode standby policy outside managed scopes is unverified")
    if not _identifier(revision) or not isinstance(snapshot_sha256, str) or _DIGEST.fullmatch(snapshot_sha256) is None:
        raise ValueError("Shadow Mode standby policy requires an authenticated revision and snapshot")

    record = state.get(STANDBY_POLICY)
    if record is not None:
        validate_standby_policy(record, reservation, state["verified_revision"])
        if (record["controller_revision"] != revision or record["snapshot_sha256"] != snapshot_sha256
                or record["outside_scope_sha256"] != outside_scope):
            raise ValueError("Shadow Mode standby snapshot changed during policy application")
        if record.get("mapped_resources_sha256", mapped_resources_sha256) != mapped_resources_sha256:
            raise ValueError("Shadow Mode standby physical resource mapping changed")
    return reservation, record


def stage_standby_policy(writer, state, receipt, *, revision, snapshot_sha256, plan,
                         verify_fenced, verify_primary, approved_outside_scope, outside_scope,
                         mapped_resources_sha256=None):
    """Stage once or verify a pending stage. The authenticated caller holds both journals' locks."""
    reservation, record = _policy_reservation(
        writer, state, receipt, revision, snapshot_sha256, approved_outside_scope, outside_scope, mapped_resources_sha256,
    )
    if record is None:
        if state.get(STANDBY_POLICY_ROLLBACK) == {"target": reservation["target"], "controller_revision": revision}:
            raise ValueError("Shadow Mode standby policy revision already rolled back")
        _verify_plan(writer, state, plan, revision)
        ordinary = _observe(writer, receipt, verify_fenced, phase="saved_commit", boot_id=plan.boot_id)
        outside, active_rules = _firewall_proofs(writer)
        desired_rules = _digest({name: plan.desired[name] for name in _PATHS})
        if (ordinary.rollback_action != "reboot" or ordinary.config_sha256 != plan.configuration_sha256
                or bool(plan.commands) != (desired_rules != active_rules)
                or active_rules != _digest({name: state[f"verified_{name}"] for name in _PATHS})):
            raise ValueError("Shadow Mode standby preimage changed since planning")
        slot = receipt.status()
        if slot.receipt is not None:
            raise ValueError("Shadow Mode standby requires an empty receipt before policy staging")
        verify_primary()
        fenced = receipt.fence(slot.generation)
        _check_receipt(receipt, fenced.generation)
        if writer.commit_proof(phase="saved_commit") != (plan.boot_id, plan.configuration_sha256):
            raise ValueError("Shadow Mode standby saved proof changed before policy staging")
        record = {
            "phase": "armed" if plan.commands else "unchanged",
            "target": reservation["target"], "boot_id": plan.boot_id,
            "fallback_revision": state["verified_revision"], "controller_revision": revision,
            "snapshot_sha256": snapshot_sha256, "config_sha256": plan.configuration_sha256,
            "saved_sha256": ordinary.saved_sha256, "outside_sha256": outside, "rules_sha256": desired_rules,
            "receipt_generation": fenced.generation, "outside_scope_sha256": outside_scope,
        }
        if mapped_resources_sha256 is not None:
            record["mapped_resources_sha256"] = mapped_resources_sha256
        validate_standby_policy(record, reservation, state["verified_revision"])
        state[STANDBY_POLICY] = record
        writer._write_state(state, durable=True)
        if not plan.commands:
            return ordinary
        writer.backend.stage_configuration(list(plan.commands), confirm_minutes=2)
    elif record["phase"] not in ("armed", "staged"):
        raise ValueError("Shadow Mode standby policy has advanced past staging")

    _check_receipt(receipt, record["receipt_generation"])
    staged = _observe(writer, receipt, verify_fenced, phase="staged_reboot", boot_id=record["boot_id"],
                      saved_sha256=record["saved_sha256"])
    if (staged.rollback_action != "reboot" or staged.saved_sha256 != record["saved_sha256"]
            or staged.config_sha256 == record["config_sha256"]
            or staged.config_sha256 != record.get("staged_sha256", staged.config_sha256)
            or _firewall_proofs(writer) != (record["outside_sha256"], record["rules_sha256"])
            or writer.commit_proof(phase="staged_reboot") != staged.config_sha256):
        raise ValueError("Shadow Mode standby staged policy differs from the reserved intent")
    verify_primary()
    _check_receipt(receipt, record["receipt_generation"])
    if record["phase"] == "armed":
        state[STANDBY_POLICY] = record | {"phase": "staged", "staged_sha256": staged.config_sha256}
        validate_standby_policy(state[STANDBY_POLICY], reservation, state["verified_revision"])
        writer._write_state(state, durable=True)
    return staged


def _verify_candidate(writer, receipt, record, verify_fenced, verify_primary, *, phase, saved_sha256=None):
    verify_primary()
    _check_receipt(receipt, record["receipt_generation"])
    candidate = _observe(writer, receipt, verify_fenced, phase=phase, boot_id=record["boot_id"],
                         saved_sha256=saved_sha256)
    fingerprint = record.get("staged_sha256", record["config_sha256"])
    proof = (record["boot_id"], fingerprint) if phase == "saved_commit" else fingerprint
    if (candidate.rollback_action != "reboot" or candidate.config_sha256 != fingerprint
            or (saved_sha256 is not None and candidate.saved_sha256 != saved_sha256)
            or _firewall_proofs(writer) != (record["outside_sha256"], record["rules_sha256"])
            or writer.commit_proof(phase=phase) != proof):
        raise ValueError("Shadow Mode standby candidate differs from the reserved intent")
    _check_receipt(receipt, record["receipt_generation"])
    return candidate


def confirm_and_save_standby_policy(writer, state, receipt, *, revision, snapshot_sha256,
                                    verify_fenced, verify_primary, approved_outside_scope, outside_scope,
                                    mapped_resources_sha256=None):
    """Verify and persist the staged candidate under both journal locks with the standby fenced."""
    reservation, record = _policy_reservation(
        writer, state, receipt, revision, snapshot_sha256, approved_outside_scope, outside_scope, mapped_resources_sha256,
    )
    if record is None or record["phase"] == "armed":
        raise ValueError("Shadow Mode standby requires a verified staged policy before confirming")

    def checkpoint(phase, **proofs):
        updated = record | {"phase": phase} | proofs
        validate_standby_policy(updated, reservation, state["verified_revision"])
        state[STANDBY_POLICY] = updated
        writer._write_state(state, durable=True)
        return updated

    def verify(phase, *, saved_sha256=None):
        return _verify_candidate(writer, receipt, record, verify_fenced, verify_primary,
                                 phase=phase, saved_sha256=saved_sha256)

    phase = record["phase"]
    if phase in ("saving", "saved", "unchanged"):
        try:
            saved_proof = writer.commit_proof(phase="saved_commit")
        except VyOSReadError:
            if phase != "saving":
                raise
            # An unpersisted candidate in the saving phase still needs completed proof.
            saved_proof = None
        fingerprint = record.get("staged_sha256", record["config_sha256"])
        if saved_proof is not None and saved_proof[1] == fingerprint:
            old_boot = record["boot_id"]
            record = record | {"boot_id": saved_proof[0]}
            validate_standby_policy(record, reservation, state["verified_revision"])
            saved_sha256 = record["saved_sha256"] if phase == "unchanged" else record.get("final_saved_sha256")
            saved = verify("saved_commit", saved_sha256=saved_sha256)
            if phase == "saving":
                if saved.saved_sha256 == record["saved_sha256"]:
                    raise ValueError("Shadow Mode standby candidate did not reach saved storage")
                checkpoint("saved", final_saved_sha256=saved.saved_sha256)
            elif saved.boot_id != old_boot:
                checkpoint(phase)
            return saved
        if phase != "saving" or (saved_proof is not None and saved_proof[0] != record["boot_id"]):
            raise ValueError("Shadow Mode standby saved configuration differs from the reserved candidate")
    if record["phase"] == "staged":
        verify("staged_reboot", saved_sha256=record["saved_sha256"])
        record = checkpoint("confirming")
        writer.backend.confirm_configuration()

    completed = verify("completed")
    if record["phase"] == "confirming":
        if completed.saved_sha256 != record["saved_sha256"]:
            raise ValueError("Shadow Mode standby candidate preimage changed before saving")
        record = checkpoint("saving")
    if completed.saved_sha256 == record["saved_sha256"]:
        writer.backend.save_configuration()
        completed = verify("completed")
        if completed.saved_sha256 == record["saved_sha256"]:
            raise ValueError("Shadow Mode standby candidate did not reach saved storage")

    saved = verify("saved_commit", saved_sha256=completed.saved_sha256)
    checkpoint("saved", final_saved_sha256=saved.saved_sha256)
    return saved


def recover_standby_policy_rollback(writer, state, receipt, *, revision, snapshot_sha256,
                                    verify_fenced, verify_primary, approved_outside_scope, outside_scope,
                                    mapped_resources_sha256=None):
    """Release the policy checkpoint only after a reboot to the exact fenced preimage."""
    _, record = _policy_reservation(
        writer, state, receipt, revision, snapshot_sha256, approved_outside_scope, outside_scope, mapped_resources_sha256,
    )
    if record is None or record["phase"] in ("saved", "unchanged"):
        raise ValueError("Shadow Mode standby rollback requires an unfinished policy transaction")

    verify_primary()
    _check_receipt(receipt, record["receipt_generation"])
    boot_id, fingerprint = writer.commit_proof(phase="saved_commit")
    if (not isinstance(boot_id, str) or _UUID.fullmatch(boot_id) is None
            or boot_id == record["boot_id"] or fingerprint != record["config_sha256"]):
        raise ValueError("Shadow Mode standby did not reboot into the saved policy preimage")
    restored = _observe(writer, receipt, verify_fenced, phase="saved_commit", boot_id=boot_id,
                       saved_sha256=record["saved_sha256"])
    fallback_rules = _digest({name: state[f"verified_{name}"] for name in _PATHS})
    if (restored.rollback_action != "reboot" or restored.saved_sha256 != record["saved_sha256"]
            or restored.config_sha256 != fingerprint
            or _firewall_proofs(writer) != (record["outside_sha256"], fallback_rules)
            or writer.commit_proof(phase="saved_commit") != (boot_id, fingerprint)):
        raise ValueError("Shadow Mode standby rollback did not restore the exact policy preimage")
    _check_receipt(receipt, record["receipt_generation"])
    state[STANDBY_POLICY_ROLLBACK] = {key: record[key] for key in ("target", "controller_revision")}
    del state[STANDBY_POLICY]
    writer._write_state(state, durable=True)
    return restored
