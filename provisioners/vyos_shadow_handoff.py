"""Serialize and recover the initial fenced Shadow Mode primary transfer."""

from contextlib import ExitStack, contextmanager
from dataclasses import asdict
from hashlib import sha256
from ipaddress import IPv4Address, ip_interface
import json
from pathlib import Path
import re
from types import SimpleNamespace
from uuid import uuid4

from provisioners.vyos_shadow_binding import _identifier
from provisioners.vyos_shadow_complete import SHADOW_VRRP_PARENTS, ShadowLanPreimage
from provisioners.vyos_shadow_guard import SHADOW_GUARD_CONTAINERS


SHADOW_HANDOFF = "shadow_handoff"
SHADOW_ROLLBACK = "last_shadow_rollback"
_BINDING_FIELDS = {"target", "revision", "saved_sha256", "config_sha256", "receipt_generation", "outside_sha256"}
_BASE_FIELDS = _BINDING_FIELDS | {"phase", "boot_id", "transaction"}
_PHASE_FIELDS = {
    **dict.fromkeys(("reserved", "standby", "armed", "rolled_back"), set()),
    "staged": {"staged_sha256"},
    "confirming": {"staged_sha256"},
    "saving": {"staged_sha256"},
    "saved": {"staged_sha256", "final_saved_sha256"},
    "publishing": {"staged_sha256", "final_saved_sha256", "policy_sha256"},
    "primary_active": {"staged_sha256", "final_saved_sha256", "policy_sha256", "receipt_id"},
}
_UUID = re.compile(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}")
_DIGEST = re.compile(r"[0-9a-f]{64}")
_INFORM_FIELDS = {"controller_revision", "primary_identity_sha256"}
_COMPLETE_DIGEST = "complete_snapshot_sha256"
_STANDBY_RESOURCES = "standby_resources_sha256"
_SITE_POLICY = "site_policy_sha256"
_LAN_PREIMAGE = "lan_preimage"


class ShadowPrimaryPending(RuntimeError):
    """The authorized primary is still fenced while VRRP converges."""


def pending_shadow_handoff(path):
    try:
        state = json.loads(Path(path).read_text(encoding="utf-8"))
    except FileNotFoundError:
        return False
    return isinstance(state, dict) and SHADOW_HANDOFF in state


def validate_shadow_handoff(record):
    phase = record.get("phase") if isinstance(record, dict) else None
    if not isinstance(phase, str) or phase not in _PHASE_FIELDS:
        raise ValueError("Invalid saved Shadow Mode handoff phase")
    digests = _BINDING_FIELDS | _PHASE_FIELDS[phase]
    fields = _BASE_FIELDS | digests
    if _LAN_PREIMAGE in record:
        fields |= {_LAN_PREIMAGE}
        _parse_lan_preimage(record[_LAN_PREIMAGE])
    if phase == "primary_active" and record.keys() & _INFORM_FIELDS:
        fields |= _INFORM_FIELDS
        if (not _identifier(record.get("controller_revision"))
                or record.get("revision") != _revision_digest(record.get("target"), record["controller_revision"])):
            raise ValueError("Invalid saved Shadow Mode controller revision")
        digests |= {"primary_identity_sha256"}
        if _COMPLETE_DIGEST in record:
            fields |= {_COMPLETE_DIGEST}
            digests |= {_COMPLETE_DIGEST}
            if _STANDBY_RESOURCES in record:
                fields |= {_STANDBY_RESOURCES}
                digests |= {_STANDBY_RESOURCES}
                if _SITE_POLICY in record:
                    fields |= {_SITE_POLICY}
                    digests |= {_SITE_POLICY}
    if (record.keys() != fields
            or any(not isinstance(record[key], str) or _UUID.fullmatch(record[key]) is None
                   for key in ("boot_id", "transaction"))
            or any(not isinstance(record[key], str) or _DIGEST.fullmatch(record[key]) is None for key in digests)):
        raise ValueError("Invalid saved Shadow Mode handoff")


def _parse_lan_preimage(document):
    if (not isinstance(document, dict)
            or document.keys() - {"created_vrrp_parent"} != {"addresses", "route_source", "guard_containers"}):
        raise ValueError("Invalid saved Shadow Mode LAN preimage")
    addresses, route_source, containers = (document[key] for key in ("addresses", "route_source", "guard_containers"))
    parent = document.get("created_vrrp_parent", [])
    allowed_containers = [list(path) for path in SHADOW_GUARD_CONTAINERS]
    if (not isinstance(addresses, list) or not addresses or any(not isinstance(value, str) for value in addresses)
            or len(set(addresses)) != len(addresses) or not isinstance(route_source, str)
            or not isinstance(containers, list) or containers != [path for path in allowed_containers if path in containers]
            or not isinstance(parent, list) or tuple(parent) not in ((), *SHADOW_VRRP_PARENTS)):
        raise ValueError("Invalid saved Shadow Mode LAN preimage")
    try:
        IPv4Address(route_source)
        for value in addresses:
            if value not in {"dhcp", "dhcpv6"}:
                ip_interface(value)
    except ValueError as error:
        raise ValueError("Invalid saved Shadow Mode LAN preimage address") from error
    return ShadowLanPreimage(tuple(addresses), route_source, tuple(tuple(path) for path in containers), tuple(parent))


def read_shadow_lan_preimage(record):
    validate_shadow_handoff(record)
    if record["phase"] == "standby" or _LAN_PREIMAGE not in record:
        raise ValueError("Shadow Mode recovery requires a primary reservation with a LAN preimage")
    return _parse_lan_preimage(record[_LAN_PREIMAGE])


def _revision_digest(target, revision):
    return sha256(json.dumps([target, revision]).encode()).hexdigest()


def _target_digest(identity):
    return sha256(json.dumps(identity, default=str, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _identity_digest(identity):
    return sha256(json.dumps(asdict(identity), sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _match_activation_receipt(record, slot):
    receipt = slot.receipt
    if (slot.generation != record["receipt_generation"] or receipt is None
            or (receipt.transaction, receipt.sha256, receipt.config_sha256)
            != (record["transaction"], record["policy_sha256"], record["staged_sha256"])
            or ("receipt_id" in record and receipt.id != record["receipt_id"])):
        raise ValueError("Shadow Mode has no matching activation receipt")
    return receipt


def verify_primary_inform(record, receipt_client, backend, commit_proof, *, expected_lan_link=None, expected_role="master"):
    """Return the controller revision only while the activated primary is still verified."""
    validate_shadow_handoff(record)
    if (expected_role not in ("master", "backup") or record["phase"] != "primary_active"
            or not (_INFORM_FIELDS | {_COMPLETE_DIGEST}).issubset(record)
            or _identity_digest(receipt_client.management_identity) != record["primary_identity_sha256"]
            or commit_proof is None):
        raise ValueError("Shadow Mode inform lacks the verified primary enrollment")
    initial = _match_activation_receipt(record, receipt_client.status())
    proof = commit_proof(phase="saved_commit")
    if (not isinstance(proof, tuple) or len(proof) != 2 or not isinstance(proof[0], str)
            or _UUID.fullmatch(proof[0]) is None or proof[1] != record["staged_sha256"]):
        raise ValueError("Shadow Mode primary saved commit differs from the activated configuration")
    boot_id, fingerprint = proof
    live = receipt_client.observe_handoff_state(
        backend, commit_proof, phase="saved_commit", expected_boot_id=boot_id,
        expected_saved_sha256=record["final_saved_sha256"],
    )
    if (live.role != expected_role or live.phase != "saved_commit" or live.boot_id != boot_id
            or live.config_sha256 != fingerprint or live.saved_sha256 != record["final_saved_sha256"]
            or _match_activation_receipt(record, receipt_client.status()) != initial):
        raise ValueError("Shadow Mode primary inform could not verify current activation")
    if expected_lan_link is not None:
        interface, address = expected_lan_link
        if not any(str(value.ip) == address for value in live.state.kernel.get(interface, ())):
            raise ValueError("Shadow Mode primary no longer owns the expected LAN link-local address")
    return record["controller_revision"]


def verify_standby_rollback_resources(primary_record, standby_record, *, binding, observation,
                                      receipt_client, backend, commit_proof, primary_lan_interface):
    """Verify the current pair's previously committed resources irrespective of policy changes."""
    from provisioners.uxg_enterprise_shadow_tunnel import verify_bound_shadow_standby_complete

    validate_shadow_handoff(primary_record)
    validate_shadow_handoff(standby_record)
    if (primary_record["phase"] != "primary_active" or _STANDBY_RESOURCES not in primary_record
            or standby_record != _standby_reservation(primary_record)):
        raise ValueError("Shadow Mode standby lacks the matching active primary reservation")
    snapshot = verify_bound_shadow_standby_complete(
        binding, authenticated_response=observation, expected_resources=primary_record[_STANDBY_RESOURCES],
    )
    verify_primary_inform(
        primary_record, receipt_client, backend, commit_proof,
        expected_lan_link=(primary_lan_interface, snapshot.election.peer_lan[1]),
    )
    return snapshot


def verify_standby_complete(primary_record, standby_record, *, binding, observation,
                            receipt_client, backend, commit_proof, primary_lan_interface,
                            ordinary, phase_one_digest, phase_one_revision, verified_standby_revision):
    """Verify a standby response against both reservations while the caller holds both locks."""
    from provisioners.uxg_enterprise_shadow_tunnel import primary_shadow_policy_fingerprint, shadow_site_policy_fingerprint

    snapshot = verify_standby_rollback_resources(
        primary_record, standby_record, binding=binding, observation=observation, receipt_client=receipt_client,
        backend=backend, commit_proof=commit_proof, primary_lan_interface=primary_lan_interface,
    )
    if binding.primary.desired_revision != primary_record.get("controller_revision"):
        raise ValueError("Shadow Mode standby requires the applied primary controller revision")
    if (not _identifier(phase_one_revision) or phase_one_revision != verified_standby_revision
            or not isinstance(phase_one_digest, str) or _DIGEST.fullmatch(phase_one_digest) is None):
        raise ValueError("Shadow Mode standby COMPLETE requires its verified phase-one revision and policy")
    system_cfg = observation[1]["system_cfg"]
    if _SITE_POLICY in primary_record:
        if binding.state != "SETUP_COMPLETED":
            raise ValueError("Shadow Mode standby site policy requires the completed controller setup phase")
        actual_policy = shadow_site_policy_fingerprint(system_cfg, election=snapshot.election)
        expected_policy = primary_record[_SITE_POLICY]
    else:
        actual_policy = primary_shadow_policy_fingerprint(system_cfg, ordinary, complete=True)
        expected_policy = phase_one_digest
    if actual_policy != expected_policy:
        raise ValueError("Shadow Mode standby COMPLETE changed policy outside its verified handoff")
    return snapshot


def _standby_reservation(record):
    fields = _BASE_FIELDS | ({_LAN_PREIMAGE} if _LAN_PREIMAGE in record else set())
    return {key: record[key] for key in fields} | {"phase": "standby"}


@contextmanager
def locked_shadow_pair(primary, standby):
    writers = sorted((primary, standby), key=lambda writer: writer.state_path.with_suffix(".lock").resolve())
    if writers[0].state_path.with_suffix(".lock").resolve() == writers[1].state_path.with_suffix(".lock").resolve():
        raise ValueError("Shadow Mode requires separate router provisioning locks")
    with ExitStack() as locks:
        states = {writer: locks.enter_context(writer.locked_state()) for writer in writers}
        yield states[primary], states[standby]


class ShadowPrimaryTransfer:
    """Stage once under both routers' locks. Leave ambiguous results fenced for read-back."""

    def __init__(self, primary, standby, pair, handoff, *, observe_primary, observe_standby,
                 read_route_source, receipt_client, read_controller_pair=None):
        self.primary, self.standby = primary, standby
        peers = (primary, standby)
        if len({writer.state_path.with_suffix(".lock").resolve() for writer in peers}) != 2:
            raise ValueError("Shadow Mode requires separate router provisioning locks")
        nodes = (pair.primary, pair.standby)
        if (nodes[0].device_id == nodes[1].device_id
                or any(writer.backend.management_origin != node.management.https_origin
                       for writer, node in zip(peers, nodes))
                or receipt_client.management_identity != nodes[0].management
                or primary.backend.management_origin == standby.backend.management_origin):
            raise ValueError("Shadow Mode provisioning targets must match the distinct enrolled routers")
        self._handoff = handoff
        self._observe_primary = observe_primary
        self._observe_standby = observe_standby
        self._read_route_source = read_route_source
        self._receipt = receipt_client
        self._pair = pair
        self._read_controller_pair = read_controller_pair
        self._controller_revision = pair.primary.desired_revision
        identity = [pair.site_id, [[node.device_id, asdict(node.management)] for node in nodes],
                    handoff.create_commands(), asdict(handoff.standby_scope), handoff.ordinary_address_order,
                    handoff.ordinary_route_source]
        if handoff.complete_snapshot_sha256 is not None:
            if (handoff.complete_binding != pair or not isinstance(handoff.complete_snapshot_sha256, str)
                    or _DIGEST.fullmatch(handoff.complete_snapshot_sha256) is None):
                raise ValueError("Shadow Mode handoff does not match the authenticated COMPLETE enrollment")
            if read_controller_pair is None:
                raise ValueError("Shadow Mode COMPLETE requires live controller enrollment verification")
            identity.append(handoff.complete_snapshot_sha256)
            if handoff.standby_resources_sha256 is not None:
                if not isinstance(handoff.standby_resources_sha256, str) or _DIGEST.fullmatch(
                    handoff.standby_resources_sha256
                ) is None:
                    raise ValueError("Invalid Shadow Mode standby resources fingerprint")
                identity.append(handoff.standby_resources_sha256)
                if handoff.site_policy_sha256 is not None:
                    if not isinstance(handoff.site_policy_sha256, str) or _DIGEST.fullmatch(handoff.site_policy_sha256) is None:
                        raise ValueError("Invalid Shadow Mode site policy fingerprint")
                    identity.append(handoff.site_policy_sha256)
            if handoff.management_guard is not None:
                identity.append(handoff.guard_containers)
        legacy_target = _target_digest(identity)
        if handoff.created_vrrp_parent:
            identity.append({"created_vrrp_parent": handoff.created_vrrp_parent})
        self._target = _target_digest(identity) if handoff.created_vrrp_parent else legacy_target
        self._revision = _revision_digest(self._target, self._controller_revision)
        self._legacy_revision = _revision_digest(legacy_target, self._controller_revision)

    def _locked_pair(self):
        return locked_shadow_pair(self.primary, self.standby)

    def advance_primary(self, *, verify_forwarding, phase_one_revision=None):
        """Run or resume the journaled initial primary transaction."""
        with self._locked_pair() as (local, peer):
            self._verify_phase_one(local, phase_one_revision)
            record = local.get(SHADOW_HANDOFF)
            if record is not None and (record["target"] != self._target or record["phase"] == "standby"):
                raise ValueError("Shadow Mode COMPLETE does not match the pending handoff")
            phase = record["phase"] if record is not None else None
            if phase == "armed":
                if peer.get(SHADOW_HANDOFF) != _standby_reservation(record):
                    raise ValueError("Shadow Mode staging recovery requires both matching reservations")
                self._verify_timed_candidate(local, record)
                phase = "staged"

        if phase in ("reserved", "rolled_back"):
            self.recover_rollback()
            phase = None
        if phase is None:
            self.stage(phase_one_revision=phase_one_revision)
            phase = "staged"
        if phase in ("staged", "confirming", "saving"):
            self.confirm_and_save()
        return self.activate_primary(verify_forwarding=verify_forwarding)

    def advance_authenticated_complete(self, observation, *, verify_forwarding, phase_one_revision):
        from provisioners.uxg_enterprise_shadow_tunnel import (
            complete_snapshot_fingerprint,
            decode_primary_management_guard,
            expected_standby_resources,
            shadow_site_policy_fingerprint,
            verify_bound_shadow_primary_complete,
        )

        snapshot = verify_bound_shadow_primary_complete(self._pair, authenticated_response=observation)
        system_cfg = observation[1]["system_cfg"]
        if (complete_snapshot_fingerprint(system_cfg) != self._handoff.complete_snapshot_sha256
                or decode_primary_management_guard(system_cfg) != self._handoff.management_guard
                or expected_standby_resources(self._pair, snapshot, self._handoff.primary.primary_lan_link_local)
                != self._handoff.standby_resources_sha256
                or shadow_site_policy_fingerprint(system_cfg, election=snapshot.election) != self._handoff.site_policy_sha256):
            raise ValueError("Shadow Mode COMPLETE does not match the verified primary plan")
        if not _identifier(phase_one_revision):
            raise ValueError("Shadow Mode COMPLETE requires a verified phase-one revision")
        return self.advance_primary(verify_forwarding=verify_forwarding, phase_one_revision=phase_one_revision)

    @staticmethod
    def _verify_phase_one(local, revision):
        if revision is not None and local["verified_revision"] != revision:
            raise ValueError("Shadow Mode phase-one policy changed before the handoff")

    def stage(self, *, phase_one_revision=None):
        """Return verified staged evidence while both nodes remain reserved and the timer stays armed."""
        with self._locked_pair() as (local, peer):
            self._verify_phase_one(local, phase_one_revision)
            if local.get(SHADOW_ROLLBACK) in (self._revision, self._legacy_revision):
                raise ValueError("This Shadow Mode handoff revision already rolled back")
            for state in (local, peer):
                if (state.get("pending") is not None or any(key in state for key in (
                    SHADOW_HANDOFF, "restart", "policy_table_setup", "policy_route_guard_setup",
                ))):
                    raise ValueError("Shadow Mode handoff refused during pending router provisioning")
            outside_sha256 = self._outside_configuration_digest(guard_installed=False)
            preimage = self._observe_primary(phase="saved_commit")
            commands = self._handoff.reboot_safe_transfer_commands(
                preimage, peer=self._observe_standby(), route_source=self._read_route_source(),
            )
            slot = self._receipt.status()
            if slot.receipt is not None:
                raise ValueError("Shadow Mode handoff requires an empty receipt slot")
            self._verify_controller_pair()
            fenced = self._receipt.fence(slot.generation)
            self._verify_outside_configuration(outside_sha256, guard_installed=False)
            record = {"phase": "reserved", "target": self._target, "boot_id": preimage.boot_id,
                      "revision": self._revision, "transaction": str(uuid4()),
                      "saved_sha256": preimage.saved_sha256, "config_sha256": preimage.config_sha256,
                      "receipt_generation": fenced.generation, "outside_sha256": outside_sha256,
                      _LAN_PREIMAGE: {"addresses": list(self._handoff.ordinary_address_order),
                                      "route_source": self._handoff.ordinary_route_source,
                                      "guard_containers": [list(path) for path in self._handoff.guard_containers]}}
            if self._handoff.created_vrrp_parent:
                record[_LAN_PREIMAGE]["created_vrrp_parent"] = list(self._handoff.created_vrrp_parent)
            validate_shadow_handoff(record)
            local[SHADOW_HANDOFF] = record
            self.primary._write_state(local, durable=True)
            peer[SHADOW_HANDOFF] = record | {"phase": "standby"}
            self.standby._write_state(peer, durable=True)
            local[SHADOW_HANDOFF] = record | {"phase": "armed"}
            self.primary._write_state(local, durable=True)
            self.primary.backend.stage_configuration(commands, confirm_minutes=1)
            return self._verify_timed_candidate(local, record)

    def _verify_timed_candidate(self, local, record):
        staged = self._observe_primary(phase="staged_reboot", expected_boot_id=record["boot_id"],
                                      expected_saved_sha256=record["saved_sha256"])
        if (staged.phase != "staged_reboot" or staged.boot_id != record["boot_id"]
                or staged.saved_sha256 != record["saved_sha256"]
                or staged.config_sha256 == record["config_sha256"]):
            raise ValueError("Shadow Mode staged proof does not match the reserved router and preimage")
        self._handoff.verify_staged_transfer(staged.state, peer=self._observe_standby(), role=staged.role)
        self._verify_outside_configuration(record["outside_sha256"])
        self._verify_receipt_fence(record)
        self._write_primary(local, record | {"phase": "staged", "staged_sha256": staged.config_sha256})
        return staged

    def _write_primary(self, state, record):
        validate_shadow_handoff(record)
        state[SHADOW_HANDOFF] = record
        self.primary._write_state(state, durable=True)

    def _observe_candidate(self, record, phase, *, saved_sha256=None):
        current = self._observe_primary(phase=phase, expected_boot_id=record["boot_id"],
                                        expected_saved_sha256=saved_sha256)
        if (current.phase != phase or current.boot_id != record["boot_id"]
                or current.config_sha256 != record["staged_sha256"]
                or (saved_sha256 is not None and current.saved_sha256 != saved_sha256)):
            raise ValueError("Shadow Mode evidence differs from the journaled candidate")
        return current

    def _verify_receipt_fence(self, record):
        slot = self._receipt.status()
        if slot.receipt is not None or slot.generation != record["receipt_generation"]:
            raise ValueError("Shadow Mode receipt fence changed during the handoff")

    def _verify_controller_pair(self):
        if self._read_controller_pair is not None and self._read_controller_pair() != self._pair:
            raise ValueError("Shadow Mode controller enrollment or desired revision changed during the handoff")

    def _read_activation_receipt(self, record):
        return _match_activation_receipt(record, self._receipt.status())

    def _outside_configuration_digest(self, *, guard_installed):
        config = self.primary.backend.read_complete_configuration()
        if not guard_installed:
            self._handoff.verify_ordinary_vrrp_ancestry(config)
        if self._handoff.management_guard is not None:
            guard = self._handoff.management_guard
            guard.verify_stock(
                config, installed=guard_installed, interconnect=self._handoff.primary._resource_scope().interconnect,
            )
            if not guard_installed and guard.created_containers(config) != self._handoff.guard_containers:
                raise ValueError("The Shadow Mode guard containers changed before staging")
        outside = self._handoff.outside_transfer_configuration(config)
        return sha256(json.dumps(outside, sort_keys=True, separators=(",", ":")).encode()).hexdigest()

    def _verify_outside_configuration(self, expected, *, guard_installed=True):
        if self._outside_configuration_digest(guard_installed=guard_installed) != expected:
            raise ValueError("VyOS configuration outside the Shadow Mode transfer changed")

    def confirm_and_save(self):
        """Confirm once, then recover and verify the saved candidate without activating it."""
        with self._locked_pair() as (local, peer):
            record = local.get(SHADOW_HANDOFF)
            if (record is None or record["target"] != self._target
                    or record["phase"] not in ("staged", "confirming", "saving", "saved")
                    or peer.get(SHADOW_HANDOFF) != _standby_reservation(record)):
                raise ValueError("Shadow Mode confirmation requires both matching reservations")

            if record["phase"] == "staged":
                if record["revision"] != self._revision:
                    raise ValueError("Shadow Mode desired revision changed before confirmation")
                staged = self._observe_candidate(record, "staged_reboot", saved_sha256=record["saved_sha256"])
                self._handoff.verify_staged_transfer(staged.state, peer=self._observe_standby(), role=staged.role)
                self._verify_outside_configuration(record["outside_sha256"])
                self._verify_receipt_fence(record)
                self._verify_controller_pair()
                record = record | {"phase": "confirming"}
                self._write_primary(local, record)
                self.primary.backend.confirm_configuration()

            saved_sha256 = record.get("final_saved_sha256")
            if record["phase"] == "confirming":
                completed = self._observe_candidate(record, "completed")
                standby = self._observe_standby()
                if completed.saved_sha256 == record["saved_sha256"]:
                    self._handoff.verify_staged_transfer(completed.state, peer=standby, role=completed.role)
                    self._verify_outside_configuration(record["outside_sha256"])
                    self._verify_receipt_fence(record)
                    self._verify_controller_pair()
                    record = record | {"phase": "saving"}
                    self._write_primary(local, record)
                    self.primary.backend.save_configuration()
                else:
                    self._handoff.verify_saved_transfer(completed.state, peer=standby, role=completed.role)
                    saved_sha256 = completed.saved_sha256

            saved = self._observe_candidate(record, "saved_commit", saved_sha256=saved_sha256)
            if saved.saved_sha256 == record["saved_sha256"] or saved.state.running != saved.state.saved:
                raise ValueError("Shadow Mode candidate was not saved")
            self._handoff.verify_saved_transfer(saved.state, peer=self._observe_standby(), role=saved.role)
            self._verify_outside_configuration(record["outside_sha256"])
            self._verify_receipt_fence(record)
            if record["phase"] != "saved":
                self._write_primary(local, record | {"phase": "saved", "final_saved_sha256": saved.saved_sha256})
            return saved

    def activate_primary(self, *, verify_forwarding):
        """Allow only the saved primary to take over and verify forwarding before acknowledging it."""
        with self._locked_pair() as (local, peer):
            record = local.get(SHADOW_HANDOFF)
            if (record is None or record["target"] != self._target
                    or record["phase"] not in ("saved", "publishing", "primary_active")
                    or peer.get(SHADOW_HANDOFF) != _standby_reservation(record)):
                raise ValueError("Shadow Mode activation requires both matching reservations")
            if record["revision"] != self._revision:
                raise ValueError("Shadow Mode desired revision changed before activation")

            if record["phase"] == "saved":
                candidate = self._prepare_activation_candidate(record)
                record = record | {"phase": "publishing", "policy_sha256": candidate.sha256}
                self._write_primary(local, record)
                self._receipt.publish(record["transaction"], candidate)
            elif record["phase"] == "publishing":
                slot = self._receipt.status()
                if slot.receipt is None and slot.generation == record["receipt_generation"]:
                    candidate = self._prepare_activation_candidate(record)
                    if candidate.sha256 != record["policy_sha256"]:
                        raise ValueError("Shadow Mode receipt candidate changed before publication recovery")
                    self._receipt.publish(record["transaction"], candidate)

            initial_receipt = self._read_activation_receipt(record)
            self._verify_primary_activation(record)
            if verify_forwarding() is False:
                raise ValueError("Shadow Mode primary forwarding could not be verified")
            master = self._verify_primary_activation(record)
            if self._read_activation_receipt(record) != initial_receipt:
                raise ValueError("Shadow Mode receipt changed while verifying primary activation")
            if record["phase"] != "primary_active" or not _INFORM_FIELDS <= record.keys():
                active = record | {
                    "phase": "primary_active", "receipt_id": initial_receipt.id,
                    "controller_revision": self._controller_revision,
                    "primary_identity_sha256": _identity_digest(self._receipt.management_identity),
                }
                if self._handoff.complete_snapshot_sha256 is not None:
                    active[_COMPLETE_DIGEST] = self._handoff.complete_snapshot_sha256
                    if self._handoff.standby_resources_sha256 is not None:
                        active[_STANDBY_RESOURCES] = self._handoff.standby_resources_sha256
                        if self._handoff.site_policy_sha256 is not None:
                            active[_SITE_POLICY] = self._handoff.site_policy_sha256
                self._write_primary(local, active)
            return master

    def _prepare_activation_candidate(self, record):
        saved = self._observe_candidate(record, "saved_commit", saved_sha256=record["final_saved_sha256"])
        self._handoff.verify_saved_transfer(saved.state, peer=self._observe_standby(), role=saved.role)
        self._verify_outside_configuration(record["outside_sha256"])
        self._verify_receipt_fence(record)
        guard = self._handoff.management_guard
        scope = {"required_paths": guard.eligibility_paths} if guard is not None else {}
        candidate = self._receipt.candidate(expected_boot_id=record["boot_id"],
                                            expected_config_sha256=record["staged_sha256"], **scope)
        if candidate.generation != record["receipt_generation"]:
            raise ValueError("Shadow Mode receipt generation changed before publication")
        self._verify_controller_pair()
        return candidate

    def _verify_primary_activation(self, record):
        master = self._observe_candidate(record, "saved_commit", saved_sha256=record["final_saved_sha256"])
        standby = self._observe_standby()
        if record["phase"] == "publishing" and master.role == "fault":
            self._handoff.verify_saved_transfer(master.state, peer=standby, role=master.role)
            raise ShadowPrimaryPending("Shadow Mode primary is waiting for VRRP activation")
        self._handoff.verify_primary_master(master.state, peer=standby, role=master.role)
        self._verify_outside_configuration(record["outside_sha256"])
        return master

    def recover_rollback(self):
        """Release this reservation after a proven rollback or before any stage call was possible."""
        with self._locked_pair() as (local, peer):
            record = local.get(SHADOW_HANDOFF)
            if record is None:
                return
            if record["target"] != self._target or record["phase"] in ("standby", "saved", "publishing", "primary_active"):
                raise ValueError("Shadow Mode handoff recovery does not match the reserved pair")
            standby_record = _standby_reservation(record)
            if record["phase"] != "rolled_back":
                if peer.get(SHADOW_HANDOFF) not in (None, standby_record):
                    raise ValueError("Shadow Mode standby reservation changed during recovery")
                if record["phase"] in ("armed", "staged", "confirming", "saving"):
                    if peer.get(SHADOW_HANDOFF) is None:
                        raise ValueError("Shadow Mode standby reservation is missing during recovery")
                    restored = self._observe_primary(phase="saved_commit", expected_saved_sha256=record["saved_sha256"])
                    preimage = SimpleNamespace(**{key: record[key] for key in ("boot_id", "saved_sha256", "config_sha256")})
                    self._handoff.verify_reboot_rollback(
                        preimage, restored, peer=self._observe_standby(), route_source=self._read_route_source(),
                    )
                    local[SHADOW_ROLLBACK] = record["revision"]
                self._write_primary(local, standby_record | {"phase": "rolled_back"})
            if peer.get(SHADOW_HANDOFF) == standby_record:
                del peer[SHADOW_HANDOFF]
                self.standby._write_state(peer, durable=True)
            del local[SHADOW_HANDOFF]
            self.primary._write_state(local, durable=True)
