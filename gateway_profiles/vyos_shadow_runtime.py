"""Assemble the installed primary coordinator from enrolled gateway settings."""

from functools import partial
from contextlib import contextmanager
from dataclasses import asdict
from hashlib import sha256
from ipaddress import IPv4Address, IPv4Interface, IPv6Address
import json
from pathlib import Path
from urllib.parse import urlsplit

from backends.vyos import VyOSReadError
from backends.vyos_failover import _run_helper
from gateway_profiles.uxg_enterprise_shadow_controller import SHADOW_ADMISSION_STATES, ShadowControllerReader
from gateway_profiles.enterprise import FIRMWARE
from backends.vyos_ssh import vyos_ssh_host_fingerprint
from provisioners.uxg_enterprise_shadow import (
    SHADOW_ADDRESSES, normalize_shadow_interconnect, read_interconnect, verify_interconnect,
    verify_no_vrrp_interconnect_conflict,
)
from provisioners.vyos_shadow_binding import ShadowEnrollmentPair
from provisioners.vyos_shadow_complete import (
    SHADOW_SYNC_GROUP, SHADOW_VRRP_GROUP, ShadowNode, _address_leaf, _configured_address_order, _vrrp_inventory,
    build_vyos_shadow_standby_candidate, standby_resource_scope,
)
from provisioners.vyos_shadow_handoff import (
    SHADOW_HANDOFF, ShadowPrimaryTransfer, _standby_reservation, locked_shadow_pair, verify_primary_inform, verify_standby_complete,
    verify_standby_rollback_resources,
)
from provisioners.vyos_shadow_standby import (
    STANDBY_ELECTION,
    STANDBY_POLICY,
    _WITHDRAWING_ELECTION_PHASES,
    _policy_reservation,
    advance_standby_election,
    confirm_and_save_standby_policy,
    publish_standby_election,
    recover_standby_policy_rollback,
    required_receipt_paths,
    verify_published_standby_election,
    verify_revoked_standby_release,
    verify_standby_inform,
    stage_standby_policy,
)
from provisioners.uxg_enterprise_shadow_tunnel import (
    complete_snapshot_fingerprint,
    prepare_bound_shadow_primary_lan_handoff,
    standby_policy_snapshot,
    verify_bound_shadow_primary_complete,
)


def _ordinary_lan(config):
    reference = json.loads(config.get("vyos_shadow_applied", "reference", fallback="null"))
    lan = reference.get("lan_preimage") if isinstance(reference, dict) else None
    return lan.get("addresses") if isinstance(lan, dict) else None


def _standby_mapping_digest(scope):
    mapping = asdict(scope)
    mapping["vips"] = sorted((str(address), interface) for address, interface in scope.vips)
    return sha256(json.dumps(mapping, default=str, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _mapped_node(config, ports, probe, address):
    settings = config["vyos_shadow"]
    bridges = [(row["ifname"], row["realif"]) for row in ports if row["ifname"].startswith("br")]
    interfaces = dict(bridges)
    if "br0" not in interfaces or len(bridges) != len(interfaces):
        raise ValueError("Shadow Mode requires an explicit br0 mapping on each router")
    return ShadowNode(probe.interface, address, interfaces, str(IPv4Interface(settings["lan_election_address"])))


def _verify_commit_pin(config, identity):
    settings = config["vyos_restart"]
    host = urlsplit(identity.https_origin).hostname
    if vyos_ssh_host_fingerprint(host, settings.getint("ssh_port", 22), settings["ssh_known_hosts_file"]) != (
        identity.ssh_host_key
    ):
        raise ValueError("Shadow Mode commit proof must pin the enrolled router")


def _observe(writer, receipt, *, phase, expected_boot_id=None, expected_saved_sha256=None):
    if expected_boot_id is None:
        expected_boot_id, _ = writer.commit_proof(phase="saved_commit")
    return receipt.observe_handoff_state(
        writer.backend, writer.commit_proof, phase=phase, expected_boot_id=expected_boot_id,
        expected_saved_sha256=expected_saved_sha256,
    )


def _check_prepared_router(writer, receipt, node, *, port_interfaces):
    observed = _observe(writer, receipt, phase="saved_commit")
    backend = writer.backend
    owned, (_, addresses) = read_interconnect(backend, node.interconnect)
    if owned is not None or addresses:
        raise ValueError("Shadow Mode pre-pair interconnect already has a configured address")
    verify_interconnect(backend, node.interconnect, None, reserve_prefix=True, require_carrier=True)
    verify_no_vrrp_interconnect_conflict(backend)
    lan = node.interfaces["br0"]
    path = _address_leaf(lan)[:-1]
    state = observed.state
    groups, sync = _vrrp_inventory(state.read(state.saved, ("high-availability", "vrrp")))
    if (SHADOW_VRRP_GROUP in groups or SHADOW_SYNC_GROUP in sync
            or state.read(state.saved, ("service", "conntrack-sync")) is not None
            or any(group.get("interface") == lan and group.get("vrid") == "42" for group in groups.values())):
        raise ValueError("Shadow Mode pre-pair check found existing election or connection sync resources")
    source = IPv4Interface(node.lan_address)
    if (any(str(source) not in _configured_address_order(state.read(tree, path)) for tree in (state.running, state.saved))
            or [interface for interface, addresses in state.kernel.items()
                for address in addresses if address.ip == source.ip] != [lan]
            or source not in state.kernel[lan]):
        raise ValueError("Shadow Mode LAN election address is missing from the saved, running or kernel state")
    management = IPv4Address(urlsplit(receipt.management_identity.https_origin).hostname)
    data_interfaces = set(node.interfaces.values()) | {node.interconnect}
    management_interfaces = [interface for interface, addresses in state.kernel.items()
                             for address in addresses if address.ip == management]
    if (management.is_loopback or len(management_interfaces) != 1
            or management_interfaces[0] in data_interfaces | port_interfaces | {"lo"}):
        raise ValueError("Shadow Mode requires an independent router management interface")
    receipt.verify_admission(
        boot_id=observed.boot_id, config_sha256=observed.config_sha256,
        required_paths=required_receipt_paths(data_interfaces, ipv6_enabled=bool(writer.ipv6_interfaces)),
    )
    if writer.commit_proof(phase="saved_commit") != (observed.boot_id, observed.config_sha256):
        raise ValueError("Shadow Mode router configuration changed during pre-pair verification")


class ShadowPrimaryRuntime:
    def __init__(self, config, ports, writer, probe, standby_config, standby_ports, standby_writer, standby_probe,
                 *, preparing_admission=False):
        options = config["vyos_shadow_primary"]
        self._paths = (writer.state_path, standby_writer.state_path)
        if (len({path.resolve() for path in self._paths}) != 2
                or any(path.is_symlink() or path.with_suffix(".lock").is_symlink() for path in self._paths)):
            raise ValueError("Shadow Mode requires separate canonical router journals")
        if any(not path.parent.is_dir() for path in self._paths):
            raise ValueError("Shadow Mode router journal directories need to exist")
        self._writer = writer
        self._peer_writer = standby_writer
        self._config = config
        self._standby_config = standby_config
        self._probe = probe
        self._peer_probe = standby_probe
        self._port_interfaces = tuple({row["realif"] for row in mapping} for mapping in (ports, standby_ports))
        self._nodes = (
            _mapped_node(config, ports, probe, SHADOW_ADDRESSES[0]),
            _mapped_node(standby_config, standby_ports, standby_probe, SHADOW_ADDRESSES[1]),
        )
        primary_identity = probe.management_identity()
        standby_identity = standby_probe.management_identity(require_adopted=not preparing_admission)
        if (primary_identity.mac == standby_identity.mac or primary_identity.https_origin == standby_identity.https_origin
                or primary_identity.ssh_host_key == standby_identity.ssh_host_key):
            raise ValueError("Shadow Mode requires distinct enrolled router identities")
        _verify_commit_pin(config, primary_identity)
        _verify_commit_pin(standby_config, standby_identity)
        self._receipt = probe.receipt_client()
        self._peer_receipt = standby_probe.receipt_client(require_adopted=not preparing_admission)
        self._identities = (primary_identity, standby_identity)
        self._controller = ShadowControllerReader(
            origin=options["controller_origin"], site=options["site"], site_id=options["site_id"],
            ca_file=options["controller_ca_file"], session_file=options["controller_session_file"],
        )
        self._read_pair = partial(self._controller.read_pair, routers=(primary_identity, standby_identity))
        self._forwarding_probe = options["forwarding_probe"]
        if not Path(self._forwarding_probe).is_absolute() or "\x00" in self._forwarding_probe:
            raise ValueError("Shadow Mode needs an absolute independent forwarding probe executable")
        self._lan_destination = IPv4Address(options["lan_probe_destination"])

    def verify_admission(self):
        """Verify both prepared routers and the ordinary controller head before standby adoption."""
        return self.verify_capability(role="primary", before_adoption_only=True)

    def verify_capability(self, *, role, before_adoption_only=False):
        with self._writer.locked_state() as journal:
            applied = journal["verified_revision"]
        firmware = FIRMWARE
        if before_adoption_only:
            controller = self._controller.read_primary_admission(
                router=self._identities[0], firmware=firmware, applied_revision=applied,
            )
        else:
            controller = self._controller.read_capability_binding(
                routers=self._identities, role=role, firmware=firmware, applied_revision=applied,
            )
        if isinstance(controller, ShadowEnrollmentPair) and controller.state not in SHADOW_ADMISSION_STATES:
            return controller

        self._verify_prepared_pair(journal)
        return controller

    def _verify_prepared_pair(self, journal):
        primary, standby = self._nodes
        first, second = map(IPv4Interface, (primary.lan_address, standby.lan_address))
        if (first.network != second.network or first.ip == second.ip or self._lan_destination not in first.network
                or self._lan_destination in {first.ip, second.ip, first.network.network_address, first.network.broadcast_address}):
            raise ValueError("Shadow Mode requires two distinct LAN election addresses and a host to probe on that LAN")
        if (not journal["verified_revision"] or journal.get("pending") is not None
                or any(key in journal for key in (SHADOW_HANDOFF, "restart", "policy_table_setup", "policy_route_guard_setup"))):
            raise ValueError("Shadow Mode admission needs a verified ordinary primary revision")
        for writer, receipt, node, ports in (
            (self._writer, self._receipt, primary, self._port_interfaces[0]),
            (self._peer_writer, self._peer_receipt, standby, self._port_interfaces[1]),
        ):
            _check_prepared_router(writer, receipt, node, port_interfaces=ports)
        self.verify_forwarding()
        with self._writer.locked_state() as current:
            if current != journal:
                raise ValueError("Shadow Mode primary provisioning changed during pre-pair verification")

    def prepare(self, observation):
        pair = self._read_pair()
        snapshot = verify_bound_shadow_primary_complete(pair, authenticated_response=observation)
        with self._writer.locked_state() as journal:
            reservation = journal.get(SHADOW_HANDOFF)
        ordinary = _ordinary_lan(self._config)
        lan = self._nodes[0].interfaces["br0"]
        vip = dict(snapshot.election.virtual_ips).get("br0")
        if vip is None:
            raise ValueError("Shadow Mode COMPLETE needs the mapped br0 LAN address")
        read_source = partial(self._probe.lan_preferred_source, vip.network, interface=lan, destination=self._lan_destination)
        observe_primary = partial(_observe, self._writer, self._receipt)
        observe_standby = partial(_observe, self._peer_writer, self._peer_receipt, phase="saved_commit")
        # The standby remains in ordinary saved configuration through initial primary activation.
        peer = observe_standby().state
        if reservation is None:
            config_proof = observe_primary(phase="saved_commit")
            current = config_proof.state
            stock = self._writer.backend.read_complete_configuration()
            if self._writer.commit_proof(phase="saved_commit") != (config_proof.boot_id, config_proof.config_sha256):
                raise ValueError("Shadow Mode stock configuration changed while preparing the handoff")
            route_source = read_source()
        else:
            current, stock, route_source = None, None, None
        links = [
            str(IPv6Address(entry.get("local"))) for row in self._writer.backend.show_kernel_interfaces() if row["ifname"] == lan
            for entry in row["addr_info"] if entry.get("family") == "inet6" and entry.get("scope") == "link"
            and not {"tentative", "dadfailed"}.intersection(entry.get("flags", ()))
        ]
        if len(links) != 1:
            raise ValueError("Shadow Mode requires one verified primary LAN link-local address")
        plan = prepare_bound_shadow_primary_lan_handoff(
            pair, authenticated_response=observation, nodes=self._nodes, primary_lan_link_local=links[0],
            ordinary=ordinary, local=current, peer=peer, route_source=route_source,
            reservation=reservation, stock_configuration=stock,
        )
        return ShadowPrimaryTransfer(
            self._writer, self._peer_writer, pair, plan,
            observe_primary=observe_primary, observe_standby=lambda: observe_standby().state,
            read_route_source=read_source, receipt_client=self._receipt, read_controller_pair=self._read_pair,
        )

    @contextmanager
    def _locked_standby_response(self, observation):
        section = "vyos_shadow_applied"
        config = self._standby_config
        ordinary = _ordinary_lan(config)
        with locked_shadow_pair(self._writer, self._peer_writer) as (primary, standby):
            def verify():
                return verify_standby_complete(
                    primary.get(SHADOW_HANDOFF), standby.get(SHADOW_HANDOFF), binding=self._read_pair(), observation=observation,
                    receipt_client=self._receipt, backend=self._writer.backend, commit_proof=self._writer.commit_proof,
                    primary_lan_interface=self._nodes[0].interfaces["br0"], ordinary=ordinary,
                    phase_one_digest=config.get(section, "standby_policy_sha256", fallback=""),
                    phase_one_revision=config.get(section, "standby_policy_revision", fallback=""),
                    verified_standby_revision=standby["verified_revision"],
                )

            yield primary, standby, verify

    def verify_standby_response(self, observation):
        """Read and verify the initial standby snapshot without changing either router."""
        with self._locked_standby_response(observation) as (_, _, verify):
            return verify()

    def plan_standby_response(self, observation, *, decode_policy):
        """Verify, decode and plan under both journal locks without applying or acknowledging."""
        with self._locked_standby_response(observation) as (_, standby, verify):
            intent, options, outside_scope, _guard = self._decode_standby_policy(observation[1], verify(), decode_policy)
            plan = self._peer_writer.plan_shadow_standby_policy(intent, standby, **options)
            return plan, outside_scope

    def advance_standby_response(self, observation, *, decode_policy, approved_outside_scope):
        """Advance the fenced policy transaction without acknowledging the new revision."""
        with self._locked_standby_response(observation) as (primary, standby, verify):
            record = standby.get(STANDBY_POLICY)
            if record is not None and record["phase"] in ("armed", "staged", "confirming", "saving"):
                try:
                    saved = self._peer_writer.commit_proof(phase="saved_commit")
                except VyOSReadError:
                    # A staged or confirmed unsaved commit also lacks a saved proof.
                    # Resume only through the stricter proof required by its journal phase.
                    saved = None
                if saved is not None and saved[0] != record["boot_id"] and saved[1] == record["config_sha256"]:
                    return self._recover_standby_rollback(observation, primary, standby, record, approved_outside_scope)

            snapshot = verify()
            response = observation[1]
            intent, options, outside_scope, management_guard = self._decode_standby_policy(response, snapshot, decode_policy)
            plan = build_vyos_shadow_standby_candidate(snapshot.election, nodes=self._nodes)
            scope = plan._resource_scope()
            args = dict(
                revision=response["cfgversion"], snapshot_sha256=complete_snapshot_fingerprint(response["system_cfg"]),
                verify_fenced=lambda state: state._verify_fenced(scope), verify_primary=verify,
                approved_outside_scope=approved_outside_scope, outside_scope=outside_scope,
                mapped_resources_sha256=_standby_mapping_digest(scope),
            )
            election = standby.get(STANDBY_ELECTION)
            preimage = None
            if election is None:
                if record is None or record["phase"] == "armed":
                    policy_plan = None if record is not None else self._peer_writer.plan_shadow_standby_policy(
                        intent, standby, **options,
                    )
                    stage_standby_policy(self._peer_writer, standby, self._peer_receipt, plan=policy_plan, **args)
                preimage = confirm_and_save_standby_policy(self._peer_writer, standby, self._peer_receipt, **args)
            else:
                _policy_reservation(
                    self._peer_writer, standby, self._peer_receipt, args["revision"], args["snapshot_sha256"],
                    approved_outside_scope, outside_scope, args["mapped_resources_sha256"],
                )
            phase = election["phase"] if election is not None else None
            activation = dict(management_guard=management_guard, verify_primary=verify)
            router = self._peer_writer, standby, self._peer_receipt, plan
            if phase not in ("publishing", "published", *_WITHDRAWING_ELECTION_PHASES):
                advance_standby_election(*router, preimage=preimage, **activation)
            if phase not in ("published", *_WITHDRAWING_ELECTION_PHASES):
                publish_standby_election(*router, verify_ready=self.verify_standby_readiness, **activation)
            return verify_published_standby_election(
                *router, **activation, inform_binding_sha256=self._standby_inform_binding(),
            )

    def _standby_inform_binding(self):
        pair = self._read_pair()
        if pair.state not in ("IN_PROGRESS", "SETUP_COMPLETED"):
            raise ValueError("Shadow Mode standby acknowledgement requires an enrolled pair")
        stable = [pair.site_id, pair.firmware, [[node.device_id, asdict(node.management)] for node in
                  (pair.primary, pair.standby)], [asdict(node) for node in self._nodes]]
        return sha256(json.dumps(stable, sort_keys=True, separators=(",", ":")).encode()).hexdigest()

    def poll_standby_release(self):
        """Read back VIP withdrawal on each standby inform while revocation is pending."""
        with locked_shadow_pair(self._writer, self._peer_writer) as (primary, standby):
            election = standby.get(STANDBY_ELECTION, {})
            if election.get("phase") != "revoking" and not (
                election.get("phase") == "revoked" and "revoked_generation" in election
            ):
                return
            record = primary.get(SHADOW_HANDOFF)
            if record is None or standby.get(SHADOW_HANDOFF) != _standby_reservation(record):
                raise ValueError("Shadow Mode standby VIP release requires matching reservations")
            verify_revoked_standby_release(self._peer_writer, standby, self._peer_receipt)

    def verify_pair_inform(self, *, role, is_standby, replay=None):
        """Report the live role of either enrolled member after verifying reciprocal ownership."""
        if role not in ("master", "backup"):
            raise ValueError("Shadow Mode acknowledgement requires MASTER or BACKUP")
        opposite = "backup" if role == "master" else "master"
        with locked_shadow_pair(self._writer, self._peer_writer) as (primary, standby):
            record = primary.get(SHADOW_HANDOFF)
            election = standby.get(STANDBY_ELECTION, {})
            if replay is not None:
                applied = standby.get(STANDBY_POLICY, {}) if is_standby else record or {}
                digest = "snapshot_sha256" if is_standby else "complete_snapshot_sha256"
                if ("inform_binding_sha256" not in election or replay.get("_type") != "setparam"
                        or replay.get("cfgversion") != applied.get("controller_revision")
                        or complete_snapshot_fingerprint(replay.get("system_cfg")) != applied.get(digest)):
                    raise ValueError("Shadow Mode replay differs from the verified COMPLETE")
            if not is_standby and role == "master" and "inform_binding_sha256" not in election:
                return verify_primary_inform(record, self._receipt, self._writer.backend, self._writer.commit_proof)
            binding = self._standby_inform_binding()
            if record is None or standby.get(SHADOW_HANDOFF) != _standby_reservation(record):
                raise ValueError("Shadow Mode pair acknowledgement requires matching reservations")
            verify_primary = partial(
                verify_primary_inform, record, self._receipt, self._writer.backend, self._writer.commit_proof,
                expected_role=opposite if is_standby else role,
            )
            verify_standby = partial(
                verify_standby_inform, self._peer_writer, standby, self._peer_receipt, inform_binding_sha256=binding,
                expected_role=role if is_standby else opposite,
            )
            verify_peer, verify_local = (verify_primary, verify_standby) if is_standby else (verify_standby, verify_primary)
            verify_peer()
            if self._standby_inform_binding() != binding:
                raise ValueError("Shadow Mode enrolment changed during acknowledgement")
            return verify_local()

    def _recover_standby_rollback(self, observation, primary, standby, record, approved_outside_scope):
        """Prove the saved preimage even if Network has since changed the desired policy."""
        def verify():
            return verify_standby_rollback_resources(
                primary.get(SHADOW_HANDOFF), standby.get(SHADOW_HANDOFF),
                binding=self._read_pair(), observation=observation, receipt_client=self._receipt,
                backend=self._writer.backend, commit_proof=self._writer.commit_proof,
                primary_lan_interface=self._nodes[0].interfaces["br0"],
            )

        scope = standby_resource_scope(verify().election, self._nodes)
        response = observation[1]
        if "mapped_resources_sha256" not in record and (
            response["cfgversion"] != record["controller_revision"]
            or complete_snapshot_fingerprint(response["system_cfg"]) != record["snapshot_sha256"]
        ):
            raise ValueError("Shadow Mode standby rollback needs the original snapshot for this checkpoint")
        return recover_standby_policy_rollback(
            self._peer_writer, standby, self._peer_receipt,
            revision=record["controller_revision"], snapshot_sha256=record["snapshot_sha256"],
            verify_fenced=lambda state: state._verify_fenced(scope), verify_primary=verify,
            approved_outside_scope=approved_outside_scope, outside_scope=record["outside_scope_sha256"],
            mapped_resources_sha256=_standby_mapping_digest(scope),
        )

    def _decode_standby_policy(self, response, snapshot, decode_policy):
        system_cfg, management_guard = standby_policy_snapshot(response["system_cfg"], election=snapshot.election)
        reference = json.loads(self._standby_config.get("vyos_shadow_applied", "reference", fallback="null"))
        system_cfg, address, _ = normalize_shadow_interconnect(system_cfg, reference)
        if address != SHADOW_ADDRESSES[1]:
            raise ValueError("Shadow Mode standby policy requires the verified standby interconnect")
        intent, options, inspection, outside_scope = decode_policy(system_cfg, response["cfgversion"])
        if inspection is not None:
            raise ValueError("Shadow Mode standby policy needs coordinated inspection preparation")
        return intent, options, outside_scope, management_guard

    def verify_forwarding(self):
        _, status = _run_helper([self._forwarding_probe], reader="VyOS Shadow forwarding probe", limit=4096)
        if status != 0:
            raise VyOSReadError("VyOS Shadow forwarding probe failed")
        return True

    def verify_standby_readiness(self, *, boot_id, config_sha256, generation):
        """Require both enrolled paths, primary forwarding and post-INPUT VRRP reception."""
        primary_lan, standby_lan = (IPv4Interface(node.lan_address) for node in self._nodes)
        return (self._probe.reachable(is_secondary=False) and self._peer_probe.reachable(is_secondary=True)
                and self._probe.lan_peer_reachable(primary_lan, standby_lan)
                and self._peer_probe.lan_peer_reachable(standby_lan, primary_lan)
                and self.verify_forwarding()
                and self._peer_receipt.observe_standby_vrrp(
                    boot_id=boot_id, config_sha256=config_sha256, generation=generation,
                    interface=self._nodes[1].interfaces["br0"], local=standby_lan.ip, peer=primary_lan.ip,
                ))
