"""Coordinate a controller restart request with stock VyOS recovery checks."""
from functools import partial
from hashlib import sha256
import json
import logging
from pathlib import Path
import re
import time
from urllib.parse import urlsplit
from uuid import UUID

from backends.vyos import VyOSReadError
from backends.vyos_failover import _run_helper
from backends.vyos_ssh import vyos_ssh_command
from provisioners.vyos_shadow_handoff import SHADOW_HANDOFF


logger = logging.getLogger("unifi-gateway")
_ACCEPTED_REPLIES = frozenset({"noop", "setparam", "cmd", "upgrade", "setdefault"})
_MAX_CLOCK_SKEW_MS = 60_000


def pending_restart(path):
    try:
        state = json.loads(Path(path).read_text(encoding="utf-8"))
    except (FileNotFoundError, ValueError):
        return False
    return isinstance(state, dict) and "restart" in state


def _preflight_command(config):
    options = config["vyos_restart"]
    return vyos_ssh_command(
        urlsplit(config["vyos"]["api_url"]).hostname, options.getint("ssh_port", 22),
        options["ssh_user"], options["ssh_key_file"], options["ssh_known_hosts_file"],
    )


def commit_proof_from_config(config):
    return partial(_read_commit_fingerprint, _preflight_command(config))


def _read_commit_fingerprint(argv, *, phase):
    if phase == "saved":
        try:
            return _read_boot_id(argv)
        except VyOSReadError as error:
            raise VyOSReadError("VyOS saved configuration or rollback state could not be verified") from error
    if phase == "saved_commit":
        result, status = _run_helper([*argv[:-1], "/bin/false uxg-commit-saved"], reader="VyOS commit proof", limit=128,
                                     timeout=15)
        match = re.fullmatch(rb"uxg-commit-saved ([0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}) ([0-9a-f]{64})\n", result)
        if status != 0 or match is None:
            raise VyOSReadError("VyOS saved commit and boot could not be verified together")
        return match[1].decode("ascii"), match[2].decode("ascii")
    request = {"completed": "proof", "staged": "snapshot", "staged_reboot": "snapshot-reboot"}[phase]
    response = phase.encode("ascii")
    result, status = _run_helper([*argv[:-1], f"/bin/false uxg-commit-{request}"], reader="VyOS commit proof", limit=128)
    match = re.fullmatch(rb"uxg-commit-" + response + rb" ([0-9a-f]{64})\n", result)
    if status != 0 or match is None:
        raise VyOSReadError("VyOS completed configuration could not be verified" if phase == "completed"
                            else "VyOS staged configuration fingerprint is unavailable")
    return match[1].decode("ascii")


class VyOSRestart:
    def __init__(self, reconciler, *, preflight, verify_forwarding):
        self._reconciler = reconciler
        self._preflight = preflight
        self._verify_forwarding = verify_forwarding
        self._verified_recovery = None
        self._recovery_error = None

    @classmethod
    def from_config(cls, reconciler, config):
        options = config["vyos_restart"]
        argv = _preflight_command(config)
        probe = options["forwarding_probe"]
        if not Path(probe).is_absolute() or "\x00" in probe:
            raise ValueError("VyOS restart forwarding_probe requires an absolute executable path")
        return cls(reconciler, preflight=partial(_read_boot_id, argv),
                   verify_forwarding=partial(_probe_forwarding, probe))

    def request(self, controller_time):
        with self._reconciler.locked_state() as state:
            if state.get("restart") is not None:
                return
            destination = state.get("verified_policy_route")
            if (state["pending"] is not None or "policy_table_setup" in state
                    or "policy_route_guard_setup" in state
                    or SHADOW_HANDOFF in state
                    or state.get("policy_route_guard", []) != ([destination] if destination is not None else [])):
                raise ValueError("VyOS restart refused during pending provisioning")
            stamp = _fresh_controller_time(controller_time, after=state.get("restart_watermark", 0))
            self._verify_forwarding()
            self._reconciler.verify_policy_route_for_restart(state)
            config_hash = self._configuration_hash()
            boot_id = self._preflight()
            state["restart"] = {"boot_id": boot_id, "configuration_sha256": config_hash}
            state["restart_watermark"] = stamp
            self._reconciler._write_state(state, durable=True)
            logger.info("Requesting VyOS restart after saved configuration and forwarding checks")
            self._reconciler.backend.reboot()

    def ready_for_inform(self):
        self._verified_recovery = None
        try:
            with self._reconciler.locked_state() as state:
                pending = state.get("restart")
                if pending is not None:
                    if self._preflight() == pending["boot_id"]:
                        raise VyOSReadError("VyOS boot ID has not changed")
                    if self._configuration_hash() != pending["configuration_sha256"]:
                        raise VyOSReadError("VyOS configuration differs from its pre-restart state")
                    self._verify_forwarding()
                    self._reconciler.verify_policy_route_for_restart(state)
                    self._verified_recovery = (pending, state["restart_watermark"])
        except (OSError, ValueError, VyOSReadError) as error:
            if str(error) != self._recovery_error:
                self._recovery_error = str(error)
                logger.warning("VyOS restart recovery is unverified: %s", error)
            return False
        self._recovery_error = None
        return True

    def accept_response(self, response_type, controller_time):
        if self._verified_recovery is None or response_type not in _ACCEPTED_REPLIES:
            return
        pending, requested_at = self._verified_recovery
        with self._reconciler.locked_state() as state:
            if state.get("restart") == pending and state.get("restart_watermark") == requested_at:
                state["restart_watermark"] = _fresh_controller_time(controller_time, after=requested_at)
                del state["restart"]
                self._reconciler._write_state(state, durable=True)
                logger.info("Verified VyOS restart and controller reconnection")
        self._verified_recovery = None

    def _configuration_hash(self):
        config = self._reconciler.backend.read_complete_configuration()
        return sha256(json.dumps(config, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _read_boot_id(argv):
    result, status = _run_helper(argv, reader="VyOS restart preflight", limit=128)
    if status != 0:
        raise VyOSReadError("VyOS restart preflight refused or could not check the router")
    try:
        boot_id = result.decode("ascii").removesuffix("\n")
        if str(UUID(boot_id)) == boot_id:
            return boot_id
    except ValueError:
        pass
    raise VyOSReadError("VyOS restart preflight returned an invalid boot ID")


def _probe_forwarding(probe):
    _, status = _run_helper([probe], reader="VyOS restart forwarding probe", limit=4096)
    if status != 0:
        raise VyOSReadError("VyOS restart forwarding probe failed")


def _fresh_controller_time(value, *, after):
    if not isinstance(value, str) or len(value) != 13 or not value.isascii() or not value.isdecimal():
        raise ValueError("VyOS restart requires a controller timestamp in Unix milliseconds")
    stamp = int(value)
    if stamp <= after or abs(time.time_ns() // 1_000_000 - stamp) > _MAX_CLOCK_SKEW_MS:
        raise ValueError("VyOS restart controller timestamp is stale or outside the clock tolerance")
    return stamp
