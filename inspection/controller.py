"""Project approved native inspection modes and verify the fixed actuator's reply."""

from copy import deepcopy
from dataclasses import asdict
import json
import os
from pathlib import Path
import re
import stat
import subprocess
from threading import Lock

from inspection.suricata import (
    DISABLED_INSPECTION, InspectionIntent, _invalid_constant, _unique_fields, decode_inspection_intent,
)


_EVENT_FEED_FIELDS = {"schema", "phase", "status", "generation", "offset", "record"}
_FORWARDING_PROOF = "forwarding_observed"


def is_passive_alert(record):
    if type(record) is not dict or record.get("event_type") != "alert":
        return False
    verdict, alert = record.get("verdict"), record.get("alert")
    return (type(verdict) is dict and verdict.get("action") == "alert"
            and type(alert) is dict and alert.get("action") == "allowed")


def event_feed_forwarding_proof(response):
    """Validate the feed envelope and return its independently observed verdict flag."""
    if (
        type(response) is not dict or response.keys() - {_FORWARDING_PROOF} != _EVENT_FEED_FIELDS
        or type(response["schema"]) is not int or response["schema"] != 1 or response["phase"] != "read-events"
        or response["status"] not in ("records", "idle", "gap")
    ):
        raise ValueError("Invalid EVE source response")
    if _FORWARDING_PROOF not in response:
        return False
    if (response[_FORWARDING_PROOF] is not True or response["status"] != "records"
            or not is_passive_alert(response["record"])):
        raise ValueError("Invalid EVE forwarding proof")
    return True


class InspectionControlError(ValueError):
    """The authorized inspection actuator could not verify the requested state."""


class InspectionController:
    @classmethod
    def from_config(cls, options, *, management_host, stock_queue_scope=None):
        ssh_fields = {"ssh_host", "ssh_user", "ssh_port", "ssh_key_file", "ssh_known_hosts_file"}
        command = options.get("command")
        ssh_argv = None
        if ssh_fields.intersection(options):
            if command is not None:
                raise ValueError("Configure exactly one inspection transport")
            if stock_queue_scope is None:
                raise ValueError("Inspection SSH requires the stock VyOS inspection queue")
            required = ssh_fields - {"ssh_port"}
            if any(not options.get(key) for key in required):
                raise ValueError("Inspection SSH needs a host, user, private key and host key pin")
            if options["ssh_host"] != management_host:
                raise ValueError("Inspection SSH must use the enrolled VyOS management host")
            from backends.vyos_ssh import vyos_ssh_command

            ssh_argv = vyos_ssh_command(
                options["ssh_host"], int(options.get("ssh_port", 22)), options["ssh_user"],
                options["ssh_key_file"], options["ssh_known_hosts_file"],
            )
        return cls(command, networks=json.loads(options["networks"]),
                   vendor_controls_sha256=options["vendor_controls_sha256"],
                   stock_queue_scope=stock_queue_scope, _ssh_argv=ssh_argv)

    def __init__(self, command, *, networks, vendor_controls_sha256, stock_queue_scope=None, _ssh_argv=None):
        if (command is None) == (_ssh_argv is None):
            raise ValueError("Configure exactly one inspection transport")
        self.command = Path(command) if command is not None else None
        if self.command is not None:
            if not self.command.is_absolute():
                raise ValueError("Inspection command must be an absolute executable path")
            mode = self.command.lstat()
            if (
                not stat.S_ISREG(mode.st_mode) or mode.st_uid not in {0, os.geteuid()} or mode.st_mode & 0o022
                or not os.access(self.command, os.X_OK)
            ):
                raise ValueError("Inspection command must be an owned executable with restricted permissions")
        self._argv = [str(self.command)] if self.command is not None else _ssh_argv
        self._request_lock = Lock()
        if (
            not isinstance(networks, (list, tuple)) or len(networks) != 2
            or any(not isinstance(network, str) or re.fullmatch(r"br[1-9][0-9]{0,3}", network) is None for network in networks)
            or len(set(networks)) != 2
        ):
            raise ValueError("Inspection scope needs two explicitly approved controller bridges")
        if not isinstance(vendor_controls_sha256, str) or re.fullmatch(r"[0-9a-f]{64}", vendor_controls_sha256) is None:
            raise ValueError("Inspection scope needs an approved controls SHA-256 digest")
        self.networks = tuple(sorted(networks))
        self.vendor_controls_sha256 = vendor_controls_sha256
        if stock_queue_scope is not None and type(stock_queue_scope) is not dict:
            raise ValueError("Stock inspection requires a queue scope object")
        self._stock_queue_scope = deepcopy(stock_queue_scope)

    def _authorize(self, intent):
        if isinstance(intent, InspectionIntent):
            if intent.mode == "off" and not intent.networks and intent.vendor_controls_sha256 is None:
                return intent
            if (
                intent.mode in ("notify", "block") and tuple(sorted(intent.networks)) == self.networks
                and intent.vendor_controls_sha256 == self.vendor_controls_sha256
            ):
                return InspectionIntent(intent.mode, self.networks, self.vendor_controls_sha256)
        raise InspectionControlError("Native inspection settings differ from the approved reference policy")

    def normalize(self, system_cfg):
        intent = self._authorize(decode_inspection_intent(system_cfg))
        document = json.loads(system_cfg)
        udapi = document["udapi"]
        services = udapi["services"]
        ids = services["idsIps"]
        if intent.mode != "off":
            companion = services.get("utm")
            expected = {"enabled": True, "eventType": "alert", "optIn": True,
                        "deviceID": ids["deviceID"], "token": ids["token"]}
            if companion != expected or companion["enabled"] is not True or companion["optIn"] is not True:
                raise InspectionControlError("Native inspection companion settings differ from the observed policy")
            del services["utm"]
        elif "utm" in services:
            raise InspectionControlError("Native inspection companion is present while inspection is off")
        services["idsIps"] = DISABLED_INSPECTION.copy()
        del udapi["versionDetail"]["services/idsIps"]
        return json.dumps(document), intent

    def apply(self, intent):
        self._call(intent, verify_only=False)

    def verify(self, intent):
        self._call(intent, verify_only=True)

    def prepare_engine(self, intent):
        if getattr(intent, "mode", None) != "block":
            raise InspectionControlError("Only Block can prepare an inspection engine")
        self._call(intent, phase="prepare-engine")

    def verify_engine(self, intent):
        self._call(intent, phase="verify-engine")

    def apply_engine(self, intent):
        if getattr(intent, "mode", None) not in ("off", "notify"):
            raise InspectionControlError("Only Off and Notify can apply an inspection engine transition")
        self._call(intent, phase="apply-engine")

    def _run(self, request, *, timeout):
        # Both provisioning and event polling use the router's exclusive command lock.
        with self._request_lock:
            return subprocess.run(self._argv, input=json.dumps(request).encode("utf-8"),
                                  capture_output=True, timeout=timeout, check=False)

    def read_events(self, cursor):
        if self._stock_queue_scope is None:
            raise InspectionControlError("Inspection event feed needs the approved queue scope")
        request = {"phase": "read-events", "queue_scope": self._stock_queue_scope, "cursor": cursor}
        try:
            result = self._run(request, timeout=12)
            if result.returncode or not 0 < len(result.stdout) <= 4096:
                raise ValueError
            response = json.loads(result.stdout, object_pairs_hook=_unique_fields, parse_constant=_invalid_constant)
            event_feed_forwarding_proof(response)
        except (OSError, ValueError, RecursionError, subprocess.SubprocessError):
            raise InspectionControlError("The stock inspection event feed is unavailable") from None
        return response

    def _call(self, intent, *, verify_only=False, phase=None):
        request = self._authorize(intent)
        payload = asdict(request)
        if phase is not None:
            if self._stock_queue_scope is None:
                raise InspectionControlError("Stock inspection needs the approved queue scope")
            payload.update(phase=phase, queue_scope=self._stock_queue_scope)
        elif verify_only:
            payload["verify_only"] = True
        try:
            result = self._run(payload, timeout=45)
            if result.returncode or not 0 < len(result.stdout) <= 4096:
                raise InspectionControlError("The inspection actuator could not verify the requested mode")
            status = json.loads(result.stdout)
        except (OSError, subprocess.SubprocessError, UnicodeError, json.JSONDecodeError) as error:
            raise InspectionControlError("The inspection actuator could not verify the requested mode") from error
        expected = {"schema": 1, "requested_mode": request.mode, "mode": request.mode, "reason": None}
        if phase is not None:
            expected["phase"] = phase
        if not isinstance(status, dict) or type(status.get("schema")) is not int or status != expected:
            raise InspectionControlError("The inspection actuator could not verify the requested mode")
