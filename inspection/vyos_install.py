"""Install the fixed stock VyOS runner from its standalone router kit."""

import argparse
import json
import os
from pathlib import Path
import re
import socket
import stat
import sys
import tempfile


INSTALLATION = Path("/opt/unifi-gateway-vyos-inspection")
INSPECTION_OWNER = "unifi-inspection"
RUNTIME = Path("/run/unifi-gateway-vyos-inspection")
_ARCHIVE_LIMIT = 1024 * 1024


def local_router_hostname() -> str:
    hostname = socket.gethostname()
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}", hostname):
        raise ValueError("The router must have a valid local hostname before inspection enrollment")
    return hostname


def _file(path, *, owner=None, permissions=None):
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), "rb") as source:
        info = os.fstat(source.fileno())
        if (not stat.S_ISREG(info.st_mode) or owner is not None and info.st_uid != owner
                or permissions is not None and stat.S_IMODE(info.st_mode) != permissions):
            raise ValueError(f"Invalid file ownership or permissions for {path.name}")
        data = source.read(_ARCHIVE_LIMIT + 1)
    if not 0 < len(data) <= _ARCHIVE_LIMIT:
        raise ValueError(f"Invalid file size for {path.name}")
    return data


def _write(path, data, mode):
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode), "wb") as stream:
        os.fchmod(stream.fileno(), mode)
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())


def install(artifact: Path, destination: Path, controls_sha256: str, *, observe_notify=False) -> Path:
    if re.fullmatch(r"[0-9a-f]{64}", controls_sha256) is None:
        raise ValueError("Supply the approved controller controls SHA-256 digest")
    parent = destination.parent
    uid = os.geteuid()
    parent_status = parent.lstat()
    if (parent.resolve(strict=True) != parent or not stat.S_ISDIR(parent_status.st_mode)
            or parent_status.st_uid != uid or parent_status.st_mode & 0o022):
        raise ValueError("The installation parent must be an owned directory")

    approval = {
        "router_hostname": local_router_hostname(),
        "hook_owner": INSPECTION_OWNER,
        "vendor_controls_sha256": controls_sha256,
        "runtime_directory": str(RUNTIME),
        "status_path": str(RUNTIME / "status.json"),
        "engine_only": True,
    }
    if observe_notify:
        approval["observe_notify"] = True
    config = json.dumps(approval, separators=(",", ":")).encode() + b"\n"
    install_files = {"run": (_file(artifact), 0o700), "approval.json": (config, 0o600)}
    try:
        current = destination.lstat()
    except FileNotFoundError:
        with tempfile.TemporaryDirectory(dir=parent, prefix=".unifi-gateway-inspection-") as temporary:
            staging = Path(temporary) / "installation"
            staging.mkdir(mode=0o700)
            for name, (contents, mode) in install_files.items():
                _write(staging / name, contents, mode)
            if (_file(staging / "approval.json", owner=uid, permissions=0o600) != config
                    or local_router_hostname() != approval["router_hostname"]):
                raise ValueError("Could not verify the inspection enrollment for this router")
            staging.rename(destination)
    else:
        if (not stat.S_ISDIR(current.st_mode) or current.st_uid != uid
                or stat.S_IMODE(current.st_mode) != 0o700):
            raise ValueError("Inspection requires an owned private directory")
        if set(path.name for path in destination.iterdir()) != install_files.keys() or any(
            _file(destination / name, owner=uid, permissions=mode) != contents
            for name, (contents, mode) in install_files.items()
        ):
            raise ValueError("A different inspection kit or approval is already installed")
    return destination / "run"


def main() -> int:
    artifact = Path(sys.argv[0]).resolve(strict=True)
    if artifact == INSTALLATION / "run":
        from inspection.vyos_command import main as run

        return run(config_path=INSTALLATION / "approval.json")

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("install",))
    parser.add_argument("--controls-sha256", required=True)
    parser.add_argument("--observe-notify", action="store_true", help="Enable scoped forwarding evidence for Notify")
    args = parser.parse_args()
    try:
        if os.geteuid() != 0 or not sys.platform.startswith("linux"):
            raise ValueError("Run installation as root on the VyOS console")
        if not re.search(r'^ID="?vyos"?$', Path("/etc/os-release").read_text(), re.MULTILINE):
            raise ValueError("The inspection kit requires stock VyOS")
        for command in ("/usr/bin/suricata", "/usr/sbin/nft", "/usr/sbin/ip"):
            if not os.access(command, os.X_OK):
                raise ValueError(f"The installed VyOS image is missing {Path(command).name}")
        path = install(artifact, INSTALLATION, args.controls_sha256, observe_notify=args.observe_notify)
    except (OSError, ValueError) as error:
        parser.exit(1, f"{error}\n")
    print(f"Stock VyOS inspection command installed at {path}")
    return 0
