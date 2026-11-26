"""Build a pinned SSH transport for restricted VyOS management commands."""

from base64 import b64decode, b64encode
from hashlib import sha256
from ipaddress import IPv4Address
import os
from pathlib import Path
import re
import stat


_PATH = re.compile(r"/[A-Za-z0-9_./-]+")
_USER = re.compile(r"[a-z_][a-z0-9_-]{0,31}")
_ED25519_WIRE_HEADER = b"\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20"
_SYSTEMD_CREDENTIALS_ROOT = Path("/run/credentials")
_OPTIONS = (
    "BatchMode=yes", "IdentitiesOnly=yes", "IdentityAgent=none", "CertificateFile=none",
    "PreferredAuthentications=publickey", "PubkeyAcceptedAlgorithms=ssh-ed25519",
    "StrictHostKeyChecking=yes", "HostKeyAlgorithms=ssh-ed25519", "GlobalKnownHostsFile=none",
    "VerifyHostKeyDNS=no", "UpdateHostKeys=no", "CheckHostIP=no",
    "ForwardAgent=no", "ForwardX11=no", "ClearAllForwardings=yes", "EscapeChar=none",
    "ConnectionAttempts=1", "ConnectTimeout=4", "ServerAliveInterval=4", "ServerAliveCountMax=2",
)


def _private_identity(path, fd, info, permissions):
    if permissions in (0o400, 0o600):
        return True
    # A systemd read ACL for the service UID is reflected in the group mask.
    return (
        permissions == 0o440 and info.st_uid == 0 and os.geteuid() != 0
        and path.parent.parent == _SYSTEMD_CREDENTIALS_ROOT
        and os.environ.get("CREDENTIALS_DIRECTORY") == str(path.parent)
        and bool(os.fstatvfs(fd).f_flag & os.ST_RDONLY)
    )


def _credential(credential, label, *, private=False):
    if not isinstance(credential, (str, Path)) or not _PATH.fullmatch(str(credential)):
        raise ValueError(f"VyOS SSH {label} needs an absolute path without expansions")
    path = Path(credential)
    owners = {0, os.geteuid()}
    try:
        if path.resolve(strict=True) != path:
            raise ValueError(f"VyOS SSH {label} path must not contain symlinks")
        for parent in path.parents:
            mode = parent.stat()
            if mode.st_uid not in owners or (mode.st_mode & 0o022 and not mode.st_mode & stat.S_ISVTX):
                raise ValueError(f"VyOS SSH {label} directory is not trusted")
        with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), "rb") as stream:
            fd = stream.fileno()
            info = os.fstat(fd)
            permissions = stat.S_IMODE(info.st_mode)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid not in owners or permissions & 0o022
                    or not 0 < info.st_size <= 16384 or private and not _private_identity(path, fd, info, permissions)):
                raise ValueError(f"VyOS SSH {label} must be an owned credential with restricted permissions")
            return (path, b"") if private else (path, stream.read(16385))
    except (OSError, RuntimeError) as error:
        raise ValueError(f"VyOS SSH {label} could not be read safely") from error


def _verify_pin(raw, endpoint):
    lines = raw.splitlines()
    fields = lines[0].split() if len(lines) == 1 and len(raw) <= 16384 else ()
    if len(fields) < 3 or fields[:2] != [endpoint.encode("ascii"), b"ssh-ed25519"]:
        raise ValueError("VyOS SSH host key file must pin this endpoint to one plain Ed25519 key")
    try:
        wire = b64decode(fields[2], validate=True)
    except ValueError:
        raise ValueError("Invalid VyOS SSH Ed25519 host key encoding") from None
    if len(wire) != len(_ED25519_WIRE_HEADER) + 32 or not wire.startswith(_ED25519_WIRE_HEADER):
        raise ValueError("Invalid VyOS SSH Ed25519 host key")
    return wire


def _validate_endpoint(host, port):
    if not isinstance(host, str):
        raise ValueError("VyOS SSH host must be a literal unicast IPv4 address")
    try:
        address = IPv4Address(host)
    except ValueError:
        raise ValueError("VyOS SSH host must be a literal unicast IPv4 address") from None
    if address.packed[0] == 0 or address.is_loopback or address.is_multicast or address.is_reserved:
        raise ValueError("VyOS SSH host must be a literal unicast IPv4 address")
    if type(port) is not int or not 1 <= port <= 65535:
        raise ValueError("VyOS SSH port must be from 1 through 65535")


def _pinned_host_key(host, port, known_hosts_file):
    known_hosts, contents = _credential(known_hosts_file, "host key file")
    return known_hosts, _verify_pin(contents, host if port == 22 else f"[{host}]:{port}")


def vyos_ssh_host_fingerprint(host, port, known_hosts_file):
    """Read the SHA-256 fingerprint of the single Ed25519 pin for this endpoint."""
    _validate_endpoint(host, port)
    _, wire = _pinned_host_key(host, port, known_hosts_file)
    digest = b64encode(sha256(wire).digest()).decode("ascii").rstrip("=")
    return f"SHA256:{digest}"


def vyos_ssh_command(host, port, user, key_file, known_hosts_file) -> list[str]:
    """Use one pinned endpoint and let its restricted key select the actuator."""
    _validate_endpoint(host, port)
    if not isinstance(user, str) or not _USER.fullmatch(user) or user == "root":
        raise ValueError("VyOS SSH requires an explicit non-root router user")

    key, _ = _credential(key_file, "identity", private=True)
    known_hosts, _ = _pinned_host_key(host, port, known_hosts_file)

    argv = ["/usr/bin/ssh", "-F", "/dev/null", "-T", "-4"]
    for option in (*_OPTIONS, f"UserKnownHostsFile={known_hosts}"):
        argv.extend(("-o", option))
    # OpenSSH runs the key's forced command. An unrestricted key only runs false.
    return [*argv, "-i", str(key), "-p", str(port), "-l", user, "--", host, "/bin/false"]
