from base64 import b64encode
from hashlib import sha256
import os
from pathlib import Path
import subprocess
from types import SimpleNamespace

import pytest


HOST = "192.0.2.4"
PUBLIC_KEY = b64encode(b"\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20" + bytes(range(32))).decode()


@pytest.fixture
def credentials(tmp_path):
    private_key = tmp_path / "inspection-ssh-key"
    private_key.write_text("The client parses the private key during the SSH handshake.\n")
    private_key.chmod(0o400)
    known_hosts = tmp_path / "inspection-ssh-known-hosts"
    known_hosts.write_text(f"{HOST} ssh-ed25519 {PUBLIC_KEY}\n")
    known_hosts.chmod(0o600)
    return private_key, known_hosts


def test_host_key_fingerprint_reads_the_pinned_ed25519_wire_key(credentials):
    from backends.vyos_ssh import vyos_ssh_host_fingerprint

    _, known_hosts = credentials
    wire = b"\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20" + bytes(range(32))
    expected = "SHA256:" + b64encode(sha256(wire).digest()).decode("ascii").rstrip("=")
    assert vyos_ssh_host_fingerprint(HOST, 22, known_hosts) == expected
    with pytest.raises(ValueError, match="pin this endpoint"):
        vyos_ssh_host_fingerprint(HOST, 2222, known_hosts)

@pytest.mark.skipif(not Path("/usr/bin/ssh").is_file(), reason="OpenSSH client unavailable")
@pytest.mark.parametrize("port, endpoint", [(22, HOST), (2222, f"[{HOST}]:2222")])
def test_effective_ssh_configuration_uses_one_pin_and_no_ambient_auth(port, endpoint, credentials):
    from backends.vyos_ssh import vyos_ssh_command

    private_key, known_hosts = credentials
    known_hosts.write_text(f"{endpoint} ssh-ed25519 {PUBLIC_KEY}\n")
    known_hosts.chmod(0o400)
    argv = vyos_ssh_command(HOST, port, "vyos", private_key, known_hosts)
    assert argv[:3] == ["/usr/bin/ssh", "-F", "/dev/null"]
    assert argv[-2:] == [HOST, "/bin/false"]

    result = subprocess.run([argv[0], "-G", *argv[1:]], capture_output=True, text=True, check=True, timeout=5)
    options = dict(line.split(" ", 1) for line in result.stdout.splitlines())
    assert options["hostname"] == HOST and options["user"] == "vyos" and options["port"] == str(port)
    assert options["stricthostkeychecking"] in {"true", "yes"}
    assert options["userknownhostsfile"] == str(known_hosts)
    assert options["globalknownhostsfile"] == "none"
    assert options["hostkeyalgorithms"] == options["pubkeyacceptedalgorithms"] == "ssh-ed25519"
    assert [line for line in result.stdout.splitlines() if line.startswith("identityfile ")] == [
        f"identityfile {private_key}",
    ]
    assert options["identityagent"] == "none" and options["certificatefile"] == "none"
    assert options["preferredauthentications"] == "publickey"
    assert options["requesttty"] in {"false", "no"}
    assert options["clearallforwardings"] in {"true", "yes"}
    for name in ("batchmode", "identitiesonly"):
        assert options[name] in {"true", "yes"}
    for name in ("forwardagent", "forwardx11", "updatehostkeys", "verifyhostkeydns"):
        assert options[name] in {"false", "no"}
    assert 0 < int(options["connecttimeout"]) < 12


@pytest.mark.parametrize("host, port, user", [
    ("router.local", 22, "vyos"), ("::1", 22, "vyos"), ("127.0.0.1", 22, "vyos"),
    ("224.0.0.5", 22, "vyos"), ("0.0.0.0", 22, "vyos"), ("255.255.255.255", 22, "vyos"),
    ("-F /tmp/config", 22, "vyos"), (HOST, True, "vyos"), (HOST, "22", "vyos"),
    (HOST, 0, "vyos"), (HOST, 65536, "vyos"), (HOST, 22, "root"),
    (HOST, 22, "-oProxyCommand=bad"), (HOST, 22, "user@other"), (HOST, 22, "a" * 33),
])
def test_refuses_ambiguous_or_privileged_ssh_endpoints(host, port, user, credentials):
    from backends.vyos_ssh import vyos_ssh_command

    with pytest.raises(ValueError):
        vyos_ssh_command(host, port, user, *credentials)


@pytest.mark.parametrize("text, port", [
    (f"other ssh-ed25519 {PUBLIC_KEY}\n", 22),
    (f"{HOST},other ssh-ed25519 {PUBLIC_KEY}\n", 22),
    (f"* ssh-ed25519 {PUBLIC_KEY}\n", 22),
    (f"{HOST} ssh-ed25519 {PUBLIC_KEY}\n", 2222),
    (f"[{HOST}]:22 ssh-ed25519 {PUBLIC_KEY}\n", 22),
    (f"@cert-authority {HOST} ssh-ed25519 {PUBLIC_KEY}\n", 22),
    (f"{HOST} ssh-rsa {PUBLIC_KEY}\n", 22),
    (f"{HOST} ssh-ed25519 AQID\n", 22),
    (f"{HOST} ssh-ed25519 {PUBLIC_KEY}\nother ssh-ed25519 {PUBLIC_KEY}\n", 22),
])
def test_requires_exactly_one_well_formed_ed25519_pin_for_the_endpoint(credentials, text, port):
    from backends.vyos_ssh import vyos_ssh_command

    private_key, known_hosts = credentials
    known_hosts.write_text(text)
    with pytest.raises(ValueError, match="host key"):
        vyos_ssh_command(HOST, port, "vyos", private_key, known_hosts)


@pytest.mark.parametrize("credential", [0, 1])
def test_refuses_symlink_and_unsafe_credential_path(tmp_path, credentials, credential):
    from backends.vyos_ssh import vyos_ssh_command

    for name in ("symlink", "expansion-%h", "multiple files", "relative"):
        files = list(credentials)
        original = files[credential]
        replacement = tmp_path / name
        if name == "symlink":
            replacement.symlink_to(original)
        else:
            replacement.write_bytes(original.read_bytes())
            replacement.chmod(0o400)
        files[credential] = name if name == "relative" else replacement
        with pytest.raises(ValueError):
            vyos_ssh_command(HOST, 22, "vyos", *files)


@pytest.mark.parametrize("credential, mode", [(0, 0o440), (0, 0o644), (1, 0o666)])
def test_refuses_exposed_private_keys_and_untrusted_host_pin_writes(credentials, credential, mode):
    from backends.vyos_ssh import vyos_ssh_command

    credentials[credential].chmod(mode)
    with pytest.raises(ValueError):
        vyos_ssh_command(HOST, 22, "vyos", *credentials)


@pytest.mark.parametrize("read_only", [False, True])
def test_systemd_acl_key_requires_a_read_only_service_mount(credentials, monkeypatch, read_only):
    from backends import vyos_ssh

    private_key, known_hosts = credentials
    private_key.chmod(0o440)
    inode = private_key.stat().st_ino
    original_fstat = os.fstat

    def fstat(fd):
        info = original_fstat(fd)
        if info.st_ino == inode:
            return SimpleNamespace(st_mode=info.st_mode, st_uid=0, st_size=info.st_size)
        return info

    monkeypatch.setattr(vyos_ssh, "_SYSTEMD_CREDENTIALS_ROOT", private_key.parent.parent, raising=False)
    monkeypatch.setenv("CREDENTIALS_DIRECTORY", str(private_key.parent))
    monkeypatch.setattr(os, "geteuid", lambda: 1000 if private_key.stat().st_uid == 0 else private_key.stat().st_uid)
    monkeypatch.setattr(os, "fstat", fstat)
    monkeypatch.setattr(os, "fstatvfs", lambda _: SimpleNamespace(f_flag=os.ST_RDONLY if read_only else 0))

    if read_only:
        argv = vyos_ssh.vyos_ssh_command(HOST, 22, "vyos", private_key, known_hosts)
        assert str(private_key) in argv
    else:
        with pytest.raises(ValueError, match="restricted permissions"):
            vyos_ssh.vyos_ssh_command(HOST, 22, "vyos", private_key, known_hosts)
