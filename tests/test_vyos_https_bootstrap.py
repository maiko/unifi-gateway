"""Check the inputs and private output of the stock HTTPS bootstrap."""
from pathlib import Path
import shutil
import stat
import subprocess
import sys

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts/vyos-https-bootstrap.py"
TEST_KEY = "ab" * 32


@pytest.fixture
def credentials(tmp_path):
    openssl = shutil.which("openssl")
    if not openssl:
        pytest.skip("The HTTPS bootstrap requires OpenSSL")
    directory = tmp_path / "credentials"
    directory.mkdir(mode=0o700)

    def run(*args):
        subprocess.run([openssl, *args], cwd=directory, check=True, capture_output=True)

    run("genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256", "-out", "ca.key")
    run("req", "-new", "-x509", "-key", "ca.key", "-out", "ca.pem", "-days", "1", "-subj", "/CN=Test CA",
        "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign")
    run("genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256", "-out", "router-key.pem")
    (directory / "router-key.pem").chmod(0o600)
    run("req", "-new", "-key", "router-key.pem", "-out", "router.csr", "-subj", "/CN=Router")
    (directory / "leaf.ext").write_text(
        "subjectAltName=IP:192.0.2.15\nextendedKeyUsage=serverAuth\nbasicConstraints=critical,CA:FALSE\n"
    )
    run("x509", "-req", "-in", "router.csr", "-CA", "ca.pem", "-CAkey", "ca.key",
        "-CAcreateserial", "-out", "router.pem", "-days", "1", "-extfile", "leaf.ext")
    key_file = directory / "vyos-api-key"
    key_file.write_text(TEST_KEY + "\n")
    key_file.chmod(0o600)
    return directory


def prepare(credentials, output, *, router="192.0.2.15", bridge="192.0.2.2"):
    return subprocess.run(
        [sys.executable, str(SCRIPT), router, bridge, "8443", str(credentials), str(output)],
        capture_output=True, text=True,
    )


def test_writes_only_the_https_and_pki_fragment_to_a_private_file(credentials, tmp_path):
    output = tmp_path / "bootstrap.config"
    result = prepare(credentials, output)
    assert result.returncode == 0, result.stderr
    assert TEST_KEY not in result.stdout + result.stderr
    assert stat.S_IMODE(output.stat().st_mode) == 0o600
    config = output.read_text()
    assert 'listen-address "192.0.2.15"' in config
    assert 'address "192.0.2.2/32"' in config
    assert 'port "8443"' in config
    assert f'key "{TEST_KEY}"' in config
    assert "unifi-gateway-https" in config and "unifi-gateway-ca" in config
    assert "interfaces {" not in config and "firewall {" not in config


def test_rejects_wildcard_client_and_mismatched_router_certificate(credentials, tmp_path):
    output = tmp_path / "bootstrap.config"
    assert "unicast" in prepare(credentials, output, bridge="0.0.0.0").stderr
    assert "certificate" in prepare(credentials, output, router="192.0.2.16").stderr
    assert not output.exists()


def test_rejects_shared_keys_and_preserves_existing_output(credentials, tmp_path):
    output = tmp_path / "bootstrap.config"
    key_file = credentials / "vyos-api-key"
    key_file.chmod(0o644)
    assert "private" in prepare(credentials, output).stderr
    assert not output.exists()
    key_file.chmod(0o600)
    output.write_text("operator data\n")
    assert "exists" in prepare(credentials, output).stderr
    assert output.read_text() == "operator data\n"


def test_rejects_a_trusted_tls_leaf_as_the_ca(credentials, tmp_path):
    subprocess.run(
        ["openssl", "req", "-new", "-x509", "-key", "router-key.pem", "-out", "router.pem",
         "-days", "1", "-subj", "/CN=Router",
         "-addext", "subjectAltName=IP:192.0.2.15", "-addext", "basicConstraints=critical,CA:FALSE"],
        cwd=credentials, capture_output=True, check=True,
    )
    shutil.copyfile(credentials / "router.pem", credentials / "ca.pem")
    output = tmp_path / "bootstrap.config"
    result = prepare(credentials, output)
    assert "CA:TRUE" in result.stderr
    assert not output.exists()


def test_rejects_a_ca_without_certificate_signing_usage(credentials, tmp_path):
    subprocess.run(
        ["openssl", "req", "-new", "-x509", "-key", "ca.key", "-out", "ca.pem",
         "-days", "1", "-subj", "/CN=Test CA", "-config", "/dev/null",
         "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "subjectKeyIdentifier=hash"],
        cwd=credentials, capture_output=True, check=True,
    )
    output = tmp_path / "bootstrap.config"
    result = prepare(credentials, output)
    assert result.returncode != 0
    assert "CA" in result.stderr
    assert not output.exists()


def test_rejects_using_the_ca_signing_key_for_https(credentials, tmp_path):
    shutil.copyfile(credentials / "ca.key", credentials / "router-key.pem")
    subprocess.run(
        ["openssl", "req", "-new", "-key", "router-key.pem", "-out", "router.csr", "-subj", "/CN=Router"],
        cwd=credentials, capture_output=True, check=True,
    )
    subprocess.run(
        ["openssl", "x509", "-req", "-in", "router.csr", "-CA", "ca.pem", "-CAkey", "ca.key",
         "-CAcreateserial", "-out", "router.pem", "-days", "1", "-extfile", "leaf.ext"],
        cwd=credentials, capture_output=True, check=True,
    )
    output = tmp_path / "bootstrap.config"
    result = prepare(credentials, output)
    assert "distinct" in result.stderr
    assert not output.exists()
