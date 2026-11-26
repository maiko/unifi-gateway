import importlib.util
import json
from pathlib import Path
import socket
import stat
import subprocess
import sys
from zipfile import ZipFile

import pytest


ROOT = Path(__file__).resolve().parents[1]
DIGEST = "a" * 64


def _builder():
    spec = importlib.util.spec_from_file_location(
        "build_vyos_inspection", ROOT / "scripts/build-vyos-inspection.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_built_kit_is_deterministic_and_contains_the_runner(tmp_path):
    builder = _builder()
    one, two = (tmp_path / name for name in ("one.pyz", "two.pyz"))
    builder.build(one)
    builder.build(two)
    assert one.read_bytes() == two.read_bytes()
    assert one.read_bytes().startswith(b"#!/usr/bin/python3 -I\n")
    with ZipFile(one) as archive:
        files = set(archive.namelist())
        assert {"__main__.py", "inspection/__init__.py", "inspection/vyos_install.py",
                "inspection/vyos_command.py", "inspection/vyos_eve_feed.py", "inspection/notify_capture.py",
                "inspection/notify_observation.py", "inspection/notify_runtime.py"} <= files
        assert all(name.endswith(".py") for name in files)
        assert archive.testzip() is None
    subprocess.run([sys.executable, "-I", "-c",
                    "import sys; sys.path.insert(0, sys.argv[1]); import inspection.notify_runtime", str(one)],
                   check=True, cwd=tmp_path, capture_output=True)
    with pytest.raises(FileExistsError):
        builder.build(one)


def test_install_is_private_idempotent_and_pins_the_stock_path(tmp_path, monkeypatch):
    from inspection.vyos_install import install

    monkeypatch.setattr(socket, "gethostname", lambda: "branch-router")
    archive = tmp_path / "kit.pyz"
    _builder().build(archive)
    destination = tmp_path / "inspection"
    installed = install(archive, destination, DIGEST)
    assert installed == destination / "run"
    assert installed.read_bytes() == archive.read_bytes()
    assert stat.S_IMODE(destination.stat().st_mode) == 0o700
    assert stat.S_IMODE(installed.stat().st_mode) == 0o700
    config = destination / "approval.json"
    assert stat.S_IMODE(config.stat().st_mode) == 0o600
    assert json.loads(config.read_text()) == {
        "router_hostname": "branch-router",
        "hook_owner": "unifi-inspection",
        "vendor_controls_sha256": DIGEST,
        "runtime_directory": "/run/unifi-gateway-vyos-inspection",
        "status_path": "/run/unifi-gateway-vyos-inspection/status.json",
        "engine_only": True,
    }
    assert install(archive, destination, DIGEST) == installed

    observing = tmp_path / "inspection-with-notify"
    install(archive, observing, DIGEST, observe_notify=True)
    assert json.loads((observing / "approval.json").read_text())["observe_notify"] is True
    monkeypatch.setattr(socket, "gethostname", lambda: "other-router")
    with pytest.raises(ValueError, match="already installed"):
        install(archive, destination, DIGEST)
    assert json.loads(config.read_text())["router_hostname"] == "branch-router"


def test_install_never_replaces_another_approval_or_bypasses_private_paths(tmp_path):
    from inspection.vyos_install import install

    archive = tmp_path / "kit.pyz"
    _builder().build(archive)
    destination = tmp_path / "inspection"
    with pytest.raises(ValueError, match="SHA-256"):
        install(archive, destination, "invalid")
    assert not destination.exists()
    with pytest.raises(ValueError, match="private directory"):
        destination.mkdir(mode=0o777)
        destination.chmod(0o777)
        install(archive, destination, DIGEST)
    destination.chmod(0o700)
    destination.rmdir()
    install(archive, destination, DIGEST)
    content = (destination / "approval.json").read_bytes()
    with pytest.raises(ValueError, match="already installed"):
        install(archive, destination, "b" * 64)
    assert (destination / "approval.json").read_bytes() == content
    link = tmp_path / "link"
    link.symlink_to(destination, target_is_directory=True)
    with pytest.raises(ValueError, match="private directory"):
        install(archive, link, DIGEST)
