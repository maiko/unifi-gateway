"""Stock inspection acknowledgement must be verified before startup inform."""

from configparser import RawConfigParser
from hashlib import sha256
import json
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from inspection.event_worker import EventWorker
from provisioners.vyos import VyOSReconciler
import unifi_gateway


REVISION = "verified-revision"


def _read_config(path):
    config = RawConfigParser()
    assert config.read(path)
    return config


@pytest.fixture
def inspection_bridge(tmp_path, monkeypatch):
    command = tmp_path / "inspection-command"
    command.touch(mode=0o700)
    enrollment = tmp_path / "site.conf"
    state = tmp_path / "gateway.conf"
    stock = {
        "queue": 41110, "server_port": 18743, "rule_id": 50, "passthrough_chain": "UXG_INS_PASS",
        "topology_sha256": "1" * 64,
        "initiator": {"interface": "eth3.110", "host": "192.168.110.2", "zone": "VLAN110", "chain": "AB"},
        "responder": {"interface": "eth3.120", "host": "192.168.120.2", "zone": "VLAN120", "chain": "BA"},
    }
    config = RawConfigParser()
    config.read_dict({
        "gateway": {"device": "UXGENT", "platform": "vyos", "url": "http://controller.test:8080/inform",
                    "lan_ip": "192.0.2.1", "ports": "[]", "lan_mac": "02:00:00:00:00:01"},
        "vyos": {"api_url": "https://192.0.2.2"},
        "vyos_firewall": {"enabled": "true"},
        "vyos_inspection": {"enabled": "true", "command": str(command), "networks": '["br110","br120"]',
                               "vendor_controls_sha256": "a" * 64, "stock_queue": json.dumps(stock)},
        "vyos_security_events": {"enabled": "true", "automatic_notify_delivery": "true", "host": "192.0.2.3",
                                    "site_id": "ee9eab5c-1adf-4fbd-b812-b20508860867", "tls_hostname": "broker.test",
                                    "ca_sha256": "b" * 64},
    })
    with enrollment.open("w") as output:
        config.write(output)
    monkeypatch.setenv("UNIFI_GW_SITE_CONFIG", str(enrollment))
    monkeypatch.setattr(unifi_gateway, "CONFIG_FILE", str(state))
    monkeypatch.setattr(unifi_gateway, "UNHANDLED_LOG", str(tmp_path / "unhandled.json"))
    monkeypatch.setattr(unifi_gateway.signal, "signal", Mock())
    monkeypatch.setattr(unifi_gateway, "VyOSCollector", lambda _: SimpleNamespace(data={}, update=lambda: None))
    saved = unifi_gateway.UnifiGateway()
    saved.config["gateway"].update(is_adopted="true", use_aes_gcm="true", key="0123456789abcdef0123456789abcdef")
    system_cfg = '{"udapi":{}}'
    saved.config["provisioned"].update(cfgversion=REVISION, system_cfg=system_cfg)
    saved.config["vyos_applied"] = {"cfgversion": REVISION, "system_cfg_sha256": sha256(system_cfg.encode()).hexdigest()}
    saved._save_config()
    state.with_name("firewall.json").write_text(json.dumps({"schema_version": 1, "verified_revision": REVISION, "previous_revisions": []}))

    reconciler = Mock(spec=VyOSReconciler)
    reconciler.wan_fib_command = None
    monkeypatch.setattr(VyOSReconciler, "from_config", lambda *args, **kwargs: reconciler)
    gateway = unifi_gateway.UnifiGateway()
    monkeypatch.setattr(gateway._stop, "wait", lambda _: gateway._handle_signal(15, None))
    return gateway, state, reconciler


def test_stock_boot_withdraws_saved_acknowledgement_before_inform_and_event_worker(inspection_bridge, monkeypatch):
    gateway, state, reconciler = inspection_bridge
    informs, worker_snapshots = [], []

    def send_inform(wire):
        informs.append((json.loads(wire), _read_config(state)))
        gateway._handle_signal(15, None)
        return {"_type": "noop"}

    monkeypatch.setattr(gateway, "_send_inform", send_inform)
    monkeypatch.setattr(EventWorker, "run", lambda self, stop: worker_snapshots.append(_read_config(state)))

    gateway.run()

    assert len(informs) == 1 and len(worker_snapshots) == 1
    inform, persisted = informs[0]
    assert inform["cfgversion"] == "" and "cfgversion_effective" not in inform
    for snapshot in (persisted, worker_snapshots[0]):
        assert not snapshot.has_section("vyos_applied")
        assert snapshot.get("provisioned", "cfgversion") == REVISION
        assert snapshot.getboolean("gateway", "is_adopted")
    reconciler.reconcile.assert_not_called()


def test_stock_boot_write_failure_prevents_inform_and_event_worker(inspection_bridge, monkeypatch):
    gateway, state, reconciler = inspection_bridge
    inform, events = Mock(), Mock()
    monkeypatch.setattr(gateway, "_send_inform", inform)
    monkeypatch.setattr(EventWorker, "run", events)

    def stop_on_inform(_):
        gateway._handle_signal(15, None)
        return {"_type": "noop"}

    inform.side_effect = stop_on_inform
    monkeypatch.setattr(gateway, "_save_config", Mock(side_effect=OSError("State is read-only")))

    with pytest.raises(OSError, match="State is read-only"):
        gateway.run()

    inform.assert_not_called()
    events.assert_not_called()
    assert _read_config(state).get("vyos_applied", "cfgversion") == REVISION
    reconciler.reconcile.assert_not_called()
