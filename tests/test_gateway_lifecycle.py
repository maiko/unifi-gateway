# -*- coding: utf-8 -*-
"""Exercise Gateway Enterprise adoption, provisioning and shutdown."""
import json
import sys
import socket
from unittest.mock import call, patch, MagicMock, Mock

import pytest


import unifi_gateway


class TestRunInitializesCollector:
    """run() must initialize the collector before entering the inform loop."""

    def test_run_prepares_configured_shadow_primary_before_first_inform(self, tmp_path):
        conf = tmp_path / 'shadow.conf'
        conf.write_text(
            '[gateway]\ndevice = UXGENT\nplatform = vyos\nis_adopted = True\n'
            '[vyos_shadow_primary]\nenabled = True\n'
        )
        with patch.object(unifi_gateway, 'CONFIG_FILE', str(conf)):
            gateway = unifi_gateway.UnifiGateway()
        startup = Mock()
        gateway.datacollector = Mock()
        gateway._init_collector = startup.collector
        gateway._init_shadow_primary = startup.shadow
        gateway._exchange_inform = startup.inform

        def stop(*_args):
            gateway.running = False

        gateway._wait_for_next_inform = stop
        gateway.run()
        assert startup.method_calls == [call.collector(), call.shadow(), call.inform()]

    def test_shadow_primary_keeps_informing_when_peer_enrollment_cannot_load(self, tmp_path):
        conf = tmp_path / 'shadow.conf'
        conf.write_text(
            '[gateway]\ndevice = UXGENT\nplatform = vyos\nis_adopted = True\n'
            '[vyos_shadow_primary]\nenabled = True\n'
        )
        with patch.object(unifi_gateway, 'CONFIG_FILE', str(conf)):
            gateway = unifi_gateway.UnifiGateway()
        startup = Mock()
        gateway.datacollector = Mock()
        gateway._init_collector = startup.collector
        runtime = Mock()
        startup.build.side_effect = [FileNotFoundError('Standby enrollment is still being created'), runtime]
        gateway._build_shadow_primary = startup.build

        def inform():
            if startup.inform.call_count == 1:
                assert gateway._shadow_prepare_primary is None
            else:
                assert gateway._shadow_prepare_primary is runtime.prepare
                gateway.running = False

        startup.inform.side_effect = inform
        gateway._exchange_inform = startup.inform
        gateway._wait_for_next_inform = Mock()
        gateway.run()
        assert startup.method_calls == [call.collector(), call.build(), call.inform(), call.build(), call.inform()]

    def test_vyos_gateway_polls_until_native_adoption_with_discovery_disabled(self, tmp_path):
        device = "UXGENT"
        conf = tmp_path / 'gateway.conf'
        conf.write_text(
            '[global]\ndisable_broadcast = True\n'
            f'[gateway]\ndevice = {device}\nplatform = vyos\nis_adopted = False\nuse_aes_gcm = False\n'
            'url = http://controller.test:8080/inform\nlan_ip = 192.0.2.1\n'
            'lan_mac = 02:00:00:00:00:01\nports = []\n'
        )
        responses = iter([
            {'_type': 'httperror', 'code': '404'},
            {'_type': 'setparam'},
            {'_type': 'setparam', 'mgmt_cfg': 'authkey=0123456789abcdef0123456789abcdef\r\nuse_aes_gcm=true'},
            {'_type': 'noop'},
        ])
        with patch.object(unifi_gateway, 'CONFIG_FILE', str(conf)):
            gateway = unifi_gateway.UnifiGateway()
            gateway.datacollector = MagicMock(data={})

            def inform(_payload):
                response = next(responses)
                if response['_type'] == 'noop':
                    gateway.running = False
                return response

            with (patch.object(gateway, '_init_collector'),
                  patch.object(gateway._stop, 'wait', side_effect=[False] * 4),
                  patch.object(gateway, '_send_inform', side_effect=inform) as send,
                  patch.object(gateway, '_send_broadcast') as broadcast):
                gateway.run()

        assert send.call_count == 4
        assert all(json.loads(call.args[0])['model'] == device for call in send.call_args_list)
        assert gateway.config.getboolean('gateway', 'is_adopted')
        assert gateway.config.getboolean('gateway', 'use_aes_gcm')
        assert gateway.config['gateway']['key'] == '0123456789abcdef0123456789abcdef'
        broadcast.assert_not_called()


@pytest.fixture
def packaged_site(tmp_path, monkeypatch):
    credentials = tmp_path / 'credentials'
    credentials.mkdir()
    enrollment = credentials / 'site.conf'
    enrollment.write_text(
        '[gateway]\ndevice = UXGENT\nplatform = vyos\nurl = http://controller.test:8080/inform\n'
        'lan_ip = 192.0.2.1\nports = []\nhostname = Original\n'
        '[vyos]\napi_url = https://router.test\n'
    )
    state = tmp_path / 'gateway.conf'
    monkeypatch.setenv('UNIFI_GW_SITE_CONFIG', str(enrollment))
    monkeypatch.setattr(unifi_gateway, 'CONFIG_FILE', str(state))
    return unifi_gateway, enrollment, state


def test_packaged_enterprise_initializes_private_state_and_reads_updated_enrollment(packaged_site):
    module, enrollment, state = packaged_site
    first = module.UnifiGateway()
    assert state.stat().st_mode & 0o777 == 0o600
    assert first.config.getboolean('global', 'disable_broadcast') is False
    mac = first.config['gateway']['lan_mac']
    assert int(mac[:2], 16) & 3 == 2
    assert first.config['vyos']['key_file'] == str(enrollment.with_name('vyos-api-key'))
    first.config['gateway']['is_adopted'] = 'true'
    first.config['gateway']['key'] = '0123456789abcdef0123456789abcdef'
    first.config['gateway']['use_aes_gcm'] = 'true'
    first.config['gateway']['hostname'] = 'stale runtime value'
    first.config['provisioned']['cfgversion'] = 'applied'
    first._save_config()
    enrollment.write_text(enrollment.read_text().replace('Original', 'New site name'))

    restarted = module.UnifiGateway()

    assert restarted.config['gateway']['hostname'] == 'New site name'
    assert restarted.config['gateway']['lan_mac'] == mac
    assert restarted.config['gateway'].getboolean('is_adopted')
    assert restarted.config['gateway']['key'] == first.config['gateway']['key']
    assert restarted.config['provisioned']['cfgversion'] == 'applied'


@pytest.mark.parametrize("uptime", [None, 375])
def test_enterprise_discovery_uses_router_identity_and_stays_on_link(packaged_site, monkeypatch, uptime):
    module, enrollment, _ = packaged_site
    enrollment.write_text(enrollment.read_text()
                          + "\n[global]\ndiscovery_source_ipv4 = 198.18.250.10\n")
    gateway = module.UnifiGateway()
    udp = MagicMock()
    monkeypatch.setattr(module.socket, "socket", Mock(return_value=udp))
    sender = udp.__enter__.return_value

    if uptime is not None:
        gateway.datacollector = Mock(data={"uptime": uptime})
    gateway._send_broadcast(4)

    sender.bind.assert_called_once_with(("198.18.250.10", 0))
    assert call(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton("198.18.250.10")) in sender.setsockopt.call_args_list
    assert call(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 1) in sender.setsockopt.call_args_list
    packet, destination = sender.sendto.call_args.args
    assert destination == ("233.89.188.1", 10001)
    assert b"UXGENT.v6.0.17" in packet
    fields = {}
    offset = 4
    while offset < len(packet):
        size = int.from_bytes(packet[offset + 1:offset + 3], "big")
        fields[packet[offset]] = packet[offset + 3:offset + 3 + size]
        offset += 3 + size
    assert fields.get(10) == (uptime.to_bytes(4, "big") if uptime is not None else None)


def test_packaged_enterprise_requires_separate_state_for_a_new_controller(packaged_site):
    module, enrollment, state = packaged_site
    module.UnifiGateway()
    before = state.read_bytes()
    enrollment.write_text(enrollment.read_text().replace('controller.test', 'other.test'))

    with pytest.raises(ValueError, match='controller'):
        module.UnifiGateway()

    assert state.read_bytes() == before


def test_packaged_enrollment_refuses_to_replace_missing_identity_when_a_journal_exists(packaged_site):
    module, _, state = packaged_site
    journal = state.with_name("firewall.json")
    journal.write_text('{"verified_revision": "saved-revision"}')
    original = journal.read_bytes()
    with pytest.raises(ValueError, match="restore gateway.conf with firewall.json"):
        module.UnifiGateway()
    assert not state.exists()
    assert journal.read_bytes() == original


def test_packaged_enrollment_requires_the_journal_for_applied_identity_state(packaged_site):
    module, enrollment, state = packaged_site
    with enrollment.open("a") as handle:
        handle.write("[vyos_firewall]\nenabled = true\n")
    gateway = module.UnifiGateway()
    gateway.config["vyos_applied"] = {"cfgversion": "saved-revision"}
    gateway._save_config()
    original = state.read_bytes()
    with pytest.raises(ValueError, match="restore firewall.json with gateway.conf"):
        module.UnifiGateway()
    assert state.read_bytes() == original
    assert not state.with_name("firewall.json").exists()


@pytest.mark.parametrize(("journal_text", "error"), [
    ('{"schema_version":1,"verified_revision":"saved-revision","previous_revisions":[]}', None),
    ('{"schema_version":1,"verified_revision":"newer","previous_revisions":["saved-revision"]}', None),
    ('{"schema_version":1,"verified_revision":"older","previous_revisions":[]}', "does not contain the gateway's applied revision"),
    ('{"schema_version":1,"verified_revision":"saved-revision","previous_revisions":"broken"}', "Invalid provisioning journal"),
    ('{"schema_version":1,"verified_revision":"saved-revision","verified_revision":"newer","previous_revisions":[]}',
     "Invalid provisioning journal"),
    ('{"schema_version":1,"verified_revision":', "Invalid provisioning journal"),
    ('{"verified_revision":"saved-revision","previous_revisions":[]}', "Expected schema version"),
    ('{"schema_version":true,"verified_revision":"saved-revision","previous_revisions":[]}', "Expected schema version"),
])
def test_packaged_enrollment_checks_journal_revision_history(packaged_site, journal_text, error):
    module, enrollment, state = packaged_site
    with enrollment.open("a") as handle:
        handle.write("[vyos_firewall]\nenabled = true\n")
    gateway = module.UnifiGateway()
    gateway.config["vyos_applied"] = {"cfgversion": "saved-revision"}
    gateway._save_config()
    original = state.read_bytes()
    journal = state.with_name("firewall.json")
    journal.write_text(journal_text)
    if error:
        with pytest.raises(ValueError, match=error):
            module.UnifiGateway()
    else:
        assert module.UnifiGateway().config["vyos_applied"]["cfgversion"] == "saved-revision"
    assert state.read_bytes() == original
    assert journal.read_text() == journal_text


def test_packaged_uxg_enterprise_enrollment_keeps_its_own_state(packaged_site):
    module, enrollment, state = packaged_site

    gateway = module.UnifiGateway()
    mac = gateway.config['gateway']['lan_mac']
    assert gateway.config['gateway']['firmware'] == '6.0.17'
    assert module.UnifiGateway().config['gateway']['lan_mac'] == mac
    before = state.read_bytes()

    enrollment.write_text(enrollment.read_text().replace('UXGENT', 'UNKNOWN'))
    with pytest.raises(ValueError, match='model'):
        module.UnifiGateway()
    assert state.read_bytes() == before


def test_enrollment_rejects_other_models_before_creating_state(packaged_site):
    module, enrollment, state = packaged_site
    enrollment.write_text(enrollment.read_text().replace('UXGENT', 'UNKNOWN'))
    with pytest.raises(ValueError, match='requires model UXGENT'):
        module.UnifiGateway()
    assert not state.exists()


def test_packaged_enterprise_shadow_probe_uses_its_own_credentials(packaged_site):
    module, enrollment, _ = packaged_site
    enrollment.write_text(enrollment.read_text() + (
        '\n[vyos_shadow]\nprobe_enabled = true\nssh_user = gwprobe\n'
        'ssh_key_file = /untrusted-key\nssh_known_hosts_file = /untrusted-pins\n'
    ))

    settings = module.UnifiGateway().config['vyos_shadow']

    assert settings['ssh_key_file'] == str(enrollment.with_name('shadow-ssh-key'))
    assert settings['ssh_known_hosts_file'] == str(enrollment.with_name('shadow-ssh-known-hosts'))
    assert 'receipt_ssh_key_file' not in settings
    receipt = enrollment.with_name('shadow-receipt-ssh-key')
    receipt.write_text('test receipt credential')
    settings = module.UnifiGateway().config['vyos_shadow']
    assert settings['receipt_ssh_key_file'] == str(receipt)


def test_packaged_stock_ssh_uses_systemd_credential_paths(packaged_site):
    module, enrollment, _ = packaged_site
    assert not module.UnifiGateway().config.has_option('vyos_inspection', 'ssh_key_file')
    with enrollment.open('a') as stream:
        stream.write('[vyos_inspection]\nssh_host = 192.0.2.1\n'
                     'ssh_key_file = /untrusted-key\nssh_known_hosts_file = /untrusted-pins\n')
    options = module.UnifiGateway().config['vyos_inspection']
    assert options['ssh_key_file'] == str(enrollment.with_name('inspection-ssh-key'))
    assert options['ssh_known_hosts_file'] == str(enrollment.with_name('inspection-ssh-known-hosts'))


def test_packaged_wan_probe_resolves_only_named_systemd_credentials(packaged_site):
    module, enrollment, _ = packaged_site
    with enrollment.open('a') as stream:
        stream.write('[vyos_wan_health]\nenabled = true\nssh_user = vyos\n'
                     'ssh_known_hosts_file = /untrusted-pins\n'
                     'probes = {"eth0":{"target":"192.0.2.10","ssh_key_file":"wan1-ssh-key"}}\n')

    options = module.UnifiGateway().config['vyos_wan_health']
    assert options['ssh_known_hosts_file'] == str(enrollment.with_name('wan-ssh-known-hosts'))
    assert json.loads(options['probes'])['eth0']['ssh_key_file'] == str(enrollment.with_name('wan1-ssh-key'))

    enrollment.write_text(enrollment.read_text().replace('"wan1-ssh-key"', '"../elsewhere"'))
    with pytest.raises(ValueError, match='systemd credential'):
        module.UnifiGateway()


@pytest.mark.parametrize('wan_command', ['', '/lab/custom-wan-fib'])
def test_packaged_routing_scopes_use_the_pinned_observer_and_preserve_custom_readers(packaged_site, monkeypatch, wan_command):
    from backends import vyos_failover

    module, enrollment, _ = packaged_site
    enrollment.write_text(enrollment.read_text().replace('https://router.test', 'https://192.0.2.1') + (
        '\n[vyos_firewall]\nenabled = true\nrule_base = 80200\n'
        'interfaces = {"192.168.110.0/24":"eth3.110","192.168.120.0/24":"eth3.120"}\n'
        '[vyos_wan_failover]\nenabled = true\n'
        + (f'fib_command = {wan_command}\n' if wan_command else '') +
        '[vyos_policy_route]\nenabled = true\n'
        '[vyos_routing_ssh]\nenabled = true\nssh_user = vyos\n'
        'ssh_key_file = /untrusted-key\nssh_known_hosts_file = /untrusted-pins\n'
    ))
    collector = MagicMock(ports=[
        {'ifname': 'eth0', 'type': 'wan', 'realif': 'eth3.210'},
        {'ifname': 'eth2', 'type': 'wan2', 'realif': 'eth3.220'},
        {'ifname': 'eth1', 'type': 'lan', 'realif': 'eth3.110'},
        {'ifname': 'eth3', 'type': 'lan2', 'realif': 'eth3.120'},
    ])
    monkeypatch.setattr(module, 'VyOSCollector', lambda _: collector)
    monkeypatch.setattr(module, 'UNHANDLED_LOG', str(enrollment.with_name('unhandled.json')))

    with patch.object(vyos_failover, 'vyos_ssh_command', return_value=['/usr/bin/ssh', '/bin/false']) as ssh:
        gateway = module.UnifiGateway()
        gateway._init_collector()

    ssh.assert_called_once_with('192.0.2.1', 22, 'vyos', str(enrollment.with_name('routing-ssh-key')),
                                str(enrollment.with_name('routing-ssh-known-hosts')))
    observer = gateway.vyos_provisioner.policy_route_fib_command
    assert isinstance(observer, vyos_failover.VyOSRoutingSSH)
    assert gateway.vyos_provisioner.wan_fib_command == (wan_command or observer)
    assert gateway.vyos_provisioner.scope['policy_route'] == {'ssh_observer': {'host': '192.0.2.1', 'port': 22, 'user': 'vyos'}}


class TestCleanShutdown:
    """A stop signal must end run() at once (systemd enforces a shutdown timeout)."""

    def test_signal_interrupts_inform_wait(self, tmp_path):
        import time
        conf = tmp_path / 'gw.conf'
        conf.write_text('[gateway]\ndevice = UXGENT\nplatform = vyos\nis_adopted = True\n[provisioned]\n')
        with patch.object(unifi_gateway, 'CONFIG_FILE', str(conf)), \
             patch.object(unifi_gateway, 'UNHANDLED_LOG', str(tmp_path / 'unhandled.json')):
            gw = unifi_gateway.UnifiGateway()
            gw.interval = 30

            def inform_then_stop(data):
                gw._handle_signal(15, None)          # SIGTERM arrives during the cycle
                return {'_type': 'noop'}

            with patch.object(unifi_gateway, 'VyOSCollector', return_value=MagicMock()), \
                 patch.object(unifi_gateway, 'create_inform', return_value=b''), \
                 patch('signal.signal'), \
                 patch.object(gw, '_send_inform', side_effect=inform_then_stop):
                start = time.monotonic()
                gw.run()
                elapsed = time.monotonic() - start
        assert elapsed < 2, f'run() kept sleeping after the stop signal ({elapsed:.1f}s)'


@pytest.mark.parametrize('runner_fails', [False, True])
def test_native_speedtest_reports_a_live_sample_and_retries_before_advancing(tmp_path, runner_fails):
    from threading import Timer

    gate = tmp_path / 'continue-upload'
    runner = tmp_path / 'wan-test'
    runner.write_text(
        f'#!{sys.executable}\n'
        'import json, time\nfrom pathlib import Path\n'
        'down = dict(download_bps=82_250_000, latency_ms=4.2, timestamp=1_800_000_000)\n'
        'print(json.dumps(dict(down, phase="download")), flush=True)\n'
        f'while not Path({str(gate)!r}).exists(): time.sleep(0.01)\n'
        + ('raise SystemExit(1)\n' if runner_fails else (
            'result = dict(down, upload_bps=14_500_000)\n'
            'print(json.dumps(dict(result, phase="upload")), flush=True)\n'
            'print(json.dumps(result), flush=True)\n'
        ))
    )
    runner.chmod(0o700)
    config = tmp_path / 'gateway.conf'
    config.write_text(
        '[gateway]\nis_adopted = true\ndevice = UXGENT\nplatform = vyos\nports = []\n'
        'url = http://lab.example/inform\nlan_mac = 02:00:00:00:00:01\nlan_ip = 192.0.2.1\n'
        f'[vyos_speedtest]\nenabled = true\ncommand = {runner}\ntimeout = 6\n'
        'server_provider = Lab WAN peer\nserver_location = Isolated lab\n'
    )
    with patch.object(unifi_gateway, 'CONFIG_FILE', str(config)):
        gateway = unifi_gateway.UnifiGateway()
    collector = MagicMock(data={})
    reports = []

    def inform(payload):
        status = json.loads(payload).get('speedtest-status')
        if status is None:
            return {'_type': 'cmd', 'cmd': 'speed-test'}
        reports.append(status)
        if len(reports) == 1:
            return {'_type': 'httperror'}
        if len(reports) == 2:
            gate.touch()
        if status['status_summary'] in (2, 3):
            gateway._handle_signal(15, None)
        return {'_type': 'noop'}

    stop = Timer(8, gateway._handle_signal, args=(15, None))
    stop.start()
    try:
        with patch.object(unifi_gateway, 'VyOSCollector', return_value=collector), \
             patch.object(gateway, '_load_unhandled', return_value={}), \
             patch.object(gateway, '_send_inform', side_effect=inform), patch('signal.signal'):
            gateway.run()
    finally:
        gate.touch()
        stop.cancel()
    assert [report['status_summary'] for report in reports] == ([1, 1, 3] if runner_fails else [1, 1, 1, 2])
    assert reports[0] == reports[1] and 'xput_upload' not in reports[1]
    assert reports[0]['server'] == {'provider': 'Lab WAN peer', 'country': 'Isolated lab'}
    if runner_fails:
        assert 'xput_download' not in reports[2] and 'xput_upload' not in reports[2]
        assert reports[2]['rundate'] == reports[1]['rundate']
        assert gateway._speedtest_completed is None
    else:
        assert 'upload-progress' in reports[2] and reports[3]['xput_upload'] == 14.5
    collector.update.assert_called_once()


def test_native_restart_holds_inform_until_verified_recovery(tmp_path):
    from unifi_protocol import decode_inform, encode_inform

    config = tmp_path / 'gateway.conf'
    config.write_text(
        '[gateway]\nis_adopted = true\ndevice = UXGENT\nplatform = vyos\nports = []\n'
        'url = http://lab.example/inform\nlan_mac = 02:00:00:00:00:01\nlan_ip = 192.0.2.1\n'
        'key = 000102030405060708090a0b0c0d0e0f\nuse_aes_gcm = true\n'
    )
    with patch.object(unifi_gateway, 'CONFIG_FILE', str(config)):
        gateway = unifi_gateway.UnifiGateway()
    gateway.datacollector = MagicMock(data={})
    restart = gateway._vyos_restart = MagicMock()
    restart.ready_for_inform.side_effect = [True, False, True]
    gateway._stop = MagicMock()
    replies = iter([
        {'_type': 'reboot', 'reboot_type': 'soft', 'server_time_in_utc': '1795537800000'},
        {'_type': 'noop', 'server_time_in_utc': '1795537890000'},
    ])
    informs = []

    def wait(_):
        if gateway._stop.wait.call_count > 2:
            gateway.running = False
        return not gateway.running

    gateway._stop.wait.side_effect = wait

    def send(request, *, timeout):
        informs.append(decode_inform(gateway.config, request.data))
        reply = next(replies)
        if reply['_type'] == 'noop':
            assert len(informs) == 2
            assert restart.ready_for_inform.call_count == 3
            gateway._handle_signal(15, None)
        response = MagicMock()
        response.read.return_value = encode_inform(gateway.config, json.dumps(reply))
        return response

    with (
        patch.object(gateway, '_init_collector'),
        patch('signal.signal'),
        patch.object(unifi_gateway.urllib.request, 'urlopen', side_effect=send),
    ):
        gateway.run()
    restart.request.assert_called_once_with('1795537800000')
    assert [call.args for call in restart.accept_response.call_args_list] == [
        ('reboot', '1795537800000'), ('noop', '1795537890000'),
    ]
    assert gateway.datacollector.update.call_count == 2
    assert informs[0]['mac'] == informs[1]['mac'] == '02:00:00:00:00:01'

    gateway.config.set('gateway', 'use_aes_gcm', 'False')
    cbc_response = encode_inform(gateway.config, json.dumps({'_type': 'noop'}))
    gateway.config.set('gateway', 'use_aes_gcm', 'True')
    with patch.object(unifi_gateway.urllib.request, 'urlopen') as urlopen:
        urlopen.return_value.read.return_value = cbc_response
        with pytest.raises(ValueError, match='authenticated AES-GCM'):
            gateway._send_inform('{}')
        gateway._vyos_restart = None
        assert gateway._send_inform('{}') == {'_type': 'noop'}


@pytest.mark.parametrize('stock', [False, True])
def test_unhealthy_inspection_withdraws_and_persists_native_acknowledgement(tmp_path, stock):
    from inspection.controller import InspectionControlError
    from inspection.suricata import InspectionIntent

    conf = tmp_path / 'gw.conf'
    conf.write_text("[gateway]\ndevice = UXGENT\nplatform = vyos\n[vyos_applied]\ncfgversion = good\n")
    with patch.object(unifi_gateway, 'CONFIG_FILE', str(conf)):
        gw = unifi_gateway.UnifiGateway()
        intent = InspectionIntent('block', ('br110', 'br120'), 'a' * 64)
        gw._verified_inspection = intent
        gw._stock_inspection = stock
        gw.vyos_inspection = MagicMock()
        gw.vyos_provisioner = MagicMock()
        verify = gw.vyos_provisioner.verify_stock_inspection if stock else gw.vyos_inspection.verify
        verify.side_effect = InspectionControlError('Listener or queue is unavailable')
        gw._notify_vyos_provisioning_error = MagicMock()
        gw._check_inspection()

    verify.assert_called_once_with(intent)
    if stock:
        gw.vyos_inspection.verify.assert_not_called()
    gw.vyos_inspection.apply.assert_not_called()
    gw._notify_vyos_provisioning_error.assert_called_once_with()
    assert gw._verified_inspection is None
    assert not gw.config.has_section('vyos_applied')
    assert '[vyos_applied]' not in conf.read_text()


class TestAtomicWrite:

    def test_replaces_and_keeps_mode(self, tmp_path):
        import os
        target = tmp_path / 'gw.conf'
        target.write_text('old')
        os.chmod(target, 0o600)
        unifi_gateway._atomic_write(str(target), lambda f: f.write('new'))
        assert target.read_text() == 'new'
        assert os.stat(target).st_mode & 0o777 == 0o600
        assert [p.name for p in tmp_path.iterdir()] == ['gw.conf']   # no temp file left

    def test_failure_keeps_old_file(self, tmp_path):
        target = tmp_path / 'gw.conf'
        target.write_text('old')

        def broken(f):
            f.write('half')
            raise RuntimeError('killed mid-write')

        with pytest.raises(RuntimeError):
            unifi_gateway._atomic_write(str(target), broken)
        assert target.read_text() == 'old'
        assert [p.name for p in tmp_path.iterdir()] == ['gw.conf']


def _native_lifecycle_gateway(tmp_path, monkeypatch, *, model='UXGENT'):
    config_path = tmp_path / 'native.conf'
    unhandled_path = tmp_path / 'unhandled.json'
    config_path.write_text(
        f"[gateway]\ndevice = {model}\nplatform = vyos\nis_adopted = False\nuse_aes_gcm = False\n"
        "[provisioned]\n"
    )
    config_path.chmod(0o644)
    monkeypatch.setattr(unifi_gateway, 'CONFIG_FILE', str(config_path))
    monkeypatch.setattr(unifi_gateway, 'UNHANDLED_LOG', str(unhandled_path))
    return unifi_gateway.UnifiGateway(), config_path, unhandled_path


def _native_provisioning():
    from base64 import b64encode
    from hashlib import sha256
    from inspection.unifi_broker import BrokerTrust

    def pem(label, data):
        return b64encode(
            b'-----BEGIN ' + label + b'-----\n' + b64encode(data) +
            b'\n-----END ' + label + b'-----\n'
        ).decode()

    ca = b'synthetic native CA'
    trust = BrokerTrust(
        host='192.0.2.3', port=5671, site_id='f86e2468-0000-4000-8000-000000000001',
        tls_hostname='mq.example.test', ca_sha256=sha256(ca).hexdigest(),
        gateway_mac='02:00:00:00:00:01',
    )
    snapshot = {
        'udapi': {
            'version': 48, 'versionFormat': 'v2',
            'versionDetail': {'services/messageBroker': 3},
            'services': {'messageBroker': {
                'enabled': True, 'siteID': trust.site_id,
                'flowConfiguration': {'eventState': ['ipsIds', 'conntrack']},
                'rabbitMq': {
                    'host': trust.host, 'port': trust.port,
                    'authentication': {'username': 'synthetic-device', 'password': 'synthetic-broker-password'},
                    'tls': {
                        'enabled': True, 'verifyPeer': True,
                        'caCertificate': {'crt': pem(b'CERTIFICATE', ca)},
                        'clientCertificate': {
                            'crt': pem(b'CERTIFICATE', b'synthetic client cert'),
                            'key': pem(b'PRIVATE KEY', b'synthetic client key'),
                        },
                    },
                },
            }},
            'vpn/wireguard/servers': [{
                'id': 'outside-approved-interface', 'privateKey': 'synthetic-vpn-private',
                'remotePeers': [{'publicKey': 'synthetic-vpn-public', 'preSharedKey': 'synthetic-vpn-peer-secret'}],
            }],
            'vpn/ipsec/site-to-site': [{'id': 'outside-approved-peer', 'preSharedKey': 'synthetic-ipsec-secret'}],
            'vpn/openvpn/raws': [{'id': '1', 'configuration': 'synthetic-encoded-client-key',
                                  'authentication': {'password': 'synthetic-openvpn-password'}}],
        },
        'ubntconf': 'system.example.enabled=true',
    }
    return trust, snapshot


@pytest.mark.parametrize('enabled', [True, 'invalid'])
def test_enterprise_preserves_live_bgp_intent_without_persisting_frr_text(tmp_path, monkeypatch, enabled):
    from base64 import b64encode
    from configparser import RawConfigParser

    gateway, path, _ = _native_lifecycle_gateway(tmp_path, monkeypatch, model='UXGENT')
    encoded = b64encode(b'router bgp 64512\n neighbor 192.0.2.2 password synthetic-test-password\n').decode()
    raw = json.dumps({'udapi': {'routes/bgp/raw': {'enabled': enabled, 'config': encoded, 'unexpected': encoded}}})
    response = {'_type': 'setparam', 'cfgversion': 'candidate', 'system_cfg': raw}
    gateway.vyos_provisioner = MagicMock()
    gateway._apply_vyos_policy = MagicMock()

    gateway._handle_response(response)

    gateway._apply_vyos_policy.assert_called_once_with(response)
    assert response['system_cfg'] == raw
    state = RawConfigParser()
    state.read(path)
    stored = state['provisioned']['system_cfg']
    assert encoded not in stored
    summary = json.loads(stored)['udapi'].get('routes/bgp/raw')
    assert summary == ({'enabled': True} if enabled is True else None)


def test_enterprise_keeps_shadow_tunnel_keys_out_of_saved_state(tmp_path, monkeypatch, caplog):
    from configparser import RawConfigParser

    gateway, path, audit = _native_lifecycle_gateway(tmp_path, monkeypatch, model='UXGENT')
    example = 'synthetic-shadow-local-private-key'
    tunnel = {'enabled': True, 'clients': [{'id': 'uuspeersock', 'clientCert': {'crt': 'local-cert', 'key': example}}],
              'servers': [{'id': 'uuslocalsock', 'serverCert': {'crt': 'local-cert', 'key': example}}]}
    raw = json.dumps({'udapi': {'services': {'stunnel': tunnel, 'vrrp': {'enabled': True}}}})
    response = {'_type': 'setparam', 'cfgversion': 'shadow-complete', 'system_cfg': raw}
    gateway.vyos_provisioner = MagicMock()
    gateway._apply_vyos_policy = MagicMock()

    gateway._handle_response(response)

    gateway._apply_vyos_policy.assert_called_once_with(response)
    state = RawConfigParser()
    state.read(path)
    assert json.loads(state['provisioned']['system_cfg'])['udapi']['services'] == {'vrrp': {'enabled': True}}
    assert example not in path.read_text() + caplog.text
    assert not audit.exists() or example not in audit.read_text()


def test_enterprise_reset_preserves_enrollment_during_shadow_recovery(tmp_path, monkeypatch):
    from contextlib import nullcontext

    gateway, path, _ = _native_lifecycle_gateway(tmp_path, monkeypatch, model='UXGENT')
    gateway.config['gateway'].update({'is_adopted': 'True', 'use_aes_gcm': 'True', 'key': 'test-key'})
    gateway.config['vyos_shadow'] = {'provisioning_enabled': 'True'}
    gateway.vyos_provisioner = MagicMock()
    gateway.vyos_provisioner.locked_state.return_value = nullcontext({'shadow_handoff': {}})
    gateway.running = True
    original = path.read_text()

    gateway._handle_response({'_type': 'setdefault'})

    assert gateway.running and gateway.config['gateway']['key'] == 'test-key'
    assert path.read_text() == original


def test_enterprise_cannot_fall_back_to_probe_only_with_a_pending_handoff(tmp_path, monkeypatch):
    gateway, _, _ = _native_lifecycle_gateway(tmp_path, monkeypatch, model='UXGENT')
    journal = tmp_path / 'firewall.json'
    journal.write_text(json.dumps({'shadow_handoff': {'phase': 'primary_active'}}))
    gateway.config['vyos_firewall'] = {'state_path': str(journal)}
    gateway.config['gateway']['platform'] = 'vyos'
    monkeypatch.setattr(unifi_gateway, 'VyOSCollector', MagicMock())

    with pytest.raises(ValueError, match='Shadow Mode handoff journal'):
        gateway._init_collector()


def test_enterprise_redacts_setparam_after_raw_reconciliation_and_keeps_broker(tmp_path, monkeypatch):
    import configparser
    import json

    from inspection.unifi_broker import decode_broker_provisioning

    gateway, path, _ = _native_lifecycle_gateway(tmp_path, monkeypatch)
    trust, original = _native_provisioning()
    original['udapi']['routes/ospf/interfaces'] = [
        {'id': 'br110', 'authentication': {'authType': 'plainText', 'authKey': 'ospf-test-plain'},
         'authKey': 'ospf-unexpected-credential'},
        {'id': 'br120', 'authentication': {'authType': 'md5', 'authKeysMD5': [{'id': 1, 'key': 'ospf-test-md5'}]}},
    ]
    raw = json.dumps(original)
    response = {'_type': 'setparam', 'cfgversion': 'rejected-scope', 'system_cfg': raw}
    gateway.vyos_provisioner = MagicMock()
    gateway._apply_vyos_policy = MagicMock()

    gateway._handle_response(response)

    gateway._apply_vyos_policy.assert_called_once_with(response)
    assert response['system_cfg'] == raw
    saved = configparser.RawConfigParser()
    saved.read(path)
    stored = saved['provisioned']['system_cfg']
    assert decode_broker_provisioning(stored, trust=trust) == decode_broker_provisioning(raw, trust=trust)
    assert json.loads(stored)['ubntconf'] == original['ubntconf']
    assert 'synthetic-vpn-public' in stored
    assert 'synthetic-vpn-private' not in stored
    assert 'synthetic-vpn-peer-secret' not in stored
    assert 'synthetic-ipsec-secret' not in stored
    assert 'synthetic-encoded-client-key' not in stored
    assert 'synthetic-openvpn-password' not in stored
    assert 'ospf-test-plain' not in stored and 'ospf-test-md5' not in stored
    assert 'ospf-unexpected-credential' not in stored
    assert json.loads(stored)['udapi']['routes/ospf/interfaces'] == [
        {'id': 'br110', 'authentication': {'authType': 'plainText'}},
        {'id': 'br120', 'authentication': {'authType': 'md5'}},
    ]
    assert path.stat().st_mode & 0o777 == 0o600


def test_enterprise_adoption_logs_type_and_never_saves_vpn_keys(tmp_path, monkeypatch, caplog):
    import json
    import logging

    gateway, path, _ = _native_lifecycle_gateway(tmp_path, monkeypatch)
    _, original = _native_provisioning()
    device_key = '0123456789abcdef0123456789abcdef'
    response = {
        '_type': 'setparam', 'system_cfg': json.dumps(original), 'mgmt_cfg': f'authkey={device_key}',
    }
    monkeypatch.setattr(unifi_gateway, 'create_inform', lambda *_: '{}')

    with caplog.at_level(logging.DEBUG, logger='unifi-gateway'):
        gateway._handle_adoption(response)

    assert gateway.config.getboolean('gateway', 'is_adopted')
    assert gateway.config.get('gateway', 'key') == device_key
    assert 'setparam received' in caplog.text
    assert device_key not in caplog.text
    assert 'synthetic-ipsec-secret' not in caplog.text + path.read_text()
    assert path.stat().st_mode & 0o777 == 0o600


def test_enterprise_drops_raw_unknown_samples_and_migrates_loaded_samples(tmp_path, monkeypatch, caplog):
    import json

    gateway, path, unhandled = _native_lifecycle_gateway(tmp_path, monkeypatch)
    _, original = _native_provisioning()
    gateway.config.set('provisioned', 'system_cfg', json.dumps(original))
    with path.open('w') as persisted:
        gateway.config.write(persisted)
    unhandled.write_text(json.dumps({
        'response/previous': {
            'category': 'response', 'key': 'previous', 'count': 1,
            'last_seen': '2026-01-01T00:00:00Z', 'payload': {'system_cfg': 'synthetic-historical-secret'},
        },
    }))
    monkeypatch.setattr(unifi_gateway, 'VyOSCollector', lambda *_: MagicMock())

    gateway._init_collector()
    assert 'synthetic-ipsec-secret' not in path.read_text()
    assert path.stat().st_mode & 0o777 == 0o600
    gateway._handle_response({'_type': 'future-type', 'system_cfg': json.dumps(original)})
    gateway._handle_response({'_type': {'authkey': 'synthetic-malformed-label-secret'}})
    gateway._handle_response({'_type': 'setparam', 'mgmt_cfg': 'future_password=synthetic-mgmt-sample'})

    records = json.loads(unhandled.read_text())
    assert records['response/previous']['count'] == 1
    assert records['response/future-type']['count'] == 1
    assert records['mgmt_cfg/future_password']['count'] == 1
    assert all('payload' not in record for record in records.values())
    assert 'synthetic-malformed-label-secret' not in unhandled.read_text() + caplog.text
    assert 'synthetic-mgmt-sample' not in unhandled.read_text() + caplog.text
    assert 'synthetic-ipsec-secret' not in unhandled.read_text() + caplog.text + path.read_text()


@pytest.mark.parametrize('raw', [
    '{"udapi":{"vpn/ipsec/site-to-site":[{"preSharedKey":"synthetic-malformed-vpn"}]}',
    '{"udapi":{"preSharedKey":"synthetic-malformed-vpn","preSharedKey":"another"}}',
])
def test_enterprise_does_not_persist_invalid_system_cfg(tmp_path, monkeypatch, raw):
    gateway, path, unhandled = _native_lifecycle_gateway(tmp_path, monkeypatch)

    gateway._handle_response({'_type': 'setparam', 'system_cfg': raw})

    assert not gateway.config.has_option('provisioned', 'system_cfg')
    assert 'synthetic-malformed-vpn' not in path.read_text() + unhandled.read_text()
