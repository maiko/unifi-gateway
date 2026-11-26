# -*- coding: utf-8 -*-
import configparser
import argparse
from collections import deque
from dataclasses import replace
from functools import partial
from hashlib import sha256
import json
import logging
import logging.handlers
import os
import re
import signal
import socket
import sys
import threading
import time
import urllib.request
import urllib.error
from urllib.parse import urlsplit

from collectors.vyos import VyOSCollector
from gateway_profiles.enterprise import require_enterprise
from provisioners.vyos_shadow_handoff import SHADOW_HANDOFF, pending_shadow_handoff
from tools import atomic_write as _atomic_write
from unifi_protocol import (
    create_broadcast_message, create_inform, encode_inform, decode_inform,
)

logger = logging.getLogger('unifi-gateway')

CONFIG_FILE = os.environ.get('UNIFI_GW_CONFIG', 'conf/unifi-gateway.conf')


def setup_logging():
    log_level = os.environ.get('UNIFI_GW_LOG_LEVEL', 'DEBUG').upper()
    log_file = os.environ.get('UNIFI_GW_LOG_FILE', None)
    formatter = logging.Formatter(
        '%(asctime)s [unifi-gateway] : %(levelname)s : %(message)s'
    )

    if log_file:
        handler = logging.handlers.RotatingFileHandler(
            log_file, maxBytes=10 * 1024 * 1024, backupCount=3
        )
    else:
        handler = logging.StreamHandler()

    handler.setFormatter(formatter)
    logger.setLevel(getattr(logging, log_level, logging.DEBUG))
    logger.addHandler(handler)


setup_logging()


UNHANDLED_LOG = os.environ.get(
    'UNIFI_GW_UNHANDLED_LOG',
    os.path.join(os.path.dirname(CONFIG_FILE), 'unhandled_commands.json'),
)
_MESSAGE_LABEL = re.compile(r'[A-Za-z0-9_][A-Za-z0-9_.-]{0,63}')
_UNHANDLED_CATEGORIES = {'command', 'mgmt_cfg', 'response', 'setparam'}
_NATIVE_VPN_SECRETS = {'privatekey', 'presharedkey'}


def _message_label(value):
    return value if isinstance(value, str) and _MESSAGE_LABEL.fullmatch(value) else 'unknown'


def _unhandled_metadata(entries):
    if not isinstance(entries, dict):
        return {}
    metadata = {}
    for row in entries.values():
        if not isinstance(row, dict):
            continue
        category, count, last_seen = row.get('category'), row.get('count'), row.get('last_seen')
        if (not isinstance(category, str) or category not in _UNHANDLED_CATEGORIES
                or type(count) is not int or count < 1 or not isinstance(last_seen, str)
                or not re.fullmatch(r'[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z', last_seen)):
            continue
        key = _message_label(row.get('key'))
        name = f'{category}/{key}'
        previous = metadata.get(name, {})
        metadata[name] = {'category': category, 'key': key, 'count': count + previous.get('count', 0),
                          'last_seen': max(last_seen, previous.get('last_seen', ''))}
    return metadata


def _redact_native_system_cfg(value):
    redacted = False

    def filter_fields(pairs):
        nonlocal redacted
        node = {}
        for key, item in pairs:
            if key in node:
                raise ValueError('Duplicate system_cfg field')
            node[key] = item
        for key in tuple(node):
            if key.casefold() in _NATIVE_VPN_SECRETS:
                del node[key]
                redacted = True
        return node

    def reject_constant(_value):
        raise ValueError('Invalid system_cfg constant')

    try:
        document = json.loads(value, object_pairs_hook=filter_fields, parse_constant=reject_constant)
        if not isinstance(document, dict) or not isinstance(document.get('udapi'), dict):
            return None
        udapi = document['udapi']
        services = udapi.get('services')
        if isinstance(services, dict):
            for key in tuple(services):
                if key.casefold() == 'stunnel':
                    del services[key]
                    redacted = True
        for key in tuple(udapi):
            if key.casefold().startswith('vpn/openvpn/') or key.casefold() == 'services/stunnel':
                del udapi[key]
                redacted = True
            elif key.casefold() == 'routes/bgp/raw':
                policy = udapi.pop(key)
                if isinstance(policy, dict) and type(policy.get('enabled')) is bool:
                    udapi[key] = {'enabled': policy['enabled']}
                redacted = True
            elif key.casefold() == 'routes/ospf/interfaces':
                rows = udapi[key]
                if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
                    del udapi[key]
                    redacted = True
                    continue
                summaries = []
                for row in rows:
                    summary = {
                        name: row[name] for name in ('cost', 'helloInterval', 'deadInterval', 'priority')
                        if type(row.get(name)) is int
                    }
                    if type(row.get('passiveInterface')) is bool:
                        summary['passiveInterface'] = row['passiveInterface']
                    identity = row.get('id')
                    if isinstance(identity, str) and _MESSAGE_LABEL.fullmatch(identity):
                        summary['id'] = identity
                    auth = row.get('authentication')
                    mode = auth.get('authType') if isinstance(auth, dict) else None
                    if mode in ('off', 'plainText', 'md5'):
                        summary['authentication'] = {'authType': mode}
                    summaries.append(summary)
                if summaries != rows:
                    udapi[key] = summaries
                    redacted = True
        return json.dumps(document, separators=(',', ':'), allow_nan=False) if redacted else value
    except (TypeError, ValueError, RecursionError):
        return None


class UnifiGateway:

    def __init__(self, *, prepare_shadow_primary=None, shadow_forwarding_probe=None, _observer_config=None):
        if (prepare_shadow_primary is None) != (shadow_forwarding_probe is None):
            raise ValueError('Shadow Mode primary dispatch requires both a prepared pair and a forwarding probe')
        self.interval = 10
        self.running = True
        # set by the signal handler; waits on it end immediately (time.sleep would run to the end)
        self._stop = threading.Event()
        site_config = os.environ.get('UNIFI_GW_SITE_CONFIG')
        self._shadow_credential_prefix = os.environ.get('UNIFI_GW_SHADOW_CREDENTIAL_PREFIX', '')
        if _observer_config is not None:
            self.config = _observer_config
        elif site_config:
            from gateway_profiles.vyos_install import load_enrolled_config

            self.config = load_enrolled_config(
                site_config, CONFIG_FILE, credential_prefix=self._shadow_credential_prefix,
            )
        else:
            self.config = configparser.RawConfigParser()
            with open(CONFIG_FILE) as source:
                self.config.read_file(source)

        require_enterprise(self.config)
        if not self.config.has_section('provisioned'):
            self.config.add_section('provisioned')

        self.datacollector = None
        self.vyos_provisioner = None
        self.controller_broker_trust = None
        self.vyos_inspection = None
        self._stock_inspection = False
        self._security_event_worker = None
        self._wan_speedtest = None
        self._vyos_restart = None
        self._shadow_peer_probe = None
        self._shadow_prepare_primary = prepare_shadow_primary
        self._shadow_forwarding_probe = shadow_forwarding_probe
        self._shadow_advertiser = None
        self._speedtest_thread = None
        self._speedtest_reports = deque()
        self._speedtest_completed = None
        self._verified_inspection = None
        self._verified_ipsec = None
        self._verified_openvpn = None
        self._wan_observations = {}
        self._inspection_check_at = 0
        self._vyos_provisioning_error = None
        self._unhandled = {}

    def _init_collector(self, *, observe_standby=False):
        """Load live router telemetry and initialize enabled provisioning operations."""
        self.datacollector = VyOSCollector(self.config)
        if self.config.getboolean('vyos_shadow', 'probe_enabled', fallback=False):
            from gateway_profiles.uxg_enterprise_shadow import ShadowPeerProbe

            self._shadow_peer_probe = ShadowPeerProbe(self.datacollector.backend, self.datacollector.ports, self.config)
        if not observe_standby:
            self._unhandled = self._load_unhandled()
            metadata = _unhandled_metadata(self._unhandled)
            if metadata != self._unhandled:
                self._unhandled = metadata
                self._save_unhandled()
            if self._sanitize_stored_system_cfg():
                self._save_config()
        firewall_enabled = self.config.getboolean('vyos_firewall', 'enabled', fallback=False)
        dhcp_enabled = self.config.getboolean('vyos_dhcp', 'enabled', fallback=False)
        routes_enabled = self.config.getboolean('vyos_static_routes', 'enabled', fallback=False)
        dns_enabled = self.config.getboolean('vyos_dns', 'enabled', fallback=False)
        nat_enabled = self.config.getboolean('vyos_source_nat', 'enabled', fallback=False)
        wireguard_enabled = self.config.getboolean('vyos_wireguard', 'enabled', fallback=False)
        port_forward_enabled = self.config.getboolean('vyos_port_forward', 'enabled', fallback=False)
        vlan_enabled = self.config.getboolean('vyos_vlan', 'enabled', fallback=False)
        mdns_enabled = self.config.getboolean('vyos_mdns', 'enabled', fallback=False)
        ospf_enabled = self.config.getboolean('vyos_ospf', 'enabled', fallback=False)
        ipsec_enabled = self.config.getboolean('vyos_ipsec', 'enabled', fallback=False)
        openvpn_enabled = self.config.getboolean('vyos_openvpn', 'enabled', fallback=False)
        wan_enabled = self.config.getboolean('vyos_wan_failover', 'enabled', fallback=False)
        policy_route_enabled = self.config.getboolean('vyos_policy_route', 'enabled', fallback=False)
        routing_ssh_enabled = self.config.getboolean('vyos_routing_ssh', 'enabled', fallback=False)
        qos_enabled = self.config.getboolean('vyos_qos', 'enabled', fallback=False)
        inspection_enabled = self.config.getboolean('vyos_inspection', 'enabled', fallback=False)
        events_enabled = self.config.getboolean('vyos_security_events', 'enabled', fallback=False)
        restart_enabled = self.config.getboolean('vyos_restart', 'enabled', fallback=False)
        commit_recovery_enabled = self.config.getboolean('vyos_restart', 'recover_provisioning', fallback=False)
        bgp_scope = None
        if self.config.getboolean('vyos_bgp', 'enabled', fallback=False):
            from provisioners.vyos_bgp import BgpScope

            if not firewall_enabled or not commit_recovery_enabled:
                raise ValueError('BGP provisioning requires a VyOS-backed UXG Enterprise and managed commit recovery')
            bgp_scope = BgpScope.from_config(self.config['vyos_bgp'])
        shadow_writes = self.config.getboolean('vyos_shadow', 'provisioning_enabled', fallback=False)
        if shadow_writes and (self._shadow_peer_probe is None or not firewall_enabled or not commit_recovery_enabled):
            raise ValueError('Shadow Mode provisioning needs the prepared observer and managed commit recovery')
        firewall_state = self.config.get('vyos_firewall', 'state_path', fallback=None)
        authenticated = (
            self.config.getboolean('gateway', 'is_adopted', fallback=False)
            and self.config.getboolean('gateway', 'use_aes_gcm', fallback=False)
        )
        if (firewall_state
                and not (shadow_writes and authenticated) and pending_shadow_handoff(firewall_state)):
            raise ValueError('Keep authenticated Shadow Mode provisioning enabled for the pending Shadow Mode handoff journal')
        if firewall_state and not (restart_enabled and authenticated):
            from gateway_profiles.vyos_restart import pending_restart

            if pending_restart(firewall_state):
                raise ValueError('Retain the adopted gateway and enable restart verification until VyOS recovers')
        if not observe_standby and self.config.getboolean('vyos_speedtest', 'enabled', fallback=False):
            from gateway_profiles.uxg_speedtest import WanSpeedTest

            options = self.config['vyos_speedtest']
            self._wan_speedtest = WanSpeedTest(options['command'], timeout=options.getint('timeout', 45))
        if any((dhcp_enabled, routes_enabled, dns_enabled, nat_enabled, wireguard_enabled,
                port_forward_enabled, vlan_enabled, mdns_enabled, ospf_enabled, ipsec_enabled, openvpn_enabled,
                inspection_enabled, wan_enabled, policy_route_enabled, qos_enabled,
                restart_enabled, commit_recovery_enabled)) and not firewall_enabled:
            raise ValueError('Enable VyOS firewall provisioning before enabling managed features')
        stock_inspection_policy = None
        if inspection_enabled:
            from inspection.controller import InspectionController

            options = self.config['vyos_inspection']
            if 'stock_queue' in options:
                from provisioners.vyos_inspection import StockInspectionPolicy

                stock_inspection_policy = StockInspectionPolicy.from_json(options['stock_queue'])
            self._stock_inspection = stock_inspection_policy is not None
            self.vyos_inspection = InspectionController.from_config(
                options, management_host=urlsplit(self.config.get('vyos', 'api_url', fallback='')).hostname,
                stock_queue_scope=stock_inspection_policy.engine_scope if self._stock_inspection else None,
            )
        if events_enabled and not observe_standby:
            from inspection.event_delivery import broker_trust_from_config

            if not firewall_enabled:
                raise ValueError('Security event delivery requires VyOS provisioning')
            self.controller_broker_trust = broker_trust_from_config(self.config)
            settings = self.config['vyos_security_events']
            automatic_drop = settings.getboolean('automatic_drop_delivery', fallback=False)
            automatic_notify = settings.getboolean('automatic_notify_delivery', fallback=False)
            if automatic_drop or automatic_notify:
                from inspection.event_delivery import verified_broker_from_state
                from inspection.event_worker import EventWorker

                if not self._stock_inspection:
                    raise ValueError('Automatic security event delivery requires the stock VyOS inspection queue')
                journal = settings.get('journal_path', fallback=os.path.join(os.path.dirname(CONFIG_FILE), 'security-events.sqlite'))
                self._security_event_worker = EventWorker(
                    self.vyos_inspection.read_events,
                    partial(verified_broker_from_state, CONFIG_FILE, self.controller_broker_trust),
                    journal_path=journal, state_path=journal + '.source.json',
                    drop_enabled=automatic_drop, notify_enabled=automatic_notify,
                )
        if firewall_enabled:
            from provisioners.vyos import VyOSReconciler

            commit_proof = None
            if commit_recovery_enabled:
                from gateway_profiles.vyos_restart import commit_proof_from_config

                commit_proof = commit_proof_from_config(self.config)
            routing_ssh = None
            if routing_ssh_enabled and any(
                enabled and not self.config.has_option(section, 'fib_command')
                for enabled, section in ((wan_enabled, 'vyos_wan_failover'), (policy_route_enabled, 'vyos_policy_route'))
            ):
                from backends.vyos_failover import VyOSRoutingSSH

                routing_ssh = VyOSRoutingSSH.from_config(self.config)
            self.vyos_provisioner = VyOSReconciler.from_config(
                self.datacollector, self.config['vyos_firewall'],
                dhcp_settings=self.config['vyos_dhcp'] if dhcp_enabled else None,
                route_settings=self.config['vyos_static_routes'] if routes_enabled else None,
                dns_settings=self.config['vyos_dns'] if dns_enabled else None,
                nat_settings=self.config['vyos_source_nat'] if nat_enabled else None,
                wireguard_settings=self.config['vyos_wireguard'] if wireguard_enabled else None,
                port_forward_settings=self.config['vyos_port_forward'] if port_forward_enabled else None,
                vlan_settings=self.config['vyos_vlan'] if vlan_enabled else None,
                mdns_settings=self.config['vyos_mdns'] if mdns_enabled else None,
                ospf_settings=self.config['vyos_ospf'] if ospf_enabled else None,
                ipsec_settings=self.config['vyos_ipsec'] if ipsec_enabled else None,
                openvpn_settings=self.config['vyos_openvpn'] if openvpn_enabled else None,
                wan_settings=self.config['vyos_wan_failover'] if wan_enabled else None,
                policy_route_settings=self.config['vyos_policy_route'] if policy_route_enabled else None,
                qos_settings=self.config['vyos_qos'] if qos_enabled else None,
                stock_inspection_policy=stock_inspection_policy,
                inspection_controller=self.vyos_inspection if self._stock_inspection else None,
                commit_proof=commit_proof,
                routing_ssh=routing_ssh,
                shadow_interconnect=self._shadow_peer_probe.interface if shadow_writes else None,
                bgp_scope=bgp_scope,
            )
            if restart_enabled and not observe_standby:
                from gateway_profiles.vyos_restart import VyOSRestart

                self._vyos_restart = VyOSRestart.from_config(self.vyos_provisioner, self.config)
            if not observe_standby and self.config.remove_section('vyos_applied') and self._stock_inspection:
                # The event worker reads the saved acknowledgement independently.
                self._save_config()

    def _init_shadow_primary(self):
        from backends.vyos import VyOSReadError
        from provisioners.vyos_shadow_receipt import ShadowReceiptError

        try:
            runtime = self._build_shadow_primary()
        except (OSError, KeyError, ValueError, VyOSReadError, ShadowReceiptError) as error:
            logger.warning('Shadow Mode primary coordinator unavailable: %s', error)
            return
        if runtime is not None:
            self._shadow_prepare_primary = runtime.prepare
            self._shadow_forwarding_probe = runtime.verify_forwarding

    def _build_shadow_primary(self, *, preparing_admission=False):
        from pathlib import Path

        from gateway_profiles.vyos_shadow_runtime import ShadowPrimaryRuntime
        from gateway_profiles.vyos_install import load_enrolled_config

        if ((not preparing_admission and self._shadow_prepare_primary is not None)
                or not (self._shadow_provisioning_enabled() and self._shadow_observer_enabled())):
            raise ValueError('Shadow Mode primary runtime requires configured, authenticated provisioning')
        options = self.config['vyos_shadow_primary']
        site_path = Path(options['standby_enrollment'])
        state_path = Path(options['standby_state'])
        primary_state = Path(CONFIG_FILE)
        primary_enrollment = os.environ.get('UNIFI_GW_SITE_CONFIG')
        packaged_pair = self._shadow_credential_prefix == 'primary_'
        if (not site_path.is_absolute() or not state_path.is_absolute() or state_path.is_symlink()
                or state_path.parent.resolve() == primary_state.parent.resolve()
                or (not packaged_pair and primary_enrollment
                    and site_path.parent.resolve() == Path(primary_enrollment).parent.resolve())):
            raise ValueError('Shadow Mode requires a separate existing standby enrollment and state')
        try:
            config = load_enrolled_config(
                str(site_path), str(state_path), require_existing=True,
                credential_prefix='standby_' if packaged_pair else '',
            )
        except FileNotFoundError:
            if not preparing_admission and packaged_pair and not state_path.exists() and site_path.is_file():
                return
            raise
        if config.get('gateway', 'url') != self.config.get('gateway', 'url'):
            raise ValueError('Shadow Mode routers must use the same inform endpoint')
        if not preparing_admission and packaged_pair and not config.getboolean('gateway', 'is_adopted', fallback=False):
            return
        standby = UnifiGateway(_observer_config=config)
        standby._init_collector(observe_standby=True)
        if (not standby._shadow_provisioning_enabled()
                or not (preparing_admission or standby._shadow_observer_enabled())):
            raise ValueError('Shadow Mode requires authenticated provisioning on the standby')
        return ShadowPrimaryRuntime(
            self.config, self.datacollector.ports, self.vyos_provisioner, self._shadow_peer_probe,
            config, standby.datacollector.ports, standby.vyos_provisioner, standby._shadow_peer_probe,
            preparing_admission=preparing_admission,
        )

    def _build_shadow_advertiser(self):
        from pathlib import Path

        from gateway_profiles.vyos_shadow_runtime import ShadowPrimaryRuntime
        from gateway_profiles.vyos_install import load_enrolled_config

        section = 'vyos_shadow_primary'
        if self._shadow_credential_prefix == 'primary_':
            if self.config.getboolean(section, 'advertise_managed_shadow', fallback=False):
                if not self.config.getboolean(section, 'enabled', fallback=False):
                    raise ValueError('Shadow Mode advertisement requires the primary coordinator')
                return self._build_shadow_primary(preparing_admission=True)
            return None
        if self._shadow_credential_prefix != 'standby_':
            return None

        enrollment = Path(os.environ['UNIFI_GW_SITE_CONFIG'])
        state = Path(CONFIG_FILE)
        primary_state = state.parent.with_name('primary') / state.name
        if primary_state.is_symlink():
            raise ValueError('Shadow Mode primary state must use the canonical enrollment file')
        config = load_enrolled_config(
            str(enrollment.with_name('primary_site.conf')), str(primary_state),
            require_existing=True, credential_prefix='primary_',
        )
        if not config.getboolean(section, 'advertise_managed_shadow', fallback=False):
            return None
        if (not config.getboolean(section, 'enabled', fallback=False)
                or config.get('gateway', 'url') != self.config.get('gateway', 'url')
                or Path(config.get(section, 'standby_state')) != state):
            raise ValueError('Shadow Mode standby does not match the configured primary enrollment')
        primary = UnifiGateway(_observer_config=config)
        primary._init_collector(observe_standby=True)
        if not (primary._shadow_provisioning_enabled() and primary._shadow_observer_enabled()):
            raise ValueError('Shadow Mode standby advertisement needs the authenticated primary')
        return ShadowPrimaryRuntime(
            config, primary.datacollector.ports, primary.vyos_provisioner, primary._shadow_peer_probe,
            self.config, self.datacollector.ports, self.vyos_provisioner, self._shadow_peer_probe,
        )

    def _advertise_managed_shadow(self, document):
        from backends.vyos import VyOSReadError
        from provisioners.uxg_enterprise_shadow import SHADOW_SERVICE_VERSIONS
        from provisioners.vyos_shadow_receipt import ShadowReceiptError

        if (self._shadow_credential_prefix not in ('primary_', 'standby_')
                or not self._shadow_provisioning_enabled() or not isinstance(document.get('udapi_version'), dict)):
            return
        try:
            if self._shadow_advertiser is None:
                self._shadow_advertiser = self._build_shadow_advertiser()
            if self._shadow_advertiser is None:
                return
            self._shadow_advertiser.verify_capability(role=self._shadow_credential_prefix.removesuffix('_'))
        except (OSError, ValueError, KeyError, VyOSReadError, ShadowReceiptError) as error:
            logger.debug('Shadow Mode capability unavailable: %s', error)
            return
        document['usg2_caps'] = document.get('usg2_caps', 0) | 0x40000000
        document['udapi_version']['versionDetail'].update(SHADOW_SERVICE_VERSIONS)

    def _load_unhandled(self):
        try:
            with open(UNHANDLED_LOG, 'r') as f:
                return json.load(f)
        except (IOError, OSError, json.JSONDecodeError):
            return {}

    def _save_unhandled(self):
        try:
            _atomic_write(UNHANDLED_LOG,
                          lambda f: json.dump(self._unhandled, f, indent=2, sort_keys=True),
                          mode=0o600)
        except (IOError, OSError) as e:
            logger.warning('Failed to write unhandled log: %s', e)

    def _record_unhandled(self, category, key):
        key = _message_label(key)
        entry_key = '%s/%s' % (category, key)
        is_new = entry_key not in self._unhandled
        self._unhandled[entry_key] = {
            'category': category,
            'key': key,
            'last_seen': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
            'count': self._unhandled.get(entry_key, {}).get('count', 0) + 1,
        }
        self._save_unhandled()
        if is_new:
            logger.info(
                'New unhandled %s recorded: %s (see %s)',
                category, key, UNHANDLED_LOG,
            )

    def run(self):
        self._init_collector()
        signal.signal(signal.SIGTERM, self._handle_signal)
        signal.signal(signal.SIGINT, self._handle_signal)

        broadcast_index = 1
        while self.running and not self.config.getboolean('gateway', 'is_adopted'):
            inform_url = self.config.get('gateway', 'url', fallback='')
            if inform_url:
                try:
                    self._handle_adoption(self._send_inform(create_inform(self.config, self.datacollector)))
                except Exception as error:
                    logger.error('UXG adoption poll failed: %s', error, exc_info=True)
                if self.config.getboolean('gateway', 'is_adopted') or not self.running:
                    break
            if not self.config.getboolean('global', 'disable_broadcast'):
                self._send_broadcast(broadcast_index)
                broadcast_index += 1
            elif not inform_url:
                logger.critical(
                    'Configure a controller inform URL or enable discovery'
                )
                return
            self._stop.wait(self.interval)

        if not self.running:
            logger.info('Shutting down before adoption')
            return

        logger.info(
            'Device adopted, starting inform loop (interval=%ds)', self.interval
        )

        event_thread = None
        if self._security_event_worker is not None:
            event_thread = threading.Thread(target=self._security_event_worker.run, args=(self._stop,),
                                            name='unifi-security-events', daemon=True)
            event_thread.start()
        while self.running:
            try:
                if (self._shadow_prepare_primary is None
                        and self.config.getboolean('vyos_shadow_primary', 'enabled', fallback=False)):
                    self._init_shadow_primary()
                if self._vyos_restart is not None and not self._vyos_restart.ready_for_inform():
                    self._stop.wait(self.interval)
                    continue
                self._check_inspection()
                self.datacollector.update()
                self._update_ipsec_status()
                self._update_openvpn_status()
                self._update_wan_failover_status()
                self._exchange_inform()
                self._wait_for_next_inform()
            except Exception as e:
                logger.error('Error in inform loop: %s', e, exc_info=True)
                self.interval = min(self.interval * 2, 60)
                self._stop.wait(self.interval)

        if event_thread is not None:
            self._stop.set()
            event_thread.join(timeout=2)
        logger.info('Shutting down gracefully')

    def _exchange_inform(self):
        pending = self._speedtest_reports[0] if self._speedtest_reports else None
        report = pending or self._speedtest_completed
        if report is not None:
            stage, measurement = report
            self.datacollector.data['uxg_speedtest'] = measurement
            self.datacollector.data['uxg_speedtest_stage'] = stage
        try:
            payload = create_inform(self.config, self.datacollector)
        finally:
            if report is not None:
                self.datacollector.data.pop('uxg_speedtest')
                self.datacollector.data.pop('uxg_speedtest_stage')
        authenticated_shadow = self._shadow_observer_enabled()
        reversed_pair = False
        if authenticated_shadow:
            from backends.vyos import VyOSReadError
            from gateway_profiles.vyos_vrrp import observe_shadow_role
            from provisioners.vyos_shadow_handoff import verify_primary_inform
            from provisioners.vyos_shadow_receipt import ShadowReceiptError
            from provisioners.vyos_shadow_standby import ShadowStandbyPending

            document = json.loads(payload)
            self._advertise_managed_shadow(document)
            shadow_revision = None
            try:
                is_standby = self._shadow_credential_prefix == 'standby_'
                if is_standby and self._shadow_advertiser is not None:
                    self._shadow_advertiser.poll_standby_release()
                state = observe_shadow_role(self.datacollector.backend)
                paired_role = (state in ('master', 'backup')
                               and self._shadow_credential_prefix in ('primary_', 'standby_'))
                if paired_role and self._shadow_provisioning_enabled():
                    if self._shadow_advertiser is None:
                        self._shadow_advertiser = self._build_shadow_advertiser()
                    if self._shadow_advertiser is None:
                        state = 'unknown'
                    else:
                        shadow_revision = self._shadow_advertiser.verify_pair_inform(role=state, is_standby=is_standby)
                        reversed_pair = state == ('master' if is_standby else 'backup')
                elif state in ('master', 'backup') and self._shadow_provisioning_enabled():
                    with self.vyos_provisioner.locked_state() as journal:
                        handoff = journal.get(SHADOW_HANDOFF)
                        if state == 'master' and handoff is not None and handoff.get('phase') == 'primary_active':
                            shadow_revision = verify_primary_inform(
                                handoff, self._shadow_peer_probe.receipt_client(), self.datacollector.backend,
                                self.vyos_provisioner.commit_proof,
                            )
                        else:
                            state = 'unknown'
            except (OSError, KeyError, ValueError, VyOSReadError, ShadowReceiptError, ShadowStandbyPending) as error:
                logger.debug('Shadow Mode role unavailable: %s', error)
                state = 'unknown'
            document['vrrp'] = {'state': state}
            if shadow_revision is not None:
                document.update(cfgversion=shadow_revision, cfgversion_effective=shadow_revision)
            payload = json.dumps(document)
        response = self._send_inform(payload)
        logger.debug('Received %s from controller', _message_label(response.get('_type')))
        if self._vyos_restart is not None:
            self._vyos_restart.accept_response(response.get('_type'), response.get('server_time_in_utc'))
        if pending is not None and response.get('_type') not in ('httperror', 'urlerror'):
            self._speedtest_reports.popleft()
            if pending[0] == 'complete':
                self._speedtest_completed = pending
        if authenticated_shadow and response.get('_type') == 'setparam' and self._shadow_provisioning_enabled():
            from backends.vyos import VyOSReadError, VyOSWriteError
            from provisioners.vyos_shadow_handoff import ShadowPrimaryPending
            from provisioners.vyos_shadow_receipt import ShadowReceiptError
            from provisioners.vyos_shadow_standby import ShadowStandbyPending

            try:
                if reversed_pair:
                    self._shadow_advertiser.verify_pair_inform(role=state, is_standby=is_standby, replay=response)
                if (reversed_pair or self._dispatch_shadow_standby_complete(response) or self._verify_shadow_complete_retry(response)
                        or self._dispatch_shadow_primary_complete(response)):
                    interval = response.get('interval')
                    if type(interval) is int and interval > 0:
                        self.interval = interval
                    if (not reversed_pair or self._vyos_provisioning_error is None
                            or self._vyos_provisioning_error[0] == response.get('cfgversion')):
                        self._vyos_provisioning_error = None
                    return
            except (ShadowPrimaryPending, ShadowStandbyPending):
                return
            except (OSError, ValueError, VyOSReadError, VyOSWriteError, ShadowReceiptError) as error:
                self._reject_vyos_provisioning(response.get('cfgversion'), error)
                return
        self._handle_response(response)

    def _dispatch_shadow_standby_complete(self, response):
        from provisioners.uxg_enterprise_shadow_tunnel import requests_shadow_completion

        if self._shadow_credential_prefix != 'standby_' or not requests_shadow_completion(response.get('system_cfg')):
            return False
        if self._shadow_advertiser is None:
            self._shadow_advertiser = self._build_shadow_advertiser()
        if self._shadow_advertiser is None:
            raise ValueError('Shadow Mode standby COMPLETE requires the installed pair coordinator')
        ordinary = self.config.get('vyos_firewall', 'unmanaged_baseline_sha256', fallback='')
        baseline = self.config.get('vyos_shadow', 'complete_unmanaged_baseline_sha256', fallback=ordinary).lower()
        if not baseline:
            raise ValueError('Shadow Mode standby COMPLETE requires the approved controller baseline')
        observation = (self._shadow_peer_probe.management_identity(), response)
        try:
            self._shadow_advertiser.advance_standby_response(
                observation, decode_policy=self._decode_vyos_policy, approved_outside_scope=baseline,
            )
        except (KeyError, TypeError) as error:
            raise ValueError('Shadow Mode standby COMPLETE contains invalid policy fields') from error
        return True

    def _verify_shadow_complete_retry(self, response):
        from provisioners.vyos_shadow_handoff import verify_primary_inform
        from provisioners.uxg_enterprise_shadow_tunnel import complete_snapshot_fingerprint

        with self.vyos_provisioner.locked_state() as journal:
            record = journal.get(SHADOW_HANDOFF)
            if (record is None or record.get('phase') != 'primary_active'
                    or record.get('controller_revision') != response.get('cfgversion')):
                return False
            expected = record.get('complete_snapshot_sha256')
            if expected is None or complete_snapshot_fingerprint(response.get('system_cfg')) != expected:
                raise ValueError('Shadow Mode COMPLETE retry does not match the verified snapshot')
            verify_primary_inform(record, self._shadow_peer_probe.receipt_client(), self.datacollector.backend,
                                  self.vyos_provisioner.commit_proof)
            return True

    def _dispatch_shadow_primary_complete(self, response):
        from provisioners.vyos_shadow_handoff import ShadowPrimaryPending
        from provisioners.uxg_enterprise_shadow_tunnel import requests_shadow_completion

        if (self._shadow_prepare_primary is None
                and not self.config.getboolean('vyos_shadow_primary', 'enabled', fallback=False)):
            return False
        if not requests_shadow_completion(response.get('system_cfg')):
            return False
        if self._shadow_prepare_primary is None:
            raise ShadowPrimaryPending('Shadow Mode COMPLETE is waiting for the primary coordinator')
        phase_one_revision = self._verify_shadow_complete_policy(response['system_cfg'])
        observation = (self._shadow_peer_probe.management_identity(), response)
        transfer = self._shadow_prepare_primary(observation)
        transfer.advance_authenticated_complete(
            observation, verify_forwarding=self._shadow_forwarding_probe, phase_one_revision=phase_one_revision,
        )
        return True

    def _verify_shadow_complete_policy(self, system_cfg):
        from provisioners.uxg_enterprise_shadow_tunnel import primary_shadow_policy_fingerprint

        section = 'vyos_shadow_applied'
        expected = self.config.get(section, 'primary_policy_sha256', fallback='')
        revision = self.config.get(section, 'primary_policy_revision', fallback='')
        reference = json.loads(self.config.get(section, 'reference', fallback='null'))
        preimage = reference.get('lan_preimage') if isinstance(reference, dict) else None
        ordinary = preimage.get('addresses') if isinstance(preimage, dict) else None
        if not (expected and revision and ordinary):
            raise ValueError('Shadow Mode COMPLETE requires a verified phase-one policy')
        if primary_shadow_policy_fingerprint(system_cfg, ordinary, complete=True) != expected:
            raise ValueError('Shadow Mode COMPLETE changed policy outside the handoff')
        return revision

    def _wait_for_next_inform(self):
        deadline = time.monotonic() + self.interval
        while self.running:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return
            if not self._speedtest_reports and not self._speedtest_running():
                self._stop.wait(remaining)
                return
            if self._stop.wait(min(1, remaining)):
                return
            if self._speedtest_reports:
                # Report fresh measurements without waiting for another router telemetry poll.
                self._exchange_inform()

    def _handle_signal(self, signum, frame):
        logger.info('Received signal %d, shutting down', signum)
        self.running = False
        self._stop.set()

    def _handle_response(self, response):
        resp_type = response.get('_type', '')

        if resp_type == 'noop':
            self.interval = response.get('interval', self.interval)

        elif resp_type == 'setparam':
            HANDLED_SETPARAM_KEYS = {
                '_type', 'server_time_in_utc', 'blocked_sta', 'mgmt_cfg',
            }
            if self.vyos_provisioner is not None:
                HANDLED_SETPARAM_KEYS = HANDLED_SETPARAM_KEYS | {'cfgversion', 'system_cfg', 'interval'}
                interval = response.get('interval')
                if type(interval) is int and interval > 0:
                    self.interval = interval
            for key, value in response.items():
                if key == 'mgmt_cfg':
                    self._update_enrollment(self._parse_mgmt_cfg, value)
                if key not in ('_type', 'server_time_in_utc', 'blocked_sta'):
                    self.config.set('provisioned', key, str(value))
                if key not in HANDLED_SETPARAM_KEYS:
                    self._record_unhandled('setparam', key)
            if self.vyos_provisioner is not None and ('cfgversion' in response or 'system_cfg' in response):
                self._apply_vyos_policy(response)
            self._save_config()

        elif resp_type == 'reboot':
            if self._vyos_restart is None:
                logger.info('Received reboot request from controller (ignored)')
            elif not self.config.getboolean('gateway', 'use_aes_gcm', fallback=False):
                logger.warning('Declined VyOS restart without authenticated AES-GCM')
            elif response.get('reboot_type', 'soft') != 'soft':
                logger.warning('Declined unsupported VyOS restart type')
            elif self._speedtest_reports or self._speedtest_running():
                logger.warning('Declined VyOS restart during an active WAN speed test')
            else:
                from backends.vyos import VyOSReadError, VyOSWriteError

                try:
                    self._vyos_restart.request(response.get('server_time_in_utc'))
                except VyOSWriteError as error:
                    logger.warning('VyOS restart response was unconfirmed. Awaiting recovery: %s', error)
                except (OSError, ValueError, VyOSReadError) as error:
                    logger.warning('VyOS restart refused: %s', error)

        elif resp_type == 'cmd':
            self._handle_cmd(response)

        elif resp_type == 'upgrade':
            logger.warning('Controller firmware installation is unsupported on VyOS')

        elif resp_type == 'setdefault':
            self._update_enrollment(self._reset_enrollment)

        elif resp_type == 'httperror':
            logger.warning(
                'HTTP error from controller: %s %s',
                response.get('code'), response.get('msg'),
            )

        elif resp_type == 'urlerror':
            logger.error(
                'Connection error to controller, retry in 60s: %s',
                response.get('msg'),
            )
            self.interval = 60

        else:
            logger.warning('Unhandled response type: %s', _message_label(resp_type))
            self._record_unhandled('response', resp_type)

    def _handle_cmd(self, response):
        cmd = response.get('cmd', '')
        label = _message_label(cmd)
        logger.info('Received command: %s', label)

        if cmd == 'speed-test':
            self._start_wan_speedtest()
        elif cmd == 'set-locate':
            self.config.set('gateway', 'locating', 'True')
            logger.info('Locate mode enabled')
        elif cmd == 'unset-locate':
            self.config.set('gateway', 'locating', 'False')
            logger.info('Locate mode disabled')
        elif (cmd == 'get-udapi-blocks'
              and self.config.get('gateway', 'platform', fallback='').strip().lower() == 'vyos'
              and self.config.getboolean('gateway', 'is_adopted', fallback=False)):
            self._handle_route_query(response)
        elif cmd == 'shadow-mode-adopt' and self._shadow_observer_enabled():
            self._handle_shadow_status(response)
        else:
            logger.warning('Unknown command: %s', label)
            self._record_unhandled('command', cmd)

    def _shadow_provisioning_enabled(self):
        return (self.config.getboolean('vyos_shadow', 'provisioning_enabled', fallback=False)
                and self.vyos_provisioner is not None)

    def _update_enrollment(self, update, *args):
        if not self._shadow_provisioning_enabled():
            update(*args)
            return
        try:
            with self.vyos_provisioner.locked_state() as journal:
                if SHADOW_HANDOFF in journal:
                    logger.warning('Controller enrollment change deferred during Shadow Mode recovery')
                    return
                update(*args)
        except (OSError, ValueError) as error:
            logger.warning('Controller enrollment change could not be applied: %s', error)

    def _reset_enrollment(self):
        logger.critical('Controller requested device reset')
        self.config.set('gateway', 'is_adopted', 'False')
        self.config.remove_option('gateway', 'key')
        self.config.set('gateway', 'use_aes_gcm', 'False')
        self._save_config()
        self.running = False

    def _shadow_observer_enabled(self):
        return (self._shadow_peer_probe is not None
                and self.config.get('gateway', 'device', fallback='') == 'UXGENT'
                and self.config.get('gateway', 'platform', fallback='').strip().lower() == 'vyos'
                and self.config.getboolean('gateway', 'is_adopted', fallback=False)
                and self.config.getboolean('gateway', 'use_aes_gcm', fallback=False))

    def _handle_shadow_status(self, response):
        from backends.vyos import VyOSReadError
        from gateway_profiles.uxg_enterprise_shadow import decode_shadow_status_request, shadow_status_notification
        from provisioners.uxg_enterprise_shadow import SHADOW_ADDRESSES

        try:
            request_id, is_secondary = decode_shadow_status_request(response)
        except ValueError as error:
            logger.warning('Declined Shadow Mode command: %s', error)
            return
        try:
            reachable = False
            if (not self.config.getboolean('vyos_shadow', 'provisioning_enabled', fallback=False)
                    or (self.config.has_option('vyos_applied', 'cfgversion')
                        and self.config.get('vyos_shadow_applied', 'address', fallback='') == SHADOW_ADDRESSES[is_secondary])):
                reachable = self._shadow_peer_probe.reachable(is_secondary=is_secondary)
        except VyOSReadError as error:
            logger.warning('Shadow Mode peer probe unavailable: %s', error)
            reachable = False
        payload = json.loads(create_inform(self.config, self.datacollector))
        payload.update(shadow_status_notification(request_id, reachable))
        try:
            reply = self._send_inform(json.dumps(payload))
        except (OSError, ValueError) as error:
            logger.warning('Could not send the Shadow Mode status reply: %s', error)
            return
        if reply.get('_type') in ('httperror', 'urlerror'):
            logger.warning('Could not send the Shadow Mode status reply')

    def _reports_ospf_routes(self):
        return (self.vyos_provisioner is not None and self.vyos_provisioner.ospf_scope is not None
                and self.config.getboolean('vyos_ospf', 'report_routes', fallback=False))

    def _handle_route_query(self, response):
        from backends.vyos import VyOSReadError
        from gateway_profiles.uxg_route_queries import (
            RouteQueryError, build_route_query_notification, decode_route_query, project_ospf_neighbors,
        )

        try:
            query = decode_route_query(response)
            if query.block_id == 'get-routes':
                rows = self._live_route_items()
            else:
                if not self._reports_ospf_routes():
                    raise RouteQueryError('OSPF neighbor reporting is disabled')
                rows = project_ospf_neighbors(self.datacollector.backend.show_ipv4_ospf_neighbors(),
                                              scope=self.vyos_provisioner.ospf_scope)
            payload = json.loads(create_inform(self.config, self.datacollector))
            payload.update(build_route_query_notification(query, rows))
            reply = self._send_inform(json.dumps(payload))
            if reply.get('_type') in ('httperror', 'urlerror'):
                logger.warning('Could not send the verified route query reply')
        except (OSError, ValueError, VyOSReadError) as error:
            logger.warning('Could not answer the route query: %s', error)

    def _live_route_items(self):
        from backends.vyos import VyOSReadError
        from gateway_profiles.uxg_route_queries import (
            FIRST_UNIFI_NETWORK_TABLE, RouteQueryError, project_installed_routes, project_ospf_routes,
            project_static_routes,
        )

        backend = self.datacollector.backend
        names_by_link = {}
        for port in self.datacollector.ports:
            names_by_link.setdefault(port['realif'], set()).add(port['ifname'])
        interfaces = {link: next(iter(names)) for link, names in names_by_link.items() if len(names) == 1}
        static_scope = self.vyos_provisioner.route_scope if self.vyos_provisioner is not None else None
        managed_prefixes = frozenset(static_scope.destinations) if static_scope is not None else frozenset()
        snapshots = {}
        rows = []
        incomplete = False

        def read_routes(version):
            nonlocal incomplete
            if version not in snapshots:
                read = backend.show_ipv4_routes if version == 4 else backend.show_ipv6_routes
                try:
                    snapshots[version] = read()
                except VyOSReadError as error:
                    logger.warning('Could not read IPv%d routes for the live routing view: %s', version, error)
                    snapshots[version] = None
                    incomplete = True
            return snapshots[version]

        for version in (4, 6):
            if (snapshot := read_routes(version)) is not None:
                try:
                    rows.extend(project_installed_routes(snapshot, version=version, interfaces=interfaces,
                                                        managed_prefixes=managed_prefixes, include_bgp=True))
                except RouteQueryError as error:
                    incomplete = True
                    logger.warning('Could not project live IPv%d installed routes: %s', version, error)
        if self._reports_ospf_routes() and (snapshot := read_routes(4)) is not None:
            try:
                rows.extend(project_ospf_routes(snapshot, scope=self.vyos_provisioner.ospf_scope))
            except RouteQueryError as error:
                incomplete = True
                logger.warning('Could not project live OSPF routes: %s', error)
        if static_scope is not None:
            try:
                owned, identities = self.vyos_provisioner.read_verified_static_route_state()
            except (OSError, ValueError, VyOSReadError) as error:
                incomplete = True
                logger.warning('Could not verify static route ownership for the live routing view: %s', error)
            else:
                for version in (4, 6):
                    paths = {prefix: tree for prefix, tree in owned.items() if (':' in prefix) == (version == 6)}
                    if paths and (snapshot := read_routes(version)) is not None:
                        try:
                            rows.extend(project_static_routes(snapshot, owned=paths, identities=identities,
                                                             interfaces=interfaces))
                        except RouteQueryError as error:
                            incomplete = True
                            logger.warning('Could not project live IPv%d static routes: %s', version, error)
        try:
            tables = backend.configured_static_route_tables()
        except VyOSReadError as error:
            incomplete = True
            logger.warning('Could not read configured VyOS static route tables: %s', error)
        else:
            for table, families in sorted(tables.items()):
                if table >= FIRST_UNIFI_NETWORK_TABLE:
                    continue
                for version in families:
                    try:
                        snapshot = backend.show_static_route_table(table, version=version)
                        rows.extend(project_installed_routes(snapshot, version=version, table=table, interfaces=interfaces))
                    except (VyOSReadError, RouteQueryError) as error:
                        incomplete = True
                        logger.warning('Could not report live IPv%d routes from table %d: %s', version, table, error)
        if not rows and incomplete:
            raise RouteQueryError('No verified live route snapshot is available')
        return rows

    def _start_wan_speedtest(self):
        if self._wan_speedtest is None:
            logger.warning('Configure a WAN measurement command to run a speed test from UniFi Network')
            self._record_unhandled('command', 'speed-test')
            return
        if self._speedtest_running() or self._speedtest_reports:
            return
        self._speedtest_completed = None
        self._speedtest_thread = threading.Thread(target=self._measure_wan_speedtest,
                                                  name='unifi-wan-speedtest', daemon=True)
        self._speedtest_thread.start()

    def _speedtest_running(self):
        return self._speedtest_thread is not None and self._speedtest_thread.is_alive()

    def _measure_wan_speedtest(self):
        from gateway_profiles.uxg_speedtest import SpeedTestError

        ran_at = int(time.time())
        streamed = False

        def progress(phase, measurement):
            nonlocal ran_at, streamed
            ran_at = measurement['lastrun']
            streamed = True
            self._speedtest_reports.append((phase, measurement))

        try:
            result = self._wan_speedtest.measure(on_progress=progress)
            if not streamed:
                self._speedtest_reports.extend([('download', result), ('upload', result)])
            self._speedtest_reports.append(('complete', result))
            logger.info('WAN speed test completed')
        except SpeedTestError as error:
            self._speedtest_reports.append(('failed', {'lastrun': ran_at}))
            logger.warning('WAN speed test failed: %s', error)

    def _send_broadcast(self, broadcast_index):
        source = self.config.get('global', 'discovery_source_ipv4', fallback='').strip()
        uptime = self.datacollector.data.get('uptime') if self.datacollector is not None else None
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                if source:
                    address = socket.inet_pton(socket.AF_INET, source)
                    sock.bind((source, 0))
                    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, address)
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 1)
                sock.sendto(
                    create_broadcast_message(self.config, broadcast_index, router_uptime=uptime),
                    ('233.89.188.1', 10001),
                )
            logger.debug(
                'Sent discovery #%d via %s',
                broadcast_index, source or 'the default multicast interface',
            )
        except Exception as e:
            logger.error('Failed to send discovery via %s: %s', source or 'the default multicast interface', e)

    def _handle_adoption(self, response):
        if response['_type'] == 'httperror':
            if str(response['code']) == '404':
                return
            if str(response['code']) == '400':
                logger.error(
                    'Authentication failed -- wrong authkey or '
                    'device removed from controller?'
                )
                return
            logger.error(
                'HTTP error from controller: %s %s',
                response['code'], response['msg'],
            )
            return

        if response['_type'] == 'urlerror':
            logger.error(
                'Connection error to controller: %s', response['msg']
            )
            return

        if response['_type'] == 'setparam':
            if not self.config.getboolean('gateway', 'is_adopted'):
                if not self._has_native_adoption_key(response.get('mgmt_cfg', '')):
                    logger.warning('UXG adoption response lacks an unambiguous device key')
                    return
                logger.info('setparam received, device now adopted')
                self.config.set('gateway', 'is_adopted', 'True')

            self._handle_response(response)

    def _has_native_adoption_key(self, management):
        if not isinstance(management, str):
            return False
        keys = [line.removeprefix('authkey=') for line in management.splitlines() if line.startswith('authkey=')]
        if not keys:
            keys = [self.config.get('gateway', 'key', fallback='')]
        return len(keys) == 1 and re.fullmatch(r'[0-9A-Fa-f]{32}', keys[0]) is not None

    def _decode_vyos_policy(self, system_cfg, revision):
        from provisioners.vyos_bgp import BgpScope, normalize_bgp_policy
        from provisioners.vyos import (
            OpenVpnDesired, normalize_ipsec_policy, normalize_ospf_policy, normalize_scoped_policy,
            unmanaged_config_fingerprint,
        )
        from provisioners.vyos_dhcp import decode_dhcp_intent
        from provisioners.vyos_dns import decode_dns_intent
        from provisioners.uxg_intent import decode_firewall_intent
        from provisioners.vyos_mdns import normalize_mdns_service_version
        from provisioners.vyos_nat import decode_nat_intent
        from provisioners.uxg_openvpn_policy import normalize_openvpn_payload
        from provisioners.uxg_pbr import normalize_policy_route
        from provisioners.uxg_qos import normalize_qos_policy
        from provisioners.vyos_routes import decode_route_intent
        from provisioners.uxg_wan_failover_policy import normalize_wan_failover_policy
        from provisioners.vyos_wireguard import decode_wireguard_intent

        bgp_intent = None
        if isinstance(getattr(self.vyos_provisioner, 'bgp_scope', None), BgpScope):
            if not (self.config.getboolean('gateway', 'is_adopted', fallback=False)
                    and self.config.getboolean('gateway', 'use_aes_gcm', fallback=False)):
                raise ValueError('Managed BGP requires authenticated Enterprise inform')
            system_cfg, bgp_intent = normalize_bgp_policy(system_cfg, revision=revision)
        inspection = None
        if self.vyos_inspection is not None:
            system_cfg, inspection = self.vyos_inspection.normalize(system_cfg)
        qos_intent = None
        if self.vyos_provisioner.qos_kernel_command is not None:
            system_cfg, qos_intent = normalize_qos_policy(system_cfg, revision=revision)
        openvpn_intent = None
        if self.vyos_provisioner.openvpn_scope is not None:
            system_cfg, client = normalize_openvpn_payload(
                system_cfg, server_name=self.vyos_provisioner.openvpn_scope.server_name,
            )
            openvpn_intent = OpenVpnDesired(revision, client)
        policy_route_intent = None
        if self.vyos_provisioner.policy_route_fib_command is not None:
            system_cfg, policy_route_intent = normalize_policy_route(system_cfg, revision=revision)
        wan_intent = None
        if self.vyos_provisioner.wan_fib_command is not None:
            system_cfg, wan_intent = normalize_wan_failover_policy(system_cfg, revision=revision)
        message_broker = self.controller_broker_trust is not None
        dns_scope = self.vyos_provisioner.dns_scope
        nat_scope = self.vyos_provisioner.nat_scope
        wireguard_scope = self.vyos_provisioner.wireguard_scope
        port_forward_scope = self.vyos_provisioner.port_forward_scope
        vlan_scope = self.vyos_provisioner.vlan_scope
        mdns_scope = self.vyos_provisioner.mdns_scope
        ospf_scope = self.vyos_provisioner.ospf_scope
        ipsec_scope = self.vyos_provisioner.ipsec_scope
        schema = {'message_broker': message_broker, 'dns_forwarder': dns_scope is not None,
                  'nat': nat_scope is not None or port_forward_scope is not None, 'wireguard': wireguard_scope is not None}
        common_cfg = normalize_mdns_service_version(system_cfg) if mdns_scope is not None else system_cfg
        base_cfg, ospf_intent = normalize_ospf_policy(common_cfg, revision=revision, schema=schema, scope=ospf_scope)
        base_cfg, ipsec_intent = normalize_ipsec_policy(base_cfg, revision=revision, schema=schema, scope=ipsec_scope)
        intent = decode_firewall_intent(base_cfg, revision=revision, **schema)
        policy_cfg, vlan_intent, port_forward_intent, mdns_intent = normalize_scoped_policy(
            base_cfg, revision=revision, schema=schema, port_forward_scope=port_forward_scope, vlan_scope=vlan_scope,
            mdns_scope=mdns_scope,
        )
        dhcp_scope = self.vyos_provisioner.dhcp_scope
        dhcp_intent = decode_dhcp_intent(base_cfg, revision=revision, scope=dhcp_scope) if dhcp_scope else None
        route_scope = self.vyos_provisioner.route_scope
        route_intent = None
        if route_scope is not None:
            route_intent = decode_route_intent(
                base_cfg, revision=revision, scope=route_scope, **schema,
            )
        dns_intent = None
        if dns_scope is not None:
            dns_intent = decode_dns_intent(
                policy_cfg, revision=revision, scope=dns_scope,
                message_broker=message_broker, nat=schema['nat'], wireguard=schema['wireguard'],
                dhcp_domain=dhcp_intent.server.domain if dhcp_intent and dhcp_intent.server else None,
            )
        nat_intent = None
        if nat_scope is not None:
            nat_intent = decode_nat_intent(
                policy_cfg, revision=revision, scope=nat_scope,
                message_broker=message_broker, dns_forwarder=dns_scope is not None,
                wireguard=wireguard_scope is not None,
            )
        wireguard_intent = None
        if wireguard_scope is not None:
            wireguard_intent = decode_wireguard_intent(
                base_cfg, revision=revision, scope=wireguard_scope, message_broker=message_broker,
                dns_forwarder=dns_scope is not None, nat=schema['nat'],
            )
        observed = unmanaged_config_fingerprint(
            system_cfg, revision=revision, dhcp_scope=dhcp_scope, broker_trust=self.controller_broker_trust,
            route_scope=route_scope, dns_scope=dns_scope, nat_scope=nat_scope,
            wireguard_scope=wireguard_scope, port_forward_scope=port_forward_scope, vlan_scope=vlan_scope,
            mdns_scope=mdns_scope, ospf_scope=ospf_scope, ipsec_scope=ipsec_scope,
        )
        options = {
            'dhcp_intent': dhcp_intent, 'route_intent': route_intent, 'dns_intent': dns_intent,
            'nat_intent': nat_intent, 'wireguard_intent': wireguard_intent,
            'port_forward_intent': port_forward_intent, 'vlan_intent': vlan_intent, 'mdns_intent': mdns_intent,
            'ospf_intent': ospf_intent, 'ipsec_intent': ipsec_intent, 'openvpn_intent': openvpn_intent,
            'wan_intent': wan_intent, 'policy_route_intent': policy_route_intent, 'qos_intent': qos_intent,
            'inspection_intent': inspection if self._stock_inspection else None,
        }
        if bgp_intent is not None:
            options['bgp_intent'] = bgp_intent
        return intent, options, inspection, observed

    def _apply_vyos_policy(self, response):
        from inspection.controller import InspectionControlError
        from provisioners.uxg_enterprise_shadow import SHADOW_ADDRESSES, normalize_shadow_interconnect
        from provisioners.uxg_enterprise_shadow_tunnel import primary_shadow_policy_fingerprint

        revision = response.get('cfgversion')
        system_cfg = response.get('system_cfg')
        try:
            shadow_address = None
            shadow_reference = None
            shadow_policy = None
            shadow_role = None
            shadow_enabled = self.config.getboolean('vyos_shadow', 'provisioning_enabled', fallback=False)
            if shadow_enabled:
                if not self._shadow_observer_enabled():
                    raise ValueError('Shadow Mode interconnect provisioning requires authenticated Enterprise inform')
                reference = json.loads(self.config.get('vyos_shadow_applied', 'reference', fallback='null'))
                raw_snapshot = system_cfg
                system_cfg, shadow_address, shadow_reference = normalize_shadow_interconnect(system_cfg, reference)
                if shadow_address in SHADOW_ADDRESSES:
                    shadow_role = 'primary' if shadow_address == SHADOW_ADDRESSES[0] else 'standby'
                    preimage = reference.get('lan_preimage')
                    ordinary = preimage.get('addresses') if isinstance(preimage, dict) else None
                    if ordinary:
                        shadow_policy = primary_shadow_policy_fingerprint(raw_snapshot, ordinary, complete=False)
            intent, options, inspection, observed = self._decode_vyos_policy(system_cfg, revision)
            ipsec_intent, openvpn_intent = options['ipsec_intent'], options['openvpn_intent']
            baseline = self.config.get('vyos_firewall', 'unmanaged_baseline_sha256', fallback='')
            if not baseline:
                raise ValueError(f'Approve the controller baseline before enabling writes: {observed}')
            if observed != baseline.lower():
                raise ValueError('Controller configuration outside the managed VyOS scopes differs from the approved baseline')
            transitioning = inspection is not None and inspection != self._verified_inspection
            verify_unchanged = None
            if inspection is not None and not self._stock_inspection:
                try:
                    self.vyos_inspection.verify(inspection)
                except InspectionControlError:
                    if not transitioning:
                        raise
                    verify_unchanged = partial(self.vyos_inspection.apply, inspection)
            result = self.vyos_provisioner.reconcile(
                intent, **options, verify_unchanged=verify_unchanged, shadow_interconnect_address=shadow_address,
            )
            if result.error:
                raise ValueError(result.error)
            if transitioning:
                self._verified_inspection = inspection
                logger.info('Verified native inspection mode: %s', inspection.mode)
            if inspection is not None:
                self._inspection_check_at = time.monotonic() + 30
        except (KeyError, TypeError, ValueError) as error:
            self._reject_vyos_provisioning(revision, error)
            return

        self._vyos_provisioning_error = None
        if ipsec_intent is not None:
            peer = replace(ipsec_intent.peer, _secret="") if ipsec_intent.peer is not None else None
            self._verified_ipsec = replace(ipsec_intent, peer=peer)
        if openvpn_intent is not None:
            client = openvpn_intent.client
            self._verified_openvpn = (revision, client.native_id) if client is not None else None
        if not self.config.has_section('vyos_applied'):
            self.config.add_section('vyos_applied')
        self.config.set('vyos_applied', 'cfgversion', result.verified_revision)
        if shadow_enabled and result.verified_revision == revision:
            section = 'vyos_shadow_applied'
            if not self.config.has_section(section):
                self.config.add_section(section)
            self.config.set(section, 'address', shadow_address or '')
            for role in ('primary', 'standby'):
                if shadow_policy is not None and shadow_role == role:
                    self.config.set(section, f'{role}_policy_sha256', shadow_policy)
                    self.config.set(section, f'{role}_policy_revision', revision)
                else:
                    self.config.remove_option(section, f'{role}_policy_sha256')
                    self.config.remove_option(section, f'{role}_policy_revision')
            if shadow_reference is not None:
                if 'lan_preimage' in shadow_reference:
                    shadow_reference['lan_preimage']['cfgversion'] = revision
                self.config.set(section, 'reference', json.dumps(shadow_reference, separators=(',', ':')))
        if self._security_event_worker is not None and result.verified_revision == revision:
            normalized = _redact_native_system_cfg(response.get('system_cfg'))
            if normalized is not None:
                self.config.set('vyos_applied', 'system_cfg_sha256', sha256(normalized.strip().encode()).hexdigest())
        if result.changed:
            logger.info('Verified and saved the managed VyOS configuration')

    def _update_ipsec_status(self):
        intent = self._verified_ipsec
        if intent is None:
            return
        from backends.vyos import VyOSReadError
        from gateway_profiles.vyos_ipsec_status import IpsecStatusError, project_ipsec_status

        data = self.datacollector.data
        data.pop('ipsec_status', None)
        revision = self.config.get('vyos_applied', 'cfgversion', fallback=None)
        if revision != intent.revision:
            return
        try:
            backend = self.datacollector.backend
            connections = backend.show_ipsec_connections() if intent.peer is not None else None
            sas = backend.show_ipsec_sas() if intent.peer is not None else None
            data['ipsec_status'] = project_ipsec_status(
                intent, applied_revision=revision, connections=connections, sas=sas,
            )
        except (IpsecStatusError, VyOSReadError) as error:
            logger.debug('IPsec telemetry unavailable: %s', error)

    def _update_openvpn_status(self):
        if self._verified_openvpn is None:
            return
        from backends.vyos import VyOSReadError
        from gateway_profiles.vyos_openvpn_status import project_openvpn_status

        data = self.datacollector.data
        data.pop('openvpn_status', None)
        revision, native_id = self._verified_openvpn
        if self.config.get('vyos_applied', 'cfgversion', fallback=None) != revision:
            return
        try:
            data['openvpn_status'] = project_openvpn_status(
                native_id, self.vyos_provisioner.openvpn_scope, self.datacollector.backend,
            )
        except (ValueError, VyOSReadError) as error:
            logger.debug('OpenVPN telemetry unavailable: %s', error)

    def _update_wan_failover_status(self):
        if self.vyos_provisioner is None or self.vyos_provisioner.wan_fib_command is None:
            return
        from backends.vyos import VyOSReadError
        from gateway_profiles.uxg_wan_status import project_wan_durations

        revision = self.config.get('vyos_applied', 'cfgversion', fallback=None)
        if revision is None:
            self._wan_observations = {}
            return
        status = None
        try:
            status = self.vyos_provisioner.observe_wan_uplink(revision)
        except (ValueError, OSError, VyOSReadError) as error:
            logger.debug('WAN failover telemetry unavailable: %s', error)
        data = self.datacollector.data
        counters, self._wan_observations = project_wan_durations(
            status['availability'] if status else None, data.get('links', {}), self._wan_observations,
            now=time.monotonic(),
        )
        if status is not None:
            data['wan_failover'] = {'uplink': status['uplink'], 'uptime_stats': counters}

    def _check_inspection(self):
        intent = self._verified_inspection
        if intent is None or (intent.mode == 'off' and not self._stock_inspection) or time.monotonic() < self._inspection_check_at:
            return
        self._inspection_check_at = time.monotonic() + 30
        from inspection.controller import InspectionControlError

        try:
            if self._stock_inspection:
                self.vyos_provisioner.verify_stock_inspection(intent)
            else:
                self.vyos_inspection.verify(intent)
        except InspectionControlError as error:
            self._verified_inspection = None
            if self.config.remove_section('vyos_applied'):
                logger.warning('Active inspection could not be verified: %s', error)
                self._notify_vyos_provisioning_error()
                self._save_config()

    def _reject_vyos_provisioning(self, revision, error):
        if self._vyos_provisioning_error != (revision, str(error)):
            self._vyos_provisioning_error = (revision, str(error))
            logger.warning('Rejected VyOS provisioning revision: %s', error)
            self._notify_vyos_provisioning_error()

    def _notify_vyos_provisioning_error(self):
        payload = json.loads(create_inform(self.config, self.datacollector))
        payload.update(inform_as_notif=True, notif_reason='setparam',
                       commit_errors='The managed VyOS configuration revision could not be verified')
        try:
            self._send_inform(json.dumps(payload))
        except (OSError, ValueError) as error:
            logger.warning('Failed to send the VyOS provisioning error: %s', error)

    def _parse_mgmt_cfg(self, data):
        HANDLED_MGMT_KEYS = {
            'cfgversion', 'mgmt_url', 'authkey', 'use_aes_gcm',
            'inform_url', 'stun_url', 'report_crash',
            'capability', 'selfrun_guest_mode', 'led_enabled',
        }
        for row in data.splitlines():
            if '=' not in row:
                continue
            key, value = row.split('=', 1)
            if key == 'cfgversion':
                self.config.set('provisioned', 'cfgversion', value)
            elif key == 'mgmt_url':
                self.config.set('provisioned', 'mgmt_url', value)
            elif key == 'authkey':
                logger.debug('Updating device authkey from mgmt_cfg')
                self.config.set('provisioned', 'key', value)
                self.config.set('gateway', 'key', value)
            elif key == 'use_aes_gcm':
                if not self.config.getboolean('gateway', 'use_aes_gcm'):
                    self.config.set('gateway', 'use_aes_gcm', 'True')
                    logger.debug('Switching encryption to AES-GCM')
            if key not in HANDLED_MGMT_KEYS:
                self._record_unhandled('mgmt_cfg', key)

    def _send_inform(self, data, encryption='CBC'):
        headers = {
            'Accept': '*/*',
            'Content-Type': 'application/x-binary',
            'User-Agent': 'AirControl Agent v1.0',
            'Expect': '100-continue',
        }
        url = self.config.get('gateway', 'url')
        request = urllib.request.Request(
            url, encode_inform(self.config, data, encryption=encryption), headers
        )
        logger.debug('Sending inform to %s', url)
        try:
            response = urllib.request.urlopen(request, timeout=30)
        except urllib.error.HTTPError as e:
            return {'_type': 'httperror', 'code': str(e.code), 'msg': str(e.reason)}
        except urllib.error.URLError as e:
            return {'_type': 'urlerror', 'msg': str(e.reason)}
        require_gcm = (
            (self._vyos_restart is not None or self._shadow_peer_probe is not None
             or self.config.getboolean('vyos_bgp', 'enabled', fallback=False))
            and self.config.getboolean('gateway', 'is_adopted', fallback=False)
            and self.config.getboolean('gateway', 'use_aes_gcm', fallback=False)
        )
        return decode_inform(self.config, response.read(), require_gcm=require_gcm)

    def _sanitize_stored_system_cfg(self):
        original = self.config.get('provisioned', 'system_cfg', fallback=None)
        if original is None:
            return False
        sanitized = _redact_native_system_cfg(original)
        if sanitized == original:
            return False
        if sanitized is None:
            self.config.remove_option('provisioned', 'system_cfg')
            logger.warning('Discarding invalid UXG system_cfg from configuration state')
        else:
            self.config.set('provisioned', 'system_cfg', sanitized)
        return True

    def _save_config(self):
        # Atomic: a kill mid-write must never leave a truncated config (it holds the adoption key)
        self._sanitize_stored_system_cfg()
        _atomic_write(CONFIG_FILE, self.config.write, mode=0o600)


def main():
    parser = argparse.ArgumentParser(description='Manage VyOS and report gateway telemetry to UniFi Network')
    subparsers = parser.add_subparsers(dest='command')

    subparsers.add_parser('run', help='Run in foreground')
    subparsers.add_parser('check-enrollment-state', help='Verify packaged enrollment and its private state without writing')
    subparsers.add_parser('check-shadow-pair-enrollment', help='Verify both local Shadow Mode enrollments without writing')
    subparsers.add_parser('check-shadow-admission', help='Verify a prepared Enterprise primary and standby before pairing')

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    if args.command == 'check-enrollment-state':
        from gateway_profiles.vyos_install import load_enrolled_config

        try:
            load_enrolled_config(
                os.environ['UNIFI_GW_SITE_CONFIG'], CONFIG_FILE, initialize_state=False,
                credential_prefix=os.environ.get('UNIFI_GW_SHADOW_CREDENTIAL_PREFIX', ''),
            )
        except (OSError, ValueError, KeyError) as error:
            parser.error(f'Invalid gateway enrollment state: {error}')
        return

    if args.command == 'check-shadow-admission':
        from backends.vyos import VyOSReadError
        from provisioners.vyos_shadow_receipt import ShadowReceiptError

        if not os.path.isfile(CONFIG_FILE):
            parser.error('Shadow Mode admission needs an existing enrolled primary')
        try:
            gw = UnifiGateway()
            gw._init_collector(observe_standby=True)
            gw._build_shadow_primary(preparing_admission=True).verify_admission()
        except (OSError, ValueError, KeyError, VyOSReadError, ShadowReceiptError) as error:
            parser.error(str(error))
        print('Shadow Mode pre-pair checks passed')
        return

    if args.command == 'check-shadow-pair-enrollment':
        from pathlib import Path

        from gateway_profiles.vyos_install import check_shadow_pair_enrollment

        try:
            check_shadow_pair_enrollment(Path(os.environ['CREDENTIALS_DIRECTORY']), Path(os.environ['STATE_DIRECTORY']))
        except (OSError, ValueError, KeyError) as error:
            parser.error(f'Invalid Shadow Mode enrollment: {error}')
        return

    UnifiGateway().run()


if __name__ == '__main__':
    main()
