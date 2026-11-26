"""Persist native event delivery decisions without storing event metadata."""

import argparse
import configparser
import json
import os
import re
import sqlite3
import stat
import sys
from contextlib import closing
from datetime import datetime
from hashlib import sha256
from pathlib import Path

from gateway_profiles.enterprise import require_enterprise
from inspection.connection_flow import project_connection_flow
from inspection.suricata import decode_eve_event
from inspection.unifi_broker import (
    BrokerPublishError,
    BrokerTrust,
    UniFiBrokerPublisher,
    decode_broker_provisioning,
)
from inspection.unifi_event import (
    FlowObservation,
    SignatureMetadata,
    project_suricata_event,
)


def broker_trust_from_config(config):
    settings = config["vyos_security_events"]
    return BrokerTrust(
        host=settings["host"],
        port=settings.getint("port", fallback=5671),
        site_id=settings["site_id"],
        tls_hostname=settings["tls_hostname"],
        ca_sha256=settings["ca_sha256"],
        gateway_mac=config["gateway"]["lan_mac"],
    )


def verified_broker_from_state(path, trust):
    """Read an atomic, adopted and verified provisioning snapshot for the worker."""
    config = configparser.RawConfigParser()
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as handle:
        info = os.fstat(handle.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077 or info.st_uid != os.geteuid():
            raise ValueError("Security event provisioning must be a private regular file")
        data = handle.read(4 * 1024 * 1024 + 1)
    if len(data) > 4 * 1024 * 1024:
        raise ValueError("Security event provisioning exceeds its size limit")
    try:
        config.read_string(data.decode("utf-8"))
        require_enterprise(config)
        if config.defaults():
            raise ValueError("Security event provisioning must omit defaults")
        revision = config.get("provisioned", "cfgversion", fallback="")
        system_cfg = config.get("provisioned", "system_cfg", fallback="")
        if (not revision or not system_cfg
                or config.get("gateway", "lan_mac", fallback="") != trust.gateway_mac
                or not config.getboolean("gateway", "is_adopted", fallback=False)
                or config.get("vyos_applied", "cfgversion", fallback="") != revision
                or config.get("vyos_applied", "system_cfg_sha256", fallback="") != sha256(system_cfg.encode()).hexdigest()):
            return None
    except (configparser.Error, UnicodeError):
        raise ValueError("Invalid security event provisioning snapshot") from None
    broker = decode_broker_provisioning(system_cfg, trust=trust, required_event_state="ipsIds")
    return trust, UniFiBrokerPublisher(broker)


def project_observation(observation, *, trust):
    """Project correlated EVE flow counters and independently verified forwarding."""
    if (
        not isinstance(observation, dict)
        or observation.keys() != {"eve", "forwarding_observed"}
        or type(observation["forwarding_observed"]) is not bool
    ):
        raise ValueError("Security observation needs EVE and a forwarding observation")
    eve = observation["eve"]
    event = decode_eve_event(eve)
    if event is None:
        raise ValueError("Security observation is not a supported EVE alert")
    try:
        flow = eve["flow"]
        flow_id = eve["flow_id"]
        observed = FlowObservation(
            flow_id,
            flow_id,
            datetime.fromisoformat(flow["start"]),
            flow["bytes_toclient"],
            flow["bytes_toserver"],
            flow["pkts_toclient"],
            flow["pkts_toserver"],
        )
        alert = eve["alert"]
        signature = SignatureMetadata(
            alert["gid"],
            alert["rev"],
            alert["severity"],
            alert["signature"],
            alert["category"],
        )
    except (KeyError, TypeError, ValueError):
        raise ValueError(
            "Security observation needs correlated EVE flow and signature data"
        ) from None
    body = project_suricata_event(
        event,
        site_id=trust.site_id,
        gateway_mac=trust.gateway_mac,
        flow=observed,
        signature=signature,
        forwarding_observed=observation["forwarding_observed"],
    )
    return (event.event_id, body) if body is not None else None


def publish_once(path, publisher, event_id: str, event: dict) -> bool:
    """Send a new event once. Keep an uncertain delivery pending for review."""
    if not isinstance(event_id, str) or re.fullmatch(r"[a-f0-9]{64}", event_id) is None:
        raise ValueError("Security delivery requires a lowercase SHA-256 event ID")
    key = event["site_id"], event["gateway_mac"], event_id
    fd = os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        mode = os.fstat(fd).st_mode
        if not stat.S_ISREG(mode) or mode & 0o077:
            raise ValueError("Security delivery journal must be a private regular file")
    finally:
        os.close(fd)

    with closing(sqlite3.connect(path)) as journal:
        journal.execute("""
            CREATE TABLE IF NOT EXISTS deliveries (
                site TEXT NOT NULL,
                gateway TEXT NOT NULL,
                event TEXT NOT NULL,
                confirmed INTEGER NOT NULL CHECK (confirmed IN (0, 1)),
                PRIMARY KEY (site, gateway, event)
            )
        """)
        with journal:
            claimed = journal.execute(
                "INSERT OR IGNORE INTO deliveries VALUES (?, ?, ?, 0)", key
            ).rowcount
        if not claimed:
            state = journal.execute(
                "SELECT confirmed FROM deliveries WHERE site=? AND gateway=? AND event=?",
                key,
            ).fetchone()
            if state == (1,):
                return False
            raise BrokerPublishError(
                "Prior delivery is pending and needs broker verification"
            )

        try:
            publisher.publish(event_id, event)
        except BrokerPublishError as error:
            if not error.delivery_confirmed:
                if error.definitely_unsent:
                    with journal:
                        journal.execute(
                            "DELETE FROM deliveries WHERE site=? AND gateway=? AND event=? AND confirmed=0", key
                        )
                raise
        with journal:
            journal.execute(
                "UPDATE deliveries SET confirmed=1 WHERE site=? AND gateway=? AND event=?",
                key,
            )
        return True


def main():
    parser = argparse.ArgumentParser(
        description="Publish verified security or flow observations to UniFi"
    )
    parser.add_argument(
        "--config", default=os.environ.get("UNIFI_GW_CONFIG", "conf/unifi-gateway.conf")
    )
    parser.add_argument(
        "--completed-flows",
        action="store_true",
        help="Read verified completed-flow observations",
    )
    args = parser.parse_args()
    config = configparser.RawConfigParser()
    try:
        path = Path(args.config)
        mode = path.stat().st_mode
        if not stat.S_ISREG(mode) or mode & 0o077:
            raise ValueError(
                "The provisioned gateway configuration must be a private regular file"
            )
        with path.open(encoding="utf-8") as handle:
            config.read_file(handle)
        require_enterprise(config)
        if (
            not config.getboolean("gateway", "is_adopted")
            or not config.getboolean(
                "vyos_security_events", "enabled", fallback=False
            )
        ):
            raise ValueError(
                "Security event delivery requires an adopted VyOS gateway and explicit opt-in"
            )
        trust = broker_trust_from_config(config)
        event_state = "conntrack" if args.completed_flows else "ipsIds"
        broker = decode_broker_provisioning(
            config["provisioned"]["system_cfg"],
            trust=trust,
            required_event_state=event_state,
        )
        publisher = UniFiBrokerPublisher(broker)
        journal = config["vyos_security_events"]["journal_path"]
    except (UnicodeError, configparser.Error):
        parser.exit(1, "Security event setup failed. Invalid gateway configuration.\n")
    except (ValueError, OSError, LookupError) as error:
        parser.exit(1, f"Security event setup failed. {error}\n")

    count = 0
    for number, line in enumerate(
        iter(lambda: sys.stdin.buffer.readline(65537), b""), start=1
    ):
        try:
            if len(line) > 65536:
                raise ValueError("Security observation exceeds the input limit")
            observation = json.loads(line)
            if args.completed_flows:
                flow = project_connection_flow(
                    observation, site_id=trust.site_id, gateway_mac=trust.gateway_mac
                )
                projected = flow.event_id, flow.event
            else:
                projected = project_observation(observation, trust=trust)
            if projected is not None and publish_once(journal, publisher, *projected):
                count += 1
        except (UnicodeError, json.JSONDecodeError):
            parser.exit(
                1, f"Security observation {number} failed. Invalid JSON input.\n"
            )
        except (
            ValueError,
            OSError,
            BrokerPublishError,
            OverflowError,
            RecursionError,
            sqlite3.Error,
        ) as error:
            parser.exit(1, f"Security observation {number} failed. {error}\n")
    print(f"Published {count} verified events")


if __name__ == "__main__":
    main()
