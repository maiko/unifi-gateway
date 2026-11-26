"""Publish inspection events to a trusted UniFi broker."""

import base64
import hashlib
import hmac
import json
import os
import re
import ssl
from dataclasses import dataclass, field
from ipaddress import ip_address
from pathlib import Path
from tempfile import TemporaryDirectory
from threading import Event
from uuid import UUID

from inspection.connection_flow import completed_flow_event_id

_CONNECT_TIMEOUT = 8
_CONFIRM_TIMEOUT = 8
_SUPPORTED_EVENT_STATES = frozenset({"ipsIds", "conntrack"})
_SURICATA_FIELDS = {
    "type",
    "site_id",
    "gateway_mac",
    "timestamp",
    "action",
    "flow_id",
    "ip",
    "flow",
    "alert",
    "ubnt",
}
_SURICATA_OBJECTS = {
    "ip": {"saddr", "sport", "daddr", "dport", "protocol"},
    "flow": {
        "flow_id",
        "start",
        "bytes_toclient",
        "bytes_toserver",
        "pkts_toclient",
        "pkts_toserver",
    },
    "alert": {"signature_id", "signature", "gid", "rev", "severity", "category"},
    "ubnt": set(),
}


class BrokerConfigError(ValueError):
    """Provisioning does not establish a trusted broker."""


class BrokerPublishError(RuntimeError):
    """Publication failed or its outcome could not be verified."""

    def __init__(self, message: str, *, delivery_confirmed: bool = False, definitely_unsent: bool = False):
        super().__init__(message)
        self.delivery_confirmed = delivery_confirmed
        self.definitely_unsent = definitely_unsent


@dataclass(frozen=True, slots=True)
class BrokerTrust:
    """Broker pins from local operator configuration."""

    host: str
    port: int
    site_id: str
    tls_hostname: str
    ca_sha256: str
    gateway_mac: str


@dataclass(frozen=True, slots=True)
class BrokerConfig:
    trust: BrokerTrust
    event_states: frozenset[str]
    _username: str = field(repr=False)
    _password: str = field(repr=False)
    _ca_pem: str = field(repr=False)
    _client_cert: bytes = field(repr=False)
    _client_key: bytes = field(repr=False)


def _validate_trust(trust: BrokerTrust) -> None:
    try:
        ip_address(trust.host)
        if not isinstance(trust.host, str) or "%" in trust.host:
            raise ValueError
        if str(UUID(trust.site_id)) != trust.site_id:
            raise ValueError
    except (TypeError, AttributeError, ValueError):
        raise BrokerConfigError(
            "Local broker trust requires a numeric address and canonical site UUID"
        ) from None
    if type(trust.port) is not int or not 1 <= trust.port <= 65535:
        raise BrokerConfigError("Local broker port is invalid")
    if not isinstance(trust.tls_hostname, str) or not all(
        re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", label)
        for label in trust.tls_hostname.split(".")
    ):
        raise BrokerConfigError("Local broker TLS hostname is invalid")
    if not isinstance(trust.ca_sha256, str) or not re.fullmatch(
        r"[0-9a-fA-F]{64}", trust.ca_sha256
    ):
        raise BrokerConfigError("Local broker CA pin must be a SHA-256 hex digest")
    if not isinstance(trust.gateway_mac, str) or not re.fullmatch(
        r"(?:[0-9a-f]{12}|[0-9a-f]{2}(?::[0-9a-f]{2}){5})", trust.gateway_mac, re.I
    ):
        raise BrokerConfigError("Local gateway MAC is invalid")


def _unique_fields(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise BrokerConfigError(
                "Broker provisioning contains a duplicate JSON field"
            )
        result[key] = value
    return result


def _invalid_constant(_value):
    raise BrokerConfigError("Broker provisioning contains a non-JSON constant")


def _decode_pem(value, label: bytes) -> tuple[bytes, bytes]:
    if not isinstance(value, str):
        raise BrokerConfigError(
            "Broker provisioning contains invalid Base64 PEM material"
        )
    try:
        pem = base64.b64decode(value, validate=True).strip()
        match = re.fullmatch(
            rb"-----BEGIN " + label + rb"-----\r?\n([A-Za-z0-9+/=\r\n]+)"
            rb"\r?\n-----END " + label + rb"-----",
            pem,
        )
        if match is None:
            raise ValueError
        der = base64.b64decode(b"".join(match[1].splitlines()), validate=True)
        if not der:
            raise ValueError
    except ValueError:
        raise BrokerConfigError(
            "Broker provisioning contains invalid Base64 PEM material"
        ) from None
    return pem + b"\n", der


def decode_broker_provisioning(
    system_cfg: str, *, trust: BrokerTrust, required_event_state: str = "ipsIds"
) -> BrokerConfig:
    """Accept a provisioned broker only when it matches the pinned connection settings."""
    _validate_trust(trust)
    if (
        type(required_event_state) is not str
        or required_event_state not in _SUPPORTED_EVENT_STATES
    ):
        raise BrokerConfigError("Unsupported required broker event state")
    if not isinstance(system_cfg, str):
        raise BrokerConfigError("Broker provisioning must be a JSON string")
    try:
        config = json.loads(
            system_cfg,
            object_pairs_hook=_unique_fields,
            parse_constant=_invalid_constant,
        )
        udapi = config["udapi"]
        version = udapi["version"]
        broker_version = udapi["versionDetail"]["services/messageBroker"]
        if (
            type(version) is not int
            or version != 48
            or udapi["versionFormat"] != "v2"
            or type(broker_version) is not int
            or broker_version != 3
        ):
            raise BrokerConfigError("Unsupported UniFi message broker version")
        service = udapi["services"]["messageBroker"]
        if service["enabled"] is not True or service["siteID"] != trust.site_id:
            raise BrokerConfigError(
                "Message broker requires an enabled service for the pinned site"
            )
        event_types = service["flowConfiguration"]["eventState"]
        if type(event_types) is not list or not all(
            type(value) is str for value in event_types
        ):
            raise BrokerConfigError("Message broker event configuration is invalid")
        event_states = _SUPPORTED_EVENT_STATES.intersection(event_types)
        if required_event_state not in event_states:
            raise BrokerConfigError(
                f"Message broker has no {required_event_state} event configuration"
            )

        rabbit = service["rabbitMq"]
        if (
            not isinstance(rabbit, dict)
            or rabbit.keys() != {"host", "port", "authentication", "tls"}
            or rabbit["host"] != trust.host
            or type(rabbit["port"]) is not int
            or rabbit["port"] != trust.port
        ):
            raise BrokerConfigError(
                "Provisioned broker does not match the pinned endpoint"
            )
        authentication = rabbit["authentication"]
        username, password = authentication["username"], authentication["password"]
        if not all(
            isinstance(value, str) and value and "\0" not in value
            for value in (username, password)
        ):
            raise BrokerConfigError(
                "Broker provisioning is missing device authentication"
            )
        tls = rabbit["tls"]
        if tls["enabled"] is not True or tls["verifyPeer"] is not True:
            raise BrokerConfigError(
                "Broker provisioning must require TLS peer verification"
            )
        _, ca_der = _decode_pem(tls["caCertificate"]["crt"], b"CERTIFICATE")
        client_cert, _ = _decode_pem(tls["clientCertificate"]["crt"], b"CERTIFICATE")
        client_key, _ = _decode_pem(tls["clientCertificate"]["key"], b"PRIVATE KEY")
    except BrokerConfigError:
        raise
    except (KeyError, TypeError, ValueError, RecursionError):
        raise BrokerConfigError(
            "Invalid or incomplete UniFi message broker provisioning"
        ) from None
    if not hmac.compare_digest(
        hashlib.sha256(ca_der).hexdigest(), trust.ca_sha256.lower()
    ):
        raise BrokerConfigError("Provisioned broker CA does not match the local pin")
    return BrokerConfig(
        trust,
        event_states,
        username,
        password,
        ssl.DER_cert_to_PEM_cert(ca_der),
        client_cert,
        client_key,
    )


def _tls_context(config: BrokerConfig) -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.verify_mode = ssl.CERT_REQUIRED
    context.check_hostname = True
    context.load_verify_locations(cadata=config._ca_pem)
    with TemporaryDirectory(prefix="unifi-broker-") as directory:
        certfile = Path(directory) / "client.crt"
        keyfile = Path(directory) / "client.key"
        for path, contents in (
            (certfile, config._client_cert),
            (keyfile, config._client_key),
        ):
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as handle:
                handle.write(contents)
        context.load_cert_chain(certfile, keyfile, password="")
    return context


def _load_pika():
    try:
        import pika
        from pika.adapters.thread_safe_connection import Connection
    except ImportError:
        raise BrokerPublishError(
            "The optional UniFi broker publisher requires Pika 1.5", definitely_unsent=True
        ) from None
    if not pika.__version__.startswith("1.5."):
        raise BrokerPublishError(
            "The optional UniFi broker publisher requires Pika 1.5", definitely_unsent=True
        )
    return pika, Connection


def _validate_suricata(event: dict) -> None:
    if event.keys() != _SURICATA_FIELDS or event["action"] not in ("ACCEPT", "DROP"):
        raise BrokerPublishError("Event does not match the Suricata event schema")
    for name, fields in _SURICATA_OBJECTS.items():
        values = event[name]
        if (
            type(values) is not dict
            or values.keys() != fields
            or any(type(value) not in (str, int) for value in values.values())
        ):
            raise BrokerPublishError(
                "Event metadata contains unsupported fields or values"
            )
    if not isinstance(event["timestamp"], str) or type(event["flow_id"]) is not int:
        raise BrokerPublishError("Event is missing a timestamp or numeric flow ID")


def _event_body(event_id: str, event: dict, config: BrokerConfig) -> bytes:
    if not isinstance(event_id, str) or not re.fullmatch(r"[0-9a-f]{64}", event_id):
        raise BrokerPublishError("A broker event requires a lowercase SHA-256 event ID")
    if (
        type(event) is not dict
        or event.get("site_id") != config.trust.site_id
        or event.get("gateway_mac") != config.trust.gateway_mac
    ):
        raise BrokerPublishError("Event does not match the pinned gateway and site")

    if event.get("type") == "SuricataEvent":
        if "ipsIds" not in config.event_states:
            raise BrokerPublishError(
                "Message broker is not provisioned for ipsIds events"
            )
        _validate_suricata(event)
    elif event.get("type") == "FLOW_POLICY":
        if "conntrack" not in config.event_states:
            raise BrokerPublishError(
                "Message broker is not provisioned for conntrack events"
            )
        try:
            expected_id = completed_flow_event_id(event)
        except ValueError:
            raise BrokerPublishError(
                "Event does not match the completed-flow schema"
            ) from None
        if not hmac.compare_digest(event_id, expected_id):
            raise BrokerPublishError(
                "Event ID does not match the completed-flow identity"
            )
    else:
        raise BrokerPublishError("Unsupported broker event type")

    try:
        return json.dumps(
            event, ensure_ascii=False, separators=(",", ":"), allow_nan=False
        ).encode("utf-8")
    except (UnicodeError, ValueError):
        raise BrokerPublishError("Event cannot be encoded as UTF-8 JSON") from None


class UniFiBrokerPublisher:
    """Send a scoped event on a fresh, authenticated connection."""

    def __init__(self, config: BrokerConfig):
        if not isinstance(config, BrokerConfig):
            raise TypeError("UniFi broker publisher requires decoded provisioning")
        self._config = config

    def publish(self, event_id: str, event: dict) -> None:
        """Return after positive broker confirmation, or report a bounded failure."""
        config = self._config
        body = _event_body(event_id, event, config)
        try:
            context = _tls_context(config)
        except (OSError, ValueError):
            raise BrokerPublishError(
                "Unable to load verified UniFi broker TLS credentials", definitely_unsent=True
            ) from None
        pika, connect = _load_pika()
        connection = None
        failure = None
        outcome = None
        delivery_confirmed = False
        operation = "connection setup"
        completed = Event()

        def on_return(_channel, _method, _properties, _body):
            nonlocal outcome
            outcome = "unroutable"
            completed.set()

        def on_confirm(frame):
            nonlocal outcome
            if outcome is not None:
                return
            method = frame.method
            if isinstance(method, pika.spec.Basic.Nack):
                outcome = "rejected"
            elif isinstance(method, pika.spec.Basic.Ack) and (
                method.delivery_tag == 1
                or (method.multiple and method.delivery_tag == 0)
            ):
                outcome = "confirmed"
            else:
                outcome = "unexpected"
            completed.set()

        try:
            params = pika.ConnectionParameters(
                host=config.trust.host,
                port=config.trust.port,
                virtual_host="/",
                credentials=pika.PlainCredentials(
                    config._username, config._password, erase_on_connect=True
                ),
                ssl_options=pika.SSLOptions(context, config.trust.tls_hostname),
                connection_attempts=1,
                socket_timeout=5,
                stack_timeout=_CONNECT_TIMEOUT,
                blocked_connection_timeout=5,
            )
            connection = connect(params, timeout=_CONNECT_TIMEOUT)
            operation = "confirm setup"
            channel = connection.channel(timeout=_CONNECT_TIMEOUT)
            channel.add_on_return_callback(on_return)
            channel.confirm_delivery(on_confirm, timeout=_CONNECT_TIMEOUT)
            operation = "publication"
            channel.basic_publish(
                exchange="",
                routing_key="unifi_flow_queue",
                mandatory=True,
                body=body,
                properties=pika.BasicProperties(
                    content_type="text/plain",
                    content_encoding="utf-8",
                    message_id=event_id,
                ),
            )
            if not completed.wait(_CONFIRM_TIMEOUT):
                failure = "UniFi broker confirmation timed out and delivery is unknown"
            elif outcome == "confirmed":
                delivery_confirmed = True
            else:
                failure = {
                    "unroutable": "UniFi broker returned the event as unroutable",
                    "rejected": "UniFi broker rejected the event",
                }.get(outcome, "UniFi broker returned an unexpected confirmation")
        except Exception:
            failure = f"UniFi broker {operation} failed"
        finally:
            if connection is not None:
                try:
                    connection.close(timeout=_CONNECT_TIMEOUT)
                except Exception:
                    if failure is None:
                        failure = "UniFi broker accepted the event but connection cleanup failed"
        if failure is not None:
            raise BrokerPublishError(
                failure, delivery_confirmed=delivery_confirmed, definitely_unsent=operation != "publication"
            )
