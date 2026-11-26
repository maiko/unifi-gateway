import base64
import json
import subprocess
from hashlib import sha256
from pathlib import Path

import pytest


RAW_SECTION = "vpn/openvpn/raws"
CAPS = 0x80
USER = "synthetic-openvpn-user"
PASSWORD = "synthetic-openvpn-password"


class SyntheticCertificateMaterial(tuple):
    def __repr__(self):
        return "<synthetic OpenVPN test PKI>"


@pytest.fixture(scope="module")
def certificate_material(tmp_path_factory):
    directory = tmp_path_factory.mktemp("openvpn-test-pki")

    def openssl(*arguments):
        subprocess.run(
            ["/usr/bin/openssl", *arguments],
            cwd=directory,
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=8,
        )

    openssl("ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", "ca.key")
    openssl(
        "req",
        "-new",
        "-x509",
        "-key",
        "ca.key",
        "-out",
        "ca.pem",
        "-subj",
        "/CN=temporary-openvpn-test-ca",
        "-days",
        "2",
    )
    openssl("ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", "client.ec")
    openssl(
        "req",
        "-new",
        "-key",
        "client.ec",
        "-out",
        "client.csr",
        "-subj",
        "/CN=temporary-openvpn-test-client",
    )
    openssl(
        "x509",
        "-req",
        "-in",
        "client.csr",
        "-CA",
        "ca.pem",
        "-CAkey",
        "ca.key",
        "-CAcreateserial",
        "-out",
        "client.pem",
        "-days",
        "2",
    )
    for source, target in (("client.ec", "client.key"), ("ca.key", "other.key")):
        openssl("pkcs8", "-topk8", "-nocrypt", "-in", source, "-out", target)
    return SyntheticCertificateMaterial(
        (directory / name).read_text()
        for name in ("ca.pem", "client.pem", "client.key", "other.key")
    )


def raw_profile(material, *, port=19443, auth_flag=False):
    ca, cert, key, _ = material
    profile = (
        "client\n"
        "dev tun\n"
        "proto udp\n"
        f"remote 198.18.210.2 {port}\n"
        "nobind\n"
        "persist-key\n"
        "persist-tun\n"
        "remote-cert-tls server\n"
        "verify-x509-name router.example.net name\n"
        "tls-version-min 1.2\n"
        "data-ciphers AES-256-GCM\n"
        "auth SHA256\n"
        "verb 3\n"
        f"<ca>\n{ca}</ca>\n"
        f"<cert>\n{cert}</cert>\n"
        f"<key>\n{key}</key>\n"
    )
    return profile + ("auth-user-pass\n" if auth_flag else "")


def snapshot(profile=None, *, username=USER, password=PASSWORD):
    udapi = {
        "version": 48,
        "versionFormat": "v2",
        "versionDetail": {"interfaces": 8, RAW_SECTION: 6},
        "interfaces": [
            {
                "identification": {"id": "eth0", "type": "ethernet"},
                "status": {"enabled": True},
                "addresses": [
                    {"type": "static", "cidr": "198.18.210.1/30", "version": "v4"}
                ],
            }
        ],
    }
    if profile is not None:
        udapi[RAW_SECTION] = [
            {
                "id": "1",
                "enabled": True,
                "localAddress": {"source": "wan", "ipVersion": "v4"},
                "authentication": {"username": username, "password": password},
                "configuration": base64.b64encode(profile.encode("ascii")).decode(
                    "ascii"
                ),
            }
        ]
    return {"udapi": udapi, "ubntconf": {}}


def decode(document, *, caps=CAPS):
    from provisioners.uxg_openvpn import decode_openvpn_intent

    return decode_openvpn_intent(json.dumps(document), udapi_caps=caps, server_name="router.example.net")


def test_create_edit_and_delete_bind_one_tls_peer_without_exposing_material(
    certificate_material,
):
    create = decode(snapshot(raw_profile(certificate_material)), caps=CAPS | 0x40000)
    edit = decode(
        snapshot(
            raw_profile(certificate_material, port=19444, auth_flag=True),
            username="rotated-fixture-user",
            password="rotated-fixture-password",
        )
    )

    assert create.native_id == edit.native_id == "1"
    assert create.remote_host == edit.remote_host == "198.18.210.2"
    assert (create.remote_port, edit.remote_port) == (19443, 19444)
    assert create.server_name == edit.server_name == "router.example.net"
    assert create.username == USER and create.password == PASSWORD
    assert edit.username == "rotated-fixture-user"
    assert edit.password == "rotated-fixture-password"
    assert (
        sha256(create.ca_pem).digest()
        == sha256(certificate_material[0].encode()).digest()
    )
    assert (
        sha256(create.client_certificate_pem).digest()
        == sha256(certificate_material[1].encode()).digest()
    )
    assert (
        sha256(create.client_private_key_pem).digest()
        == sha256(certificate_material[2].encode()).digest()
    )
    assert all(
        value not in repr(create) for value in (USER, PASSWORD, "BEGIN", "PRIVATE KEY")
    )
    assert decode(snapshot()) is None


@pytest.mark.parametrize(
    "extra",
    [
        "auth-user-pass /tmp/supplied",
        "config profile.ovpn",
        "secret shared.key",
        "ca external.pem",
        "script-security 2",
        "up /tmp/start",
        "down /tmp/stop",
        "route 192.0.2.0 255.255.255.0",
        "redirect-gateway def1",
        "pull-filter ignore redirect-gateway",
        "http-proxy 192.0.2.1 8080",
        "compress lz4",
        "tls-auth auth.key",
        "client",
        "remote 198.18.210.2 19444",
    ],
)
def test_disallowed_or_duplicate_native_directives_fail_closed(
    certificate_material, extra
):
    from provisioners.uxg_openvpn import OpenVpnIntentError

    profile = raw_profile(certificate_material) + extra + "\n"
    with pytest.raises(OpenVpnIntentError) as error:
        decode(snapshot(profile))
    assert extra not in str(error.value) and "BEGIN" not in str(error.value)


@pytest.mark.parametrize(
    "original,replacement",
    [
        ("198.18.210.2", "198.18.210.3"),
        ("19443", "19445"),
        ("proto udp", "proto tcp"),
        ("tls-version-min 1.2", "tls-version-min 1.0"),
        ("remote-cert-tls server", "remote-cert-tls client"),
        ("router.example.net", "arbitrary-server"),
        ("data-ciphers AES-256-GCM", "data-ciphers AES-256-CBC"),
        ("auth SHA256", ""),
    ],
)
def test_weaker_or_out_of_scope_parameters_fail_closed(
    certificate_material, original, replacement
):
    from provisioners.uxg_openvpn import OpenVpnIntentError

    changed = raw_profile(certificate_material).replace(original, replacement)
    with pytest.raises(OpenVpnIntentError):
        decode(snapshot(changed))


def test_invalid_or_mismatched_inline_pem_never_becomes_an_intent(certificate_material):
    from provisioners.uxg_openvpn import OpenVpnIntentError

    ca, cert, key, other = certificate_material
    profile = raw_profile(certificate_material)
    for malformed in (
        profile.replace(key, other),
        profile.replace(ca, cert),
        profile.replace(
            ca, "-----BEGIN CERTIFICATE-----\nZ29vZA==\n-----END CERTIFICATE-----\n"
        ),
        profile.replace(cert, cert + cert),
        profile.replace("<key>", "<tls-auth>"),
    ):
        with pytest.raises(OpenVpnIntentError) as error:
            decode(snapshot(malformed))
        assert "BEGIN" not in str(error.value)


@pytest.mark.parametrize("caps", [0, 0x100, -1, True, "128"])
def test_openvpn_authority_requires_the_adopted_device_flag(certificate_material, caps):
    from provisioners.uxg_openvpn import OpenVpnIntentError

    with pytest.raises(OpenVpnIntentError):
        decode(snapshot(raw_profile(certificate_material)), caps=caps)


def test_malformed_scope_or_competing_native_sections_cannot_become_removal(
    certificate_material,
):
    from provisioners.uxg_openvpn import OpenVpnIntentError

    profile = raw_profile(certificate_material)
    edits = [
        lambda u: u["versionDetail"].update({RAW_SECTION: "6"}),
        lambda u: u["versionDetail"].update({RAW_SECTION: 5}),
        lambda u: u.update({"version": 47}),
        lambda u: u.update({"versionFormat": "v1"}),
        lambda u: u.update({"vpn/openvpn/peers": []}),
        lambda u: u.update({"vpn/openvpn/certificates": []}),
        lambda u: u.update({"vpn/openvpn": {}}),
        lambda u: u.update({RAW_SECTION: []}),
        lambda u: u[RAW_SECTION].append(u[RAW_SECTION][0]),
        lambda u: u[RAW_SECTION][0].update(enabled=False),
        lambda u: u[RAW_SECTION][0].update(id="01"),
        lambda u: u[RAW_SECTION][0].update(tunnelMTU=1400),
        lambda u: u[RAW_SECTION][0]["localAddress"].update(ipVersion="v6"),
        lambda u: u["interfaces"].append(u["interfaces"][0]),
        lambda u: u["interfaces"][0]["addresses"][0].update(cidr="198.18.210.5/30"),
    ]
    for edit in edits:
        document = snapshot(profile)
        edit(document["udapi"])
        with pytest.raises(OpenVpnIntentError):
            decode(document)


def test_bounded_and_secret_safe_errors_for_transport_and_credentials(
    certificate_material,
):
    from provisioners.uxg_openvpn import OpenVpnIntentError, decode_openvpn_intent

    document = snapshot(
        raw_profile(certificate_material), password="injected\ncredential"
    )
    invalid_input = [
        json.dumps(document),
        '{"udapi":{"password":"redacted", "password":"another"}}',
        json.dumps(snapshot("X" * 65_536)),
        " " * 1_048_577,
    ]
    for value in invalid_input:
        with pytest.raises(OpenVpnIntentError) as error:
            decode_openvpn_intent(value, udapi_caps=CAPS, server_name="router.example.net")
        assert len(str(error.value)) < 120
        assert all(
            secret not in str(error.value)
            for secret in ("injected", "redacted", "another")
        )


def test_imported_profile_and_vyos_options_use_the_same_explicit_certificate_pin(certificate_material):
    from provisioners.uxg_openvpn import OpenVpnIntentError
    from provisioners.uxg_openvpn_policy import normalize_openvpn_payload
    from provisioners.vyos_openvpn import OpenVpnScope, plan_openvpn

    peer = "Vpn-01.example.net"
    profile = raw_profile(certificate_material).replace("router.example.net", peer)
    document = snapshot(profile)
    companions = json.loads((Path(__file__).parent / "fixtures/uxg_pro/native-openvpn-companions.json").read_text())
    document["udapi"].update({key: value for key, value in companions["create"].items() if key != RAW_SECTION})
    system_cfg = json.dumps(document)
    cleaned, client = normalize_openvpn_payload(system_cfg, server_name=peer)
    assert RAW_SECTION not in json.loads(cleaned)["udapi"]
    assert client.server_name == peer
    scope = OpenVpnScope(server_name=peer)
    plan = plan_openvpn(client, scope, current=None, previous=None, live_interfaces={
        "eth3.210": (["UP", "LOWER_UP"], "\n    inet 198.18.210.1/30\n"),
    })
    assert any(cmd["path"][-1] == f"--verify-x509-name {peer} name" for cmd in plan.commands)
    for wrong_name in ("vpn-01.example.net", "vpn-02.example.net"):
        with pytest.raises(OpenVpnIntentError, match="approved TLS directives"):
            normalize_openvpn_payload(system_cfg, server_name=wrong_name)


@pytest.mark.parametrize("bad_name", ["", "*.example.net", "-x.example", "x..example", "a" * 65,
                                     "vpn.example\nremote x", "vpn name-prefix", "vpn.example.", "péer"])
def test_rejects_invalid_certificate_pin_before_reading_even_a_removal(bad_name):
    from provisioners.uxg_openvpn import decode_openvpn_intent
    from provisioners.vyos_openvpn import OpenVpnScope

    for operation in (lambda: OpenVpnScope(server_name=bad_name),
                      lambda: decode_openvpn_intent(json.dumps(snapshot()), udapi_caps=CAPS, server_name=bad_name)):
        with pytest.raises(ValueError, match="certificate"):
            operation()
