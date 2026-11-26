#!/usr/bin/env python3
"""Prepare a private configuration fragment for a stock VyOS console merge."""

import argparse
from base64 import b64encode
from ipaddress import IPv4Address
import os
from pathlib import Path
import re
import stat
import subprocess


def unicast(value):
    address = IPv4Address(value)
    if (address.is_unspecified or address.is_multicast or address.is_loopback
            or address == IPv4Address("255.255.255.255")):
        raise ValueError("Use a unicast IPv4 address for each end of the management link")
    return address


def private_file(path):
    attributes = path.lstat()
    if (not stat.S_ISREG(attributes.st_mode) or attributes.st_uid != os.geteuid()
            or stat.S_IMODE(attributes.st_mode) not in (0o400, 0o600)):
        raise ValueError(f"{path.name} must be a private file owned by the current user (0400 or 0600)")
    return path


def openssl(problem, *arguments):
    try:
        return subprocess.run(
            ["openssl", *arguments], check=True, capture_output=True, stdin=subprocess.DEVNULL,
        ).stdout
    except subprocess.CalledProcessError:
        raise ValueError(problem) from None


def certificate_body(path):
    if path.read_bytes().count(b"-----BEGIN CERTIFICATE-----") != 1:
        raise ValueError(f"{path.name} must contain one PEM certificate")
    return b64encode(openssl(f"Invalid certificate in {path.name}", "x509", "-in", path, "-outform", "DER")).decode()


def certificate_is_ca(path):
    constraints = openssl(f"Could not read basic constraints in {path.name}",
                          "x509", "-in", path, "-noout", "-ext", "basicConstraints")
    return b"CA:TRUE" in constraints


def certificate_key(path):
    return openssl(f"Could not read the public key in {path.name}", "x509", "-in", path, "-pubkey", "-noout")


def render(router, bridge, port, directory):
    router, bridge = unicast(router), unicast(bridge)
    if router == bridge or not 1 <= port <= 65535:
        raise ValueError("Use distinct router and bridge addresses and a port from 1 through 65535")

    key_file = private_file(directory / "router-key.pem")
    api_key = private_file(directory / "vyos-api-key").read_text(encoding="ascii").removesuffix("\n")
    if not re.fullmatch(r"[a-fA-F0-9]{64}", api_key):
        raise ValueError("vyos-api-key must contain one 64-digit hexadecimal key")

    ca_file = directory / "ca.pem"
    certificate = directory / "router.pem"
    ca_body = certificate_body(ca_file)
    certificate_text = certificate_body(certificate)
    if not certificate_is_ca(ca_file) or certificate_is_ca(certificate):
        raise ValueError("ca.pem must have CA:TRUE and router.pem must be a server certificate")
    public_key = certificate_key(certificate)
    if public_key == certificate_key(ca_file):
        raise ValueError("The CA signing key and router TLS key must be distinct")
    if public_key != openssl("Could not read the router private key",
                             "pkey", "-in", key_file, "-passin", "pass:", "-pubout"):
        raise ValueError("Router certificate and private key do not match")
    openssl("Router certificate must form a strict TLS chain to the CA in ca.pem and identify the router IP",
            "verify", "-x509_strict", "-no-CApath", "-no-CAstore", "-CAfile", ca_file,
            "-purpose", "sslserver", "-verify_ip", str(router), certificate)
    private_key = b64encode(openssl("Could not read the router private key", "pkcs8", "-topk8",
                                   "-nocrypt", "-in", key_file, "-passin", "pass:", "-outform", "DER")).decode()
    return f'''pki {{
    ca unifi-gateway-ca {{
        certificate "{ca_body}"
    }}
    certificate unifi-gateway-https {{
        certificate "{certificate_text}"
        private {{
            key "{private_key}"
        }}
    }}
}}
service {{
    https {{
        listen-address "{router}"
        port "{port}"
        allow-client {{
            address "{bridge}/32"
        }}
        certificates {{
            ca-certificate "unifi-gateway-ca"
            certificate "unifi-gateway-https"
        }}
        api {{
            keys {{
                id unifi-gateway {{
                    key "{api_key}"
                }}
            }}
            rest
        }}
    }}
}}
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("router", help="Existing VyOS management IPv4 address")
    parser.add_argument("bridge", help="Bridge management IPv4 address as seen by VyOS")
    parser.add_argument("port", type=int, help="Dedicated HTTPS port on VyOS")
    parser.add_argument("credentials", type=Path, help="Directory with CA, server certificate and both key files")
    parser.add_argument("output", type=Path, help="New private VyOS configuration fragment")
    args = parser.parse_args()
    try:
        fragment = render(args.router, args.bridge, args.port, args.credentials)
        fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            with os.fdopen(fd, "w", encoding="ascii") as output:
                os.fchmod(output.fileno(), 0o600)
                output.write(fragment)
        except BaseException:
            args.output.unlink()
            raise
    except (OSError, ValueError) as error:
        parser.exit(1, f"{error}\n")


if __name__ == "__main__":
    main()
