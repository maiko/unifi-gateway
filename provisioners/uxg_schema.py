"""UniFi Network configuration schema versions used for gateway provisioning."""

_BASE_VERSIONS = {
    "firewall/filter": 4,
    "firewall/mangle": 6,
    "firewall/sets": 1,
    "firewall/settings": 1,
    "interfaces": 8,
}

OSPF_VERSIONS = {"routes/ospf": 2, "routes/ospf/areas": 2, "routes/ospf/interfaces": 2}
OSPF_CAPABILITY = 0x40000


def selected_schema(*, message_broker=False, dns_forwarder=False, nat=False, wireguard=False):
    versions = dict(_BASE_VERSIONS)
    if message_broker:
        versions["services/messageBroker"] = 3
    if dns_forwarder:
        versions["services/dnsForwarder"] = 4
    if nat:
        versions["firewall/nat"] = 7
    if wireguard:
        versions["vpn/wireguard/servers"] = 6
    return versions
