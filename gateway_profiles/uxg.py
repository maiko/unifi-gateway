"""Native UniFi gateway identity and observed VyOS interface telemetry."""
import ast
from ipaddress import IPv4Interface

from gateway_profiles.uxg_route_queries import ROUTE_QUERY_CAPABILITY
from gateway_profiles.uxg_wan_status import project_wan_quality
from gateway_profiles.enterprise import DISPLAY_NAME, FIRMWARE, MODEL, require_enterprise
from provisioners.vyos_bgp import BGP_UPLOAD_CAPABILITY, BGP_UPLOAD_KEY, BGP_UPLOAD_VERSION
from provisioners.vyos_mdns import MDNS_SERVICE_VERSION
from provisioners.uxg_openvpn import OPENVPN_CLIENT_CAPABILITY, OPENVPN_VERSIONS
from provisioners.uxg_pbr import POLICY_ROUTE_CAPABILITY, POLICY_ROUTE_VERSION
from provisioners.uxg_qos import QOS_CAPABILITY
from provisioners.uxg_schema import OSPF_CAPABILITY, OSPF_VERSIONS, selected_schema
from provisioners.uxg_wan_failover import WAN_FAILOVER_CAPABILITY, WAN_FAILOVER_VERSIONS
from provisioners.uxg_enterprise_shadow import SHADOW_ADDRESSES


def _speedtest_status(observation, stage):
    if type(observation) is not dict:
        return None
    latency, download, upload, ran_at = (observation.get(key) for key in ("ping", "download", "upload", "lastrun"))
    if type(ran_at) is not int or not 0 < ran_at < 1 << 53:
        return None
    if stage == "failed":
        return {"status_summary": 3, "rundate": ran_at}
    metrics = (latency, download) if stage == "download" and upload is None else (latency, download, upload)
    if any(type(value) not in (int, float) or not 0 < value < 1 << 31 for value in metrics):
        return None
    if stage == "download":
        download_status, upload_status, summary_status = 1, 0, 1
    elif stage == "upload":
        download_status, upload_status, summary_status = 2, 1, 1
    elif stage == "complete":
        download_status, upload_status, summary_status = 2, 2, 2
    else:
        return None
    status = {
        "latency": int(latency), "rundate": ran_at, "runtime": 0,
        "status_download": download_status, "status_ping": 2,
        "status_summary": summary_status, "status_upload": upload_status,
        "xput_download": download,
    }
    if upload is not None:
        status["xput_upload"] = upload
    if summary_status == 1:
        # The live card reads direction samples in hundredths of a megabit per second.
        status[f"{stage}-progress"] = [{"id": 1, "records": [[ran_at, round(observation[stage] * 100)]]}]
    return status


def build_uxg_inform(config, collector, *, adopted: bool) -> dict:
    gateway = config["gateway"]
    require_enterprise(config)
    payload = {
        "hostname": gateway.get("hostname", "VyOS"),
        "default": not adopted,
        "state": 2 if adopted else 0,
        "inform_url": gateway["url"],
        "mac": gateway["lan_mac"],
        "ip": gateway["lan_ip"],
        "model": MODEL,
        "model_display": DISPLAY_NAME,
        "type": "uxg",
        "version": FIRMWARE,
    }
    if not adopted:
        return payload

    payload["cfgversion"] = ""
    payload["udapi_caps"] = ROUTE_QUERY_CAPABILITY
    if config.getboolean("vyos_firewall", "enabled", fallback=False):
        versions = selected_schema(
            message_broker=config.getboolean("vyos_security_events", "enabled", fallback=False),
            dns_forwarder=config.getboolean("vyos_dns", "enabled", fallback=False),
            nat=(config.getboolean("vyos_source_nat", "enabled", fallback=False)
                 or config.getboolean("vyos_port_forward", "enabled", fallback=False)),
            wireguard=config.getboolean("vyos_wireguard", "enabled", fallback=False),
        )
        versions["interfaces"] = 9
        if config.getboolean("vyos_inspection", "enabled", fallback=False):
            versions["services/idsIps"] = 8
        if config.getboolean("vyos_mdns", "enabled", fallback=False):
            versions.update(MDNS_SERVICE_VERSION)
        if config.getboolean("vyos_ospf", "enabled", fallback=False):
            versions.update(OSPF_VERSIONS)
            payload["udapi_caps"] |= OSPF_CAPABILITY
        if (gateway.getboolean("use_aes_gcm", fallback=False)
                and config.getboolean("vyos_bgp", "enabled", fallback=False)
                and config.getboolean("vyos_bgp", "advertise", fallback=False)
                and config.getboolean("vyos_restart", "recover_provisioning", fallback=False)):
            versions[BGP_UPLOAD_KEY] = BGP_UPLOAD_VERSION
            payload["udapi_caps"] |= BGP_UPLOAD_CAPABILITY
        if config.getboolean("vyos_openvpn", "enabled", fallback=False):
            versions.update(OPENVPN_VERSIONS)
            payload["udapi_caps"] = payload.get("udapi_caps", 0) | OPENVPN_CLIENT_CAPABILITY
        if config.getboolean("vyos_qos", "enabled", fallback=False):
            payload["udapi_caps"] = payload.get("udapi_caps", 0) | QOS_CAPABILITY
        if config.getboolean("vyos_wan_failover", "enabled", fallback=False):
            versions.update(WAN_FAILOVER_VERSIONS)
            payload["udapi_caps"] = payload.get("udapi_caps", 0) | WAN_FAILOVER_CAPABILITY
            if config.getboolean("vyos_policy_route", "enabled", fallback=False):
                versions.update(POLICY_ROUTE_VERSION)
                payload["usg_caps"] = POLICY_ROUTE_CAPABILITY
        payload["udapi_version"] = {
            "version": 1, "versionFormat": "v2", "versionDetail": versions,
        }
        verified = config.get("vyos_applied", "cfgversion", fallback="")
        if verified:
            payload.update(cfgversion=verified, cfgversion_effective=verified)
    ports = ast.literal_eval(gateway["ports"])
    data = collector.data
    speedtest = _speedtest_status(data.get("uxg_speedtest"), data.get("uxg_speedtest_stage", "complete"))
    if speedtest is not None:
        provider = config.get("vyos_speedtest", "server_provider", fallback="").strip()
        location = config.get("vyos_speedtest", "server_location", fallback="").strip()
        if provider and location:
            speedtest["server"] = {"provider": provider, "country": location}
        payload["speedtest-status"] = speedtest
    if "cfgversion_effective" in payload:
        for feature in ("ipsec", "openvpn"):
            status = f"{feature}_status"
            if config.getboolean(f"vyos_{feature}", "enabled", fallback=False) and status in data:
                payload.setdefault("vpn", []).extend(data[status])
    links = data.get("links", {})
    interfaces = []
    observed_ports = []
    networks = []
    indexed_ports = [port["port_idx"] for port in ports if "port_idx" in port]
    if any(type(index) is not int or index < 1 for index in indexed_ports) or len(set(indexed_ports)) != len(indexed_ports):
        raise ValueError("Gateway port indices must be unique positive integers")
    for port in ports:
        name = port["ifname"]
        if name not in links:
            continue
        interface = {"name": name, **links[name]}
        observed_port = {"name": name, **links[name]}
        counters = data.get("ifstat", {}).get(name, {})
        media = data.get("port_media", {}).get(name, {})
        addresses = [*data.get("ipv4", {}).get(name, ()), *data.get("ipv6", {}).get(name, ())]
        primary = data.get("ip", {}).get(name)
        shadow_port = (name == "eth1"
                       and config.getboolean("vyos_shadow", "provisioning_enabled", fallback=False))
        if shadow_port:
            verified = config.get("vyos_shadow_applied", "address", fallback="") if "cfgversion_effective" in payload else ""
            addresses = [address for address in addresses if address not in SHADOW_ADDRESSES or address == verified]
            if primary is not None:
                cidr = str(IPv4Interface(f'{primary["address"]}/{primary["netmask"]}'))
                if cidr in SHADOW_ADDRESSES and cidr != verified:
                    primary = None
        network = {"name": name, "up": links[name]["up"]}
        if name in data.get("macs", {}):
            interface["mac"] = observed_port["mac"] = network["mac"] = data["macs"][name]
            observed_port["num_port"] = 1
        if primary is not None:
            address = primary
            interface["ip"] = address["address"]
            interface["netmask"] = address["netmask"]
            network["address"] = str(IPv4Interface(f'{address["address"]}/{address["netmask"]}'))
            addresses.insert(0, network["address"])
        interface.update(counters)
        interface.update(media)
        interfaces.append(interface)
        if "port_idx" in port:
            observed_port["port_idx"] = port["port_idx"]
            if shadow_port:
                observed_port["ifname"] = name
            observed_port.update(counters)
            observed_port.update(media)
            observed_ports.append(observed_port)
        if addresses:
            network["addresses"] = list(dict.fromkeys(addresses))
            if counters:
                network["stats"] = counters
            networks.append(network)

    payload["config_port_table"] = [
        {key: port[key] for key in ("ifname", "name", "type")} for port in ports if "port_idx" in port
    ]
    payload["if_table"] = interfaces
    payload["port_table"] = observed_ports
    payload["network_table"] = networks
    if "uptime" in data:
        payload["uptime"] = data["uptime"]
    if data.get("system_stats"):
        payload["system-stats"] = data["system_stats"].copy()
        if "uptime" in data:
            payload["system-stats"]["uptime"] = data["uptime"]
    if "routes" in data:
        payload["routes"] = data["routes"]
        wan = {port["ifname"] for port in ports if port["type"] in {"wan", "wan2", "wan3"}}
        uplinks = {hop["intf"] for route in data["routes"] if route["pfx"] == "0.0.0.0/0"
                   for hop in route["nh"] if hop["intf"] in wan and links.get(hop["intf"], {}).get("up")}
        if len(uplinks) == 1:
            payload["uplink"] = uplinks.pop()
    if "wan_failover" in data:
        observed = data["wan_failover"]
        uplink = observed.get("uplink")
        if uplink is not None:
            payload["uplink"] = uplink
        else:
            payload.pop("uplink", None)
        if observed.get("uptime_stats"):
            payload["uptime_stats"] = observed["uptime_stats"]
    if data.get("wan_health"):
        stats = payload.get("uptime_stats", {}) | data.get("wan_health_durations", {})
        payload["uptime_stats"] = project_wan_quality(stats, data["wan_health"])
    if "dhcp_leases" in data:
        payload["ipv4_active_leases"] = [
            {key: value for key, value in lease.items() if key != "ifname"}
            for lease in data["dhcp_leases"]
        ]
    return payload
