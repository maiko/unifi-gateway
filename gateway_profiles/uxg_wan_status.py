"""Project observed WAN route durations and measured verification probes."""


WAN_GROUPS = {"eth0": "WAN", "eth2": "WAN2"}
_MAX_OBSERVATION_GAP = 60


def project_wan_durations(availability, links, previous, *, now, groups=WAN_GROUPS):
    """Count from the first uninterrupted observation of each actual route state."""
    if availability is None:
        return {}, {}
    counters, observed = {}, {}
    for interface, group in groups.items():
        link = links.get(interface, {}).get("up")
        route = availability.get(interface)
        if type(link) is not bool or type(route) is not bool:
            continue
        working = link and route
        started = now
        past = previous.get(interface)
        if past is not None and past[0] == working and 0 <= now - past[2] <= _MAX_OBSERVATION_GAP:
            started = past[1]
        elapsed = int(now - started)
        observed[interface] = (working, started, now)
        counters[group] = {"uptime": elapsed if working else 0, "downtime": 0 if working else elapsed}
    return counters, observed


def project_wan_quality(stats, observations):
    """Keep measured loss and unavailable telemetry distinct on the wire."""
    result = {group: values.copy() for group, values in stats.items()}
    for group, observation in observations.items():
        if observation is None and group not in result:
            continue
        monitors = []
        if observation is not None:
            monitor = {
                "type": "icmp",
                "target": observation["target"],
                "availability": round(100 * observation["received"] / observation["sent"]),
            }
            if observation["latency_ms"] is not None:
                monitor["latency_average"] = round(observation["latency_ms"])
            monitors.append(monitor)
        result.setdefault(group, {})["alerting_monitors"] = monitors
    return result
