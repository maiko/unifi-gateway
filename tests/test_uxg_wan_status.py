from gateway_profiles.uxg_wan_status import project_wan_durations


LINKS = {"eth0": {"up": True}, "eth2": {"up": True}}


def test_wan_durations_follow_observed_routes_across_carrier_up_failure():
    both = {"eth0": True, "eth2": True}
    counters, history = project_wan_durations(both, LINKS, {}, now=10)
    assert counters == {name: {"uptime": 0, "downtime": 0} for name in ("WAN", "WAN2")}
    backup_only = {"eth0": False, "eth2": True}
    _, history = project_wan_durations(backup_only, LINKS, history, now=20)
    counters, history = project_wan_durations(backup_only, LINKS, history, now=28)
    assert counters == {"WAN": {"uptime": 0, "downtime": 8}, "WAN2": {"uptime": 18, "downtime": 0}}
    counters, _ = project_wan_durations(both, LINKS, history, now=40)
    assert counters["WAN"] == {"uptime": 0, "downtime": 0}


def test_wan_health_never_counts_through_missing_or_stale_observations():
    both = {"eth0": True, "eth2": True}
    _, history = project_wan_durations(both, LINKS, {}, now=10)
    counters, history = project_wan_durations(both, {"eth2": {"up": True}}, history, now=16)
    assert counters == {"WAN2": {"uptime": 6, "downtime": 0}}
    counters, history = project_wan_durations(both, LINKS, history, now=90)
    assert counters["WAN"] == counters["WAN2"] == {"uptime": 0, "downtime": 0}
    assert project_wan_durations(None, LINKS, history, now=95) == ({}, {})
