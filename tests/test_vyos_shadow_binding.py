"""Match the controller's adopted Shadow pair to distinct prepared routers."""

from base64 import b64encode
from dataclasses import replace

import pytest


SITE = "b6d635a3-7f54-42cf-a3a4-bb9a387812a1"
PRIMARY = "02:42:00:12:00:01"
STANDBY = "02:42:00:12:00:02"
PAIR = {"primary_mac": PRIMARY, "secondary_mac": STANDBY}
DEVICES = [
    {"_id": "b122ab39-4623-4fb4-983a-eecfa665f639", "site_id": SITE, "mac": PRIMARY,
     "adopted": True, "model": "UXGENT", "version": "6.0.17", "cfgversion": "new-primary",
     "known_cfgversion": "applied-primary"},
    {"_id": "3089b24e-f89d-4dc7-baab-de048b3e519e", "site_id": SITE, "mac": STANDBY,
     "adopted": True, "model": "UXGENT", "version": "6.0.17", "cfgversion": "new-standby",
     "known_cfgversion": "applied-standby"},
]


def _fingerprint(value):
    return "SHA256:" + b64encode(bytes([value]) * 32).decode("ascii").rstrip("=")


def _fixture():
    from provisioners.vyos_shadow_binding import ShadowManagementIdentity, bind_shadow_enrollments

    return bind_shadow_enrollments, (
        ShadowManagementIdentity(PRIMARY, "https://127.0.0.1:39443", _fingerprint(1)),
        ShadowManagementIdentity(STANDBY, "https://127.0.0.1:39444", _fingerprint(2)),
    )


@pytest.mark.parametrize("change", [None, "head", "roles", "state", "foreign-site", "port"])
def test_controller_reader_binds_a_stable_pair_from_only_the_configured_site(tmp_path, monkeypatch, change):
    from unittest.mock import Mock
    from gateway_profiles import uxg_enterprise_shadow_controller as controller

    _, routers = _fixture()
    group = PAIR | {"state": "IN_PROGRESS", "interface_name": "eth1"}
    next_group = group.copy()
    following = [row.copy() for row in DEVICES]
    if change == "head":
        following[0]["cfgversion"] = "other-head"
    elif change == "roles":
        next_group["primary_mac"], next_group["secondary_mac"] = STANDBY, PRIMARY
    elif change == "state":
        next_group["state"] = "SETUP_COMPLETED"
    elif change == "foreign-site":
        following[0]["site_id"] = "other-site"
    elif change == "port":
        next_group["interface_name"] = "eth2"

    session = tmp_path / "session"
    session.write_text("# Netscape HTTP Cookie File\n")
    verify_tls = Mock()
    monkeypatch.setattr(controller.ssl, "SSLContext", verify_tls)
    reader = controller.ShadowControllerReader(
        origin="https://controller.example:443", site="shadow-lab", site_id=SITE,
        ca_file="ca.pem", session_file=session,
    )
    paths = []
    responses = iter([group, {"meta": {"rc": "ok"}, "data": DEVICES},
                      next_group, {"meta": {"rc": "ok"}, "data": following}])

    def get(origin, path, *, opener):
        assert origin == "https://controller.example:443" and opener is not None
        paths.append(path)
        return next(responses)

    monkeypatch.setattr(controller, "_read_json", get)
    if change is None:
        pair = reader.read_pair(routers=routers)
        assert pair.primary.desired_revision == DEVICES[0]["cfgversion"]
        assert pair.standby.desired_revision == DEVICES[1]["cfgversion"]
        assert paths == ["/proxy/network/v2/api/site/shadow-lab/shadowmode/managed/group",
                         "/proxy/network/api/s/shadow-lab/stat/device"] * 2
        verify_tls.assert_called_once_with(controller.ssl.PROTOCOL_TLS_CLIENT)
        verify_tls.return_value.load_verify_locations.assert_called_once_with(cafile="ca.pem")
    else:
        with pytest.raises(ValueError):
            reader.read_pair(routers=routers)


def test_pairs_exact_same_site_enterprise_enrollments_with_distinct_management_endpoints():
    bind, routers = _fixture()
    bound = bind(site_id=SITE, pair=PAIR, inventory=DEVICES[::-1], routers=routers)

    assert bound.site_id == SITE
    assert bound.firmware == "6.0.17"
    assert bound.primary.device_id == DEVICES[0]["_id"] and bound.primary.management == routers[0]
    assert bound.standby.device_id == DEVICES[1]["_id"] and bound.standby.management == routers[1]
    assert (bound.primary.desired_revision, bound.standby.desired_revision) == ("new-primary", "new-standby")


@pytest.mark.parametrize("change", [None, "pending", "stale", "wrong-role", "foreign-site", "wrong-version",
                                    "competing-candidate", "drift", "in-use"])
def test_primary_admission_read_binds_converged_enrollment_before_standby_adoption(tmp_path, monkeypatch, change):
    from unittest.mock import Mock
    from gateway_profiles import uxg_enterprise_shadow_controller as controller

    _, (primary, _) = _fixture()
    group = {"primary_mac": PRIMARY, "state": "NO_SHADOW_CANDIDATE_ADOPTED", "interface_name": "eth1"}
    primary_row = DEVICES[0] | {"known_cfgversion": "new-primary"}
    second_group, second_row = group.copy(), primary_row.copy()
    if change == "pending":
        second_row["known_cfgversion"] = "older"
    elif change == "stale":
        second_row.update(known_cfgversion="different", cfgversion="different")
    elif change == "wrong-role":
        second_group["primary_mac"] = STANDBY
    elif change == "foreign-site":
        second_row["site_id"] = "foreign"
    elif change == "wrong-version":
        second_row["version"] = "6.0.17-lab"
    elif change == "competing-candidate":
        second_group["secondary_mac"] = STANDBY
    elif change == "drift":
        second_row["_id"] = "re-enrolled"
    elif change == "in-use":
        second_group["waitingForManagementInterface"] = True
    read = Mock(side_effect=[group, {"meta": {"rc": "ok"}, "data": [primary_row]},
                             second_group, {"meta": {"rc": "ok"}, "data": [second_row]}])
    monkeypatch.setattr(controller.ssl, "SSLContext", Mock())
    monkeypatch.setattr(controller, "_read_json", read)
    session = tmp_path / "session"
    session.write_text("# Netscape HTTP Cookie File\n", encoding="utf-8")
    reader = controller.ShadowControllerReader(
        origin="https://controller.example", site="lab", site_id=SITE, ca_file="ca.pem", session_file=session,
    )
    if change is None:
        verified = reader.read_primary_admission(router=primary, firmware="6.0.17", applied_revision="new-primary")
        assert verified.management == primary and verified.desired_revision == "new-primary"
        assert read.call_count == 4
    else:
        with pytest.raises(ValueError):
            reader.read_primary_admission(router=primary, firmware="6.0.17", applied_revision="new-primary")


@pytest.mark.parametrize(("state", "role", "foreign", "allowed"), [
    ("FIRMWARE_NOT_SUPPORTED", "primary", False, True),
    ("FIRMWARE_NOT_SUPPORTED", "standby", False, True),
    ("READY_FOR_SETUP", "standby", False, True),
    ("IN_PROGRESS", "primary", False, True),
    ("IN_PROGRESS", "standby", False, True),
    ("IN_PROGRESS", "standby", True, False),
    ("NO_SHADOW_CANDIDATE_ADOPTED", "primary", False, True),
    ("NO_SHADOW_CANDIDATE_ADOPTED", "standby", False, False),
    ("FIRMWARE_NOT_MATCHED", "primary", False, False),
])
def test_controller_advertisement_follows_the_bound_roles_without_waiting_for_existing_bits(
    monkeypatch, tmp_path, state, role, foreign, allowed,
):
    from unittest.mock import Mock
    from gateway_profiles import uxg_enterprise_shadow_controller as controller

    _, routers = _fixture()
    group = PAIR | {"state": state, "interface_name": "eth1"}
    inventory = DEVICES
    applied = "ordinary"
    if state == "NO_SHADOW_CANDIDATE_ADOPTED":
        group.pop("secondary_mac")
        applied = DEVICES[0]["cfgversion"]
        inventory = [DEVICES[0] | {"known_cfgversion": applied}]
    if foreign:
        group["secondary_mac"] = "02:00:00:00:00:03"
    session = tmp_path / "session"
    session.write_text("# Netscape HTTP Cookie File\n")
    monkeypatch.setattr(controller.ssl, "SSLContext", Mock())
    monkeypatch.setattr(controller, "_read_json", Mock(side_effect=[group, {"meta": {"rc": "ok"}, "data": inventory}] * 2))
    reader = controller.ShadowControllerReader(
        origin="https://controller.example", site="lab", site_id=SITE, ca_file="ca.pem", session_file=session,
    )
    arguments = {"routers": routers, "role": role, "firmware": "6.0.17", "applied_revision": applied}
    if allowed:
        binding = reader.read_capability_binding(**arguments)
        if state == "NO_SHADOW_CANDIDATE_ADOPTED":
            assert binding.management == routers[0] and binding.desired_revision == applied
        else:
            assert binding.state == state
    else:
        with pytest.raises(ValueError):
            reader.read_capability_binding(**arguments)


@pytest.mark.parametrize("update", (
    {"site_id": "foreign-site"}, {"adopted": 1}, {"model": "UXGPRO"}, {"version": "6.0.17-lab"},
    {"_id": DEVICES[0]["_id"]}, {"_id": ""}, {"mac": "ff:ff:ff:ff:ff:ff"},
    {"cfgversion": None}, {"cfgversion": ""}, {"cfgversion": 42},
))
def test_declines_mismatched_controller_enrollment(update):
    bind, routers = _fixture()
    with pytest.raises(ValueError):
        bind(site_id=SITE, pair=PAIR, inventory=[DEVICES[0], DEVICES[1] | update], routers=routers)


def test_declines_ambiguous_roles_and_colliding_management_identities():
    bind, routers = _fixture()
    for pair, rows, endpoints in (
        (PAIR, DEVICES + [DEVICES[0]], routers),
        ({"primary_mac": PRIMARY, "secondary_mac": PRIMARY}, DEVICES, routers),
        ({"primary_mac": STANDBY, "secondary_mac": PRIMARY}, DEVICES, routers),
        ({"primaryMac": PRIMARY, "secondaryMac": STANDBY}, DEVICES, routers),
        ({"primary_mac": PRIMARY, "state": "NO_SHADOW_CANDIDATE_ADOPTED"}, DEVICES[:1], routers),
        (PAIR, DEVICES, routers[::-1]),
        (PAIR, DEVICES, (routers[0], replace(routers[1], ssh_host_key=routers[0].ssh_host_key))),
        (PAIR, DEVICES, (routers[0], replace(routers[1], https_origin=routers[0].https_origin + "/"))),
        (PAIR, DEVICES, (replace(routers[0], https_origin="https://router.example"),
                          replace(routers[1], https_origin="https://ROUTER.example:443/"))),
    ):
        with pytest.raises(ValueError):
            bind(site_id=SITE, pair=pair, inventory=rows, routers=endpoints)


@pytest.mark.parametrize("origin", (
    "http://router.example", "https://user:secret@router.example", "https://router.example/api",
    "https://router.example:0", "https://router.example?", "https://router.example\n",
))
def test_declines_invalid_management_origins_without_echoing_values(origin):
    bind, routers = _fixture()
    with pytest.raises(ValueError, match="management") as error:
        bind(site_id=SITE, pair=PAIR, inventory=DEVICES, routers=(routers[0], replace(routers[1], https_origin=origin)))
    assert origin not in str(error.value)
