"""The bridge verifies replies from the dedicated router receipt key."""

from copy import deepcopy
from ipaddress import ip_interface
import json
from unittest.mock import Mock
import pytest

from backends.vyos import VyOSReadError
from provisioners.vyos_shadow_binding import ShadowManagementIdentity


IDENTITY = ShadowManagementIdentity("02:00:00:00:00:01", "https://192.0.2.15:8443", "SHA256:" + "A" * 43)
BOOT = "158dd3a3-dc93-4ae3-94b1-489e4f6ecc6d"
TRANSACTION = "6303a0a3-d505-4782-93e1-0639a40dd670"
COMMIT = "e" * 64
CANDIDATE = {"boot_id": BOOT, "sha256": "a" * 64, "generation": "b" * 64, "config_sha256": COMMIT}
RECEIPT = {"id": "c" * 64, "sha256": CANDIDATE["sha256"], "transaction": TRANSACTION, "config_sha256": COMMIT}
ARGV = ["/usr/bin/ssh", "--", "192.0.2.15", "/bin/false"]
INSTALLED = {"receipt": RECEIPT, "generation": CANDIDATE["generation"]}
FENCED = {"receipt": None, "generation": "d" * 64}
SAVED_SHA256 = "4" * 64
RUNNING_TREE = {"interfaces": {"ethernet": {"eth3": {"address": ["192.0.2.2/24", "192.0.2.9/24"]}}}}
SAVED_TREE = {"interfaces": {"ethernet": {"eth3": {"address": ["192.0.2.1/24", "192.0.2.9/24", "192.0.2.2/24"]}}}}
OBSERVATION = {"boot_id": BOOT, "saved_sha256": SAVED_SHA256, "running": RUNNING_TREE, "saved": SAVED_TREE}


@pytest.fixture
def transport(monkeypatch):
    from provisioners import vyos_shadow_receipt as module

    calls = []
    responses = []

    def mock_ssh(host, port, user, key, pin):
        assert (host, port, user, key, pin) == ("192.0.2.15", 22, "vyos", "receipt-key", "host-pin")
        return ARGV

    def invoke(argv, *, reader, limit, stdin, timeout):
        request = json.load(stdin)
        assert argv == ARGV and reader == "VyOS Shadow receipt SSH" and 0 < timeout <= 22
        assert limit == (256 * 1024 if request["op"] == "observe" else 4096)
        calls.append(request)
        response = responses.pop(0)
        if isinstance(response, BaseException):
            raise response
        return (response if isinstance(response, bytes) else json.dumps(response).encode()), 0

    monkeypatch.setattr(module, "vyos_ssh_command", mock_ssh)
    monkeypatch.setattr(module, "vyos_ssh_host_fingerprint", lambda *args: IDENTITY.ssh_host_key)
    monkeypatch.setattr(module, "_run_helper", invoke)
    client = module.ShadowReceiptClient(IDENTITY, port=22, user="vyos", key_file="receipt-key", known_hosts_file="host-pin")
    return client, calls, responses


@pytest.fixture
def stock_backend(monkeypatch):
    from provisioners import vyos_shadow_receipt as module

    backend = Mock(management_origin=IDENTITY.https_origin)
    backend.read_config.return_value = None
    backend.show_kernel_interfaces.return_value = [
        {"ifname": "eth2", "addr_info": [{"family": "inet", "local": "169.254.254.2", "prefixlen": 24}]},
        {"ifname": "eth3", "addr_info": [
            {"family": "inet", "local": "192.0.2.2", "prefixlen": 24},
            {"family": "inet6", "local": "fe80::1", "prefixlen": 64},
        ]},
        {"ifname": "eth4", "addr_info": []},
    ]
    role = Mock(return_value="fault")
    monkeypatch.setattr(module, "observe_shadow_role", role, raising=False)
    return backend, role


def test_receipt_admission_requires_an_explicit_boolean_success_reply(transport):
    from provisioners.vyos_shadow_receipt import ShadowReceiptError

    client, calls, responses = transport
    paths = (("interfaces", "bridge", "br0"),)
    responses.extend([{"ready": True}, {"ready": 1}])
    client.verify_admission(boot_id=BOOT, config_sha256=COMMIT, required_paths=paths)
    assert calls == [{"op": "check-admission", "boot_id": BOOT, "config_sha256": COMMIT,
                      "required_paths": [list(paths[0])]}]
    with pytest.raises(ShadowReceiptError, match="admission"):
        client.verify_admission(boot_id=BOOT, config_sha256=COMMIT, required_paths=paths)


@pytest.mark.parametrize("change", [{}, {"received": 1}, {"received": True}, {"interface": "eth4"},
                                    {"peer": "192.0.2.5"}, {"version": 1}])
def test_vrrp_readiness_checks_the_pinned_router_and_expected_reply(transport, change):
    from provisioners.vyos_shadow_receipt import ShadowReceiptError

    client, requests, responses = transport
    responses.append({"interface": "eth3", "local": "192.0.2.3", "peer": "192.0.2.2",
                      "version": 2, "received": 2} | change)
    args = dict(boot_id=BOOT, config_sha256=COMMIT, generation=CANDIDATE["generation"],
                interface="eth3", local="192.0.2.3", peer="192.0.2.2")
    if change and not (type(change.get("received")) is int and change["received"] == 1):
        with pytest.raises(ShadowReceiptError, match="mismatched Shadow VRRP"):
            client.observe_standby_vrrp(**args)
    else:
        assert client.observe_standby_vrrp(**args) is (not change)
    assert requests == [{"op": "observe-vrrp", "boot_id": BOOT, "config_sha256": COMMIT,
                         "generation": CANDIDATE["generation"]}]


def test_staged_observation_brackets_both_live_reads_and_retains_the_ordered_preimage(transport, stock_backend):
    client, requests, responses = transport
    backend, role = stock_backend
    responses.extend([OBSERVATION, deepcopy(OBSERVATION)])
    events = []
    kernel = backend.show_kernel_interfaces.return_value

    def proof(*, phase):
        assert phase == "staged"
        events.append(("proof", len(requests)))
        return COMMIT

    backend.show_kernel_interfaces.side_effect = lambda: events.append(("kernel", len(requests))) or kernel
    role.side_effect = lambda _: events.append(("role", len(requests))) or "fault"

    observed = client.observe_handoff_state(backend, proof, phase="staged", expected_boot_id=BOOT,
                                            expected_saved_sha256=SAVED_SHA256)

    assert requests == [{"op": "observe"}, {"op": "observe"}]
    assert events == [("proof", 0), ("kernel", 1), ("role", 1), ("proof", 2)]
    assert (observed.boot_id, observed.saved_sha256, observed.config_sha256, observed.role) == (
        BOOT, SAVED_SHA256, COMMIT, "fault",
    )
    assert observed.state.running == RUNNING_TREE and observed.state.saved == SAVED_TREE
    assert observed.state.projected
    assert observed.phase == "staged"
    assert observed.state.kernel == {
        "eth2": (ip_interface("169.254.254.2/24"),),
        "eth3": (ip_interface("192.0.2.2/24"), ip_interface("fe80::1/64")),
        "eth4": (),
    }


def test_saved_observation_binds_the_boot_and_fingerprint_from_the_same_proof(transport, stock_backend):
    from provisioners.vyos_shadow_receipt import ShadowReceiptError

    client, _, responses = transport
    backend, _ = stock_backend
    settled = OBSERVATION | {"running": SAVED_TREE}
    responses.extend([settled, settled])
    proof = Mock(return_value=(BOOT, COMMIT))
    observed = client.observe_handoff_state(backend, proof, phase="saved_commit", expected_boot_id=BOOT)
    assert observed.config_sha256 == COMMIT and observed.phase == "saved_commit"
    assert [call.kwargs for call in proof.call_args_list] == [{"phase": "saved_commit"}] * 2

    proof.return_value = (TRANSACTION, COMMIT)
    with pytest.raises(ShadowReceiptError, match="boot"):
        client.observe_handoff_state(backend, proof, phase="saved_commit", expected_boot_id=BOOT)


@pytest.mark.parametrize(("configured", "effective"), [
    (None, "reboot"), ({"action": "reboot"}, "reboot"), ({"action": "reload"}, "reload"), ({"action": "other"}, None),
])
def test_handoff_observes_the_effective_stock_rollback_action(transport, stock_backend, configured, effective):
    from provisioners.vyos_shadow_receipt import ShadowReceiptError

    client, _, responses = transport
    backend, _ = stock_backend
    backend.read_config.return_value = configured
    settled = OBSERVATION | {"running": SAVED_TREE}
    responses.extend([settled, settled])
    arguments = {"phase": "saved_commit", "expected_boot_id": BOOT}
    proof = Mock(return_value=(BOOT, COMMIT))
    if effective is None:
        with pytest.raises(ShadowReceiptError, match="rollback action"):
            client.observe_handoff_state(backend, proof, **arguments)
    else:
        assert client.observe_handoff_state(backend, proof, **arguments).rollback_action == effective
    backend.read_config.assert_called_once_with(["system", "config-management", "commit-confirm"])


def test_saved_observation_refuses_lan_address_order_drift_after_reload(transport, stock_backend):
    from provisioners.vyos_shadow_receipt import ShadowReceiptError

    client, _, responses = transport
    backend, _ = stock_backend
    reloaded = {"interfaces": {"ethernet": {"eth3": {"address": ["192.0.2.9/24", "192.0.2.2/24", "192.0.2.1/24"]}}}}
    responses.append(OBSERVATION | {"running": reloaded})
    with pytest.raises(ShadowReceiptError, match="Running and saved Shadow configurations disagree"):
        client.observe_handoff_state(backend, Mock(return_value=(BOOT, COMMIT)),
                                     phase="saved_commit", expected_boot_id=BOOT)


@pytest.mark.parametrize(("responses_to_send", "proofs", "reason"), [
    ([OBSERVATION | {"boot_id": TRANSACTION}], [COMMIT], "boot"),
    ([OBSERVATION | {"saved_sha256": "5" * 64}], [COMMIT], "saved configuration"),
    ([OBSERVATION, OBSERVATION | {"saved": RUNNING_TREE}], [COMMIT, COMMIT], "changed"),
    ([OBSERVATION, OBSERVATION], [COMMIT, "f" * 64], "changed"),
    ([OBSERVATION | {"running": RUNNING_TREE | {"system": {}}}], [COMMIT], "projection"),
])
def test_staged_observation_rejects_evidence_drift(transport, stock_backend, responses_to_send, proofs, reason):
    from provisioners.vyos_shadow_receipt import ShadowReceiptError

    client, _, responses = transport
    backend, _ = stock_backend
    responses.extend(responses_to_send)
    with pytest.raises(ShadowReceiptError, match=reason):
        client.observe_handoff_state(backend, Mock(side_effect=proofs), phase="staged", expected_boot_id=BOOT,
                                     expected_saved_sha256=SAVED_SHA256)


def test_handoff_observation_requires_the_enrolled_https_origin_and_journaled_saved_preimage(transport, stock_backend):
    client, requests, _ = transport
    backend, _ = stock_backend
    proof = Mock()
    with pytest.raises(ValueError, match="saved configuration"):
        client.observe_handoff_state(backend, proof, phase="staged", expected_boot_id=BOOT)
    backend.management_origin = "https://192.0.2.15"
    with pytest.raises(ValueError, match="management origin"):
        client.observe_handoff_state(backend, proof, phase="saved_commit", expected_boot_id=BOOT)
    assert requests == [] and not proof.called


def test_staged_reboot_observation_requires_the_exact_timer_proof(transport, stock_backend):
    from provisioners.vyos_shadow_receipt import ShadowReceiptError

    client, _, responses = transport
    backend, _ = stock_backend
    responses.extend([OBSERVATION, OBSERVATION])
    proof = Mock(return_value=COMMIT)
    observed = client.observe_handoff_state(backend, proof, phase="staged_reboot", expected_boot_id=BOOT,
                                           expected_saved_sha256=SAVED_SHA256)
    assert observed.phase == "staged_reboot"
    assert [call.kwargs for call in proof.call_args_list] == [{"phase": "staged_reboot"}] * 2
    backend.read_config.return_value = {"action": "reload"}
    responses.append(OBSERVATION)
    with pytest.raises(ShadowReceiptError, match="disagrees"):
        client.observe_handoff_state(backend, proof, phase="staged_reboot", expected_boot_id=BOOT,
                                     expected_saved_sha256=SAVED_SHA256)


def test_completed_observation_keeps_original_saved_tree_until_candidate_is_saved(transport, stock_backend):
    client, _, responses = transport
    backend, _ = stock_backend
    responses.extend([OBSERVATION, OBSERVATION])
    proof = Mock(return_value=COMMIT)
    observed = client.observe_handoff_state(backend, proof, phase="completed", expected_boot_id=BOOT)
    assert observed.phase == "completed" and observed.config_sha256 == COMMIT
    assert observed.state.running == RUNNING_TREE and observed.state.saved == SAVED_TREE
    assert observed.saved_sha256 == SAVED_SHA256
    assert [call.kwargs for call in proof.call_args_list] == [{"phase": "completed"}] * 2


def test_client_checks_publication_and_fences_the_exact_installed_receipt(transport):
    client, calls, responses = transport
    responses.extend([CANDIDATE, INSTALLED, INSTALLED, FENCED])
    candidate = client.candidate(expected_boot_id=BOOT, expected_config_sha256=COMMIT)
    receipt = client.publish(TRANSACTION, candidate)
    assert (receipt.id, receipt.sha256, receipt.transaction, receipt.config_sha256) == tuple(RECEIPT.values())
    observed = client.status()
    assert observed.receipt == receipt and observed.generation == candidate.generation
    client.revoke(receipt.id)
    assert calls == [
        {"op": "candidate"}, {"op": "publish", "transaction": TRANSACTION, **CANDIDATE},
        {"op": "status"}, {"op": "revoke", "receipt_id": RECEIPT["id"]},
    ]


def test_write_timeout_requires_status_instead_of_repeating_the_request(transport):
    from provisioners.vyos_shadow_receipt import ShadowReceiptError

    client, calls, responses = transport
    responses.extend([CANDIDATE, VyOSReadError("timed out"), INSTALLED])
    candidate = client.candidate(expected_boot_id=BOOT, expected_config_sha256=COMMIT)
    with pytest.raises(ShadowReceiptError):
        client.publish(TRANSACTION, candidate)
    assert client.status().receipt.id == RECEIPT["id"]
    assert [call["op"] for call in calls] == ["candidate", "publish", "status"]


def test_client_rejects_another_boot_or_unrelated_publication(transport):
    from provisioners.vyos_shadow_receipt import ShadowReceiptError

    client, _, responses = transport
    responses.extend([CANDIDATE | {"boot_id": TRANSACTION}, CANDIDATE,
                      INSTALLED | {"receipt": RECEIPT | {"sha256": "d" * 64}},
                      b'{"receipt":null,"receipt":null}'])
    with pytest.raises(ShadowReceiptError):
        client.candidate(expected_boot_id=BOOT, expected_config_sha256=COMMIT)
    candidate = client.candidate(expected_boot_id=BOOT, expected_config_sha256=COMMIT)
    with pytest.raises(ShadowReceiptError):
        client.publish(TRANSACTION, candidate)
    with pytest.raises(ShadowReceiptError):
        client.status()


def test_client_rejects_another_saved_commit_on_the_same_boot(transport):
    from provisioners.vyos_shadow_receipt import ShadowReceiptError

    client, _, responses = transport
    responses.extend([CANDIDATE | {"config_sha256": "f" * 64}, CANDIDATE,
                      INSTALLED | {"receipt": RECEIPT | {"config_sha256": None}}])
    with pytest.raises(ShadowReceiptError, match="commit changed"):
        client.candidate(expected_boot_id=BOOT, expected_config_sha256=COMMIT)
    candidate = client.candidate(expected_boot_id=BOOT, expected_config_sha256=COMMIT)
    with pytest.raises(ShadowReceiptError, match="publication"):
        client.publish(TRANSACTION, candidate)


def test_fencing_requires_a_new_empty_generation(transport):
    from provisioners.vyos_shadow_receipt import ShadowReceiptError

    client, calls, responses = transport
    responses.extend([INSTALLED, FENCED | {"generation": CANDIDATE["generation"]}, FENCED])
    for _ in range(2):
        with pytest.raises(ShadowReceiptError):
            client.fence(CANDIDATE["generation"])
    fenced = client.fence(CANDIDATE["generation"])
    assert fenced.generation == FENCED["generation"] and fenced.receipt is None
    assert calls == [{"op": "fence", "generation": CANDIDATE["generation"]}] * 3


def test_receipt_key_requires_the_enrolled_router_ssh_pin(monkeypatch):
    from provisioners import vyos_shadow_receipt as module

    monkeypatch.setattr(module, "vyos_ssh_host_fingerprint", lambda *args: "SHA256:" + "B" * 43)
    with pytest.raises(ValueError, match="enrolled.*host key"):
        module.ShadowReceiptClient(IDENTITY, port=22, user="vyos", key_file="receipt-key", known_hosts_file="other-pin")
