import json
import sys
from dataclasses import replace

import pytest

from inspection.vyos_queue import BridgeEndpoint, EngineIdentity, QueuePlan, QueueScope

BOOT = "cc74de35-40e5-4777-a4ce-a2eb32f55d6e"
NS = 4026531840
PID = 98906
START = 257239
PORT_ID = 421
INODE = 207423
QUEUE = 41110
NETLINK_HEADER = "sk Eth Pid Groups Rmem Wmem Dump Locks Drops Inode\n"


@pytest.fixture
def api():
    from inspection import vyos_readback

    return vyos_readback


@pytest.fixture
def plan():
    return QueuePlan(
        QueueScope(
            BridgeEndpoint("br110", "eth3.110", "192.168.110.1/24", "192.168.110.2"),
            BridgeEndpoint("br120", "eth3.120", "192.168.120.1/24", "192.168.120.2"),
            18743,
            QUEUE,
        )
    )


def nft_rows(plan=None, handle=108):
    rows = [
        {"metainfo": {"version": "1.0.9", "json_schema_version": 1}},
        {"table": {"family": "ip", "name": "vyos_filter", "handle": 1}},
        {
            "chain": {
                "family": "ip",
                "table": "vyos_filter",
                "name": "VYOS_FORWARD_filter",
                "type": "filter",
                "hook": "forward",
                "prio": 0,
                "policy": "accept",
            }
        },
        {
            "rule": {
                "family": "ip",
                "table": "vyos_filter",
                "chain": "VYOS_FORWARD_filter",
                "expr": [{"accept": None}],
                "comment": "secret operator comment",
            }
        },
    ]
    if plan is not None:
        for index, command in enumerate(plan.creation_batch()["nftables"]):
            [entry] = command.values()
            [definition] = entry.values()
            definition["handle"] = handle if index == 0 else index
            if "rule" in entry:
                definition["expr"][-1]["queue"]["flags"] = "bypass"
            rows.append(entry)
    return {"nftables": rows}


def put(base, name, contents):
    target = base / name
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(contents)
    return target


def link(base, name, destination):
    target = base / name
    target.parent.mkdir(parents=True, exist_ok=True)
    target.unlink(missing_ok=True)
    target.symlink_to(destination)
    return target


def process_stat(pid=PID, start=START, comm="suricata (worker)", state="S"):
    return f"{pid} ({comm}) {state} " + "0 " * 18 + f"{start} 0 0\n"


@pytest.fixture
def synthetic(tmp_path, api, monkeypatch):
    proc = tmp_path / "proc"
    sysfs = tmp_path / "sys"
    (sysfs / "module").mkdir(parents=True)
    put(proc, "sys/kernel/random/boot_id", BOOT + "\n")
    link(proc, "self/ns/net", f"net:[{NS}]")
    observed = {"ruleset": nft_rows(), "commands": []}

    def run(argv, *, timeout, limit):
        assert 0 < timeout <= 5 and limit <= 4 * 1024 * 1024
        observed["commands"].append(tuple(argv))
        if tuple(argv) == ("/usr/sbin/nft", "-j", "-s", "list", "ruleset"):
            return json.dumps(observed["ruleset"]).encode()
        if tuple(argv) == ("/usr/sbin/modinfo", "-F", "filename", "nfnetlink_queue"):
            return b"/lib/modules/6.18.64-1-vyos/kernel/net/netfilter/nfnetlink_queue.ko.xz\n"
        pytest.fail("unexpected command operation")

    monkeypatch.setattr(api, "_run_bounded", run)
    reader = api.LinuxInspectionReader(proc_root=proc, sys_root=sysfs)
    return reader, proc, sysfs, observed


def active(proc):
    put(
        proc, "net/netfilter/nfnetlink_queue", f"{QUEUE} {PORT_ID} 0 2 65531 0 0 23 1\n"
    )
    put(
        proc,
        "net/netlink",
        NETLINK_HEADER
        + f"0000000000000000 12 {PORT_ID} 00000000 0 0 0 2 0 {INODE}\n"
        + f"0000000000000000 0 {PORT_ID} 00000000 0 0 0 2 0 12\n",
    )
    put(proc, f"{PID}/stat", process_stat())
    link(proc, f"{PID}/ns/net", f"net:[{NS}]")
    link(proc, f"{PID}/exe", "/usr/bin/suricata")
    link(proc, f"{PID}/fd/6", f"socket:[{INODE}]")


def engine_claim(api):
    return api.EngineClaim(api.KernelIdentity(BOOT, NS), EngineIdentity(PID, START))


def test_stock_inventory_keeps_raw_policy_out_of_repr_and_uses_owned_table_handle(
    api, synthetic, plan
):
    reader, _, _, fake = synthetic
    assert reader.read_inventory().owned_hook(plan, claim=None) is None
    fake["ruleset"] = nft_rows(plan)
    inventory = reader.read_inventory()

    assert "secret operator comment" not in repr(inventory)
    assert inventory.kernel == api.KernelIdentity(BOOT, NS)
    assert len(inventory.digest) == 64
    receipt = api.HookClaim(inventory.kernel, "unifi-inspection", 108)
    assert inventory.owned_hook(plan, claim=receipt).handle == 108
    with pytest.raises(api.ForeignInspectionResource):
        inventory.owned_hook(plan, claim=None)
    with pytest.raises(api.ForeignInspectionResource):
        inventory.owned_hook(plan, claim=replace(receipt, handle=109))
    with pytest.raises(api.ForeignInspectionResource):
        inventory.owned_hook(
            plan, claim=replace(receipt, kernel=api.KernelIdentity(BOOT, 99))
        )


def test_exact_table_readback_refuses_drift_even_when_handle_is_owned(
    api, synthetic, plan
):
    reader, _, _, fake = synthetic
    fake["ruleset"] = nft_rows(plan)
    fake["ruleset"]["nftables"][-1]["rule"]["expr"].insert(-1, {"drop": None})
    inventory = reader.read_inventory()
    with pytest.raises(api.ForeignInspectionResource, match="shape"):
        inventory.owned_hook(
            plan, claim=api.HookClaim(inventory.kernel, "unifi-inspection", 108)
        )


def test_stock_proc_ownership_uses_netlink_port_to_inode_and_exact_suricata_process(
    api, synthetic
):
    reader, proc, _, _ = synthetic
    active(proc)

    observed = reader.read_listener(QUEUE, claim=engine_claim(api))

    assert observed.binding.port_id == PORT_ID
    assert observed.peer.socket_inode == INODE
    assert observed.peer.owner == EngineIdentity(PID, START)
    assert observed.peer.port_id != observed.peer.owner.pid
    assert observed.binding.packet_sequence == 23


@pytest.mark.parametrize(
    "case", ["claim-missing", "start-time", "netns", "executable", "inode", "boot"]
)
def test_foreign_queue_binding_is_rejected(api, synthetic, case):
    reader, proc, _, _ = synthetic
    active(proc)
    claim = engine_claim(api)
    if case == "claim-missing":
        claim = None
    if case == "start-time":
        put(proc, f"{PID}/stat", process_stat(start=START + 1))
    if case == "netns":
        link(proc, f"{PID}/ns/net", "net:[100]")
    if case == "executable":
        link(proc, f"{PID}/exe", "/tmp/suricata")
    if case == "inode":
        link(proc, f"{PID}/fd/6", "socket:[777]")
    if case == "boot":
        claim = replace(
            claim, kernel=api.KernelIdentity("00000000-0000-4000-8000-000000000001", NS)
        )
    with pytest.raises(api.ForeignInspectionResource):
        reader.read_listener(QUEUE, claim=claim)


@pytest.mark.parametrize("case", ["duplicate-port", "bad-stat", "missing-queue-file"])
def test_unavailable_evidence_is_distinct_from_foreign_listener(api, synthetic, case):
    reader, proc, sysfs, _ = synthetic
    active(proc)
    if case == "duplicate-port":
        path = proc / "net/netlink"
        path.write_text(
            path.read_text() + f"0000000000000000 12 {PORT_ID} 00000000 0 0 0 2 0 888\n"
        )
    if case == "bad-stat":
        put(proc, f"{PID}/stat", "malformed\n")
    if case == "missing-queue-file":
        (proc / "net/netfilter/nfnetlink_queue").unlink()
        (sysfs / "module/nfnetlink_queue").mkdir()
    with pytest.raises(api.ReadbackUnavailable):
        reader.read_listener(QUEUE, claim=engine_claim(api))


def test_missing_proc_queue_means_absence_only_for_a_verified_unloaded_module(
    api, synthetic, monkeypatch
):
    reader, _, _, fake = synthetic
    assert reader.read_listener(QUEUE) is None
    assert fake["commands"] == [
        ("/usr/sbin/modinfo", "-F", "filename", "nfnetlink_queue")
    ]

    monkeypatch.setattr(api, "_run_bounded", lambda *args, **kwargs: b"(builtin)\n")
    with pytest.raises(api.ReadbackUnavailable):
        reader.read_listener(QUEUE)


def test_nfqueue_readback_discards_a_racing_socket_replacement(
    api, synthetic, monkeypatch
):
    reader, proc, _, _ = synthetic
    active(proc)
    original = reader._process_identity
    calls = 0

    def identity(pid):
        nonlocal calls
        calls += 1
        if calls == 2:
            put(
                proc,
                "net/netfilter/nfnetlink_queue",
                f"{QUEUE} 444 0 2 65531 0 0 0 1\n",
            )
        return original(pid)

    monkeypatch.setattr(reader, "_process_identity", identity)
    with pytest.raises(api.ReadbackUnavailable, match="changed"):
        reader.read_listener(QUEUE, claim=engine_claim(api))


def test_subprocess_output_and_timeout_are_bounded_and_errors_are_redacted(api):
    with pytest.raises(api.ReadbackUnavailable, match="output limit") as overflow:
        api._run_bounded(
            [sys.executable, "-c", "print('secret-text' * 1000)"], timeout=1, limit=100
        )
    assert "secret-text" not in str(overflow.value)

    with pytest.raises(api.ReadbackUnavailable, match="timed out"):
        api._run_bounded(
            [sys.executable, "-c", "import time; time.sleep(10)"],
            timeout=0.05,
            limit=100,
        )

    with pytest.raises(api.ReadbackUnavailable, match="failed") as failure:
        api._run_bounded(
            [sys.executable, "-c", "import sys; sys.exit('secret stderr')"],
            timeout=1,
            limit=100,
        )
    assert "secret stderr" not in str(failure.value)


def test_inventory_digest_cannot_be_detached_from_the_read_snapshot(synthetic):
    reader, _, _, _ = synthetic
    first = reader.read_inventory()
    changed = first.snapshot
    changed["nftables"][-1]["rule"].clear()
    assert first.snapshot["nftables"][-1]["rule"]
    assert first.digest == reader.read_inventory().digest


def test_cli_refuses_reserved_table_without_receipt(
    api, synthetic, plan, monkeypatch, capsys
):
    reader, _, _, fake = synthetic
    fake["ruleset"] = nft_rows(plan)
    monkeypatch.setattr(api, "LinuxInspectionReader", lambda: reader)

    assert api.main(["--queue", str(QUEUE)]) == 1
    stdout, stderr = capsys.readouterr()
    assert stdout == ""
    assert "ownership receipt" in stderr
    assert "secret operator comment" not in stderr
