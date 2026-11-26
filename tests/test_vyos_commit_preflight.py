"""Exercise the stock preflight script against controlled CLI responses."""

from hashlib import sha256
import os
from pathlib import Path
from shlex import quote
import subprocess
import sys

import pytest


BOOT = "bb69c2fb-eaac-4d77-8492-6bbaa71579a5"
CONFIGURATION = "system { host-name router }\n"
FINGERPRINT = sha256(CONFIGURATION.encode()).hexdigest()
SAVED_REQUEST = "/bin/false uxg-commit-saved"
SCRIPT = Path(__file__).resolve().parents[1] / "scripts/vyos-restart-preflight.vbash"


@pytest.fixture
def preflight(tmp_path):
    # Replace only the OS dependencies. The request parser, session flow, and
    # proof checks all run from the actual helper under Bash.
    template = tmp_path / "script-template"
    template.write_text(r'''
trace() { printf '%s\n' "$*" >> "$TEST_TRACE"; }
systemctl() {
    if [[ $* == 'show --property=Unit --value commit-confirm.timer' ]]; then
        trace 'check timer target'
        printf '%s\n' "${TEST_TARGET:-commit-confirm.service}"
        return
    fi
    trace "check $5"
    local state=inactive
    [[ $5 != commit-confirm.timer || ${TEST_TIMER:-inactive} == inactive ]] || state=active
    printf 'LoadState=loaded\nActiveState=%s\nJob=\n' "$state"
}
busctl() {
    trace 'check rollback executable'
    printf 'a(sasbttttuii) 1 "/usr/bin/sg" 3 "sg" "vyattacfg" "/usr/bin/config-mgmt %s" false 0 0 0 0 0 0 0\n' "${TEST_ACTION:-revert}"
}
configure() { trace configure; configured=yes; }
show() { [[ $configured == yes ]] || return 1; trace show; printf '%s' "$TEST_CONFIGURATION"; }
compare() {
    [[ $configured == yes ]] || return 1
    trace "compare $1"
    if [[ -n ${TEST_COMPARISON:-} ]]; then
        printf '%s\n' "$TEST_COMPARISON"
    elif [[ $1 == saved ]]; then
        printf 'No changes between working and saved configurations.\n'
    elif [[ $1 == 0 ]]; then
        printf 'No changes between working and revision 0 configurations.\n'
    else
        return 1
    fi
}
run() {
    [[ $configured == yes && $* == 'show reboot' ]] || return 1
    trace 'show reboot'
    printf '%s\n' "${TEST_SHUTDOWN:-Reboot or poweroff is not scheduled}"
}
exit() { [[ $configured == yes ]] || return 1; trace exit; configured=no; }
''')
    saved = tmp_path / "config.boot"
    saved.write_text(CONFIGURATION)
    boot_id = tmp_path / "boot-id"
    boot_id.write_text(f"{BOOT}\n")
    trace = tmp_path / "trace"
    script = tmp_path / "preflight"
    dependencies = {
        "/usr/bin/systemctl": "systemctl",
        "/usr/bin/busctl": "busctl",
        "/usr/bin/id -gn": "printf vyattacfg",
        "/usr/bin/sha256sum": f"{quote(sys.executable)} -c " + quote(
            "import hashlib, sys; print(hashlib.sha256(sys.stdin.buffer.read()).hexdigest(), ' -')"
        ),
        "/opt/vyatta/etc/functions/script-template": quote(str(template)),
        "/config/config.boot": quote(str(saved)),
        "/proc/sys/kernel/random/boot_id": quote(str(boot_id)),
    }
    source = SCRIPT.read_text()
    for stock_dependency, replacement in dependencies.items():
        source = source.replace(stock_dependency, replacement)
    script.write_text(source)

    def invoke(request, *args, **overrides):
        trace.write_text("")
        result = subprocess.run(
            ["/bin/bash", str(script), *args],
            env={**os.environ, "SSH_ORIGINAL_COMMAND": request, "TEST_TRACE": str(trace),
                 "TEST_CONFIGURATION": CONFIGURATION, **overrides},
            capture_output=True, text=True, check=False,
        )
        return result, trace.read_text().splitlines()

    return invoke


def test_saved_commit_proof_fingerprints_and_compares_in_one_session(preflight):
    result, trace = preflight(SAVED_REQUEST)

    assert result.returncode == 0, result.stderr
    assert result.stdout == f"uxg-commit-saved {BOOT} {FINGERPRINT}\n"
    assert trace == [
        "check commit-confirm.timer", "check commit-confirm.service",
        "configure", "show", "compare saved", "show reboot", "exit",
        "check commit-confirm.timer", "check commit-confirm.service",
    ]


@pytest.mark.parametrize(
    ("overrides", "reason"),
    [
        ({"TEST_TIMER": "active"}, "pending work"),
        ({"TEST_COMPARISON": "Working and saved configurations differ."}, "differs from the requested reference"),
        ({"TEST_SHUTDOWN": "Reboot scheduled"}, "a shutdown is scheduled"),
    ],
)
def test_saved_commit_proof_refuses_unsettled_state(preflight, overrides, reason):
    result, _ = preflight(SAVED_REQUEST, **overrides)
    assert result.returncode != 0
    assert result.stdout == ""
    assert reason in result.stderr


@pytest.mark.parametrize(("command", "expected", "env"), [
    ("", BOOT, {}),
    ("/bin/false", BOOT, {}),
    ("/bin/false uxg-commit-proof", f"uxg-commit-completed {FINGERPRINT}", {}),
    ("/bin/false uxg-commit-snapshot", f"uxg-commit-staged {FINGERPRINT}", {"TEST_TIMER": "active"}),
])
def test_existing_preflight_responses_remain_unchanged(preflight, command, expected, env):
    result, _ = preflight(command, **env)
    assert result.returncode == 0, result.stderr
    assert result.stdout == f"{expected}\n"


def test_saved_commit_proof_rejects_extra_command_words_and_arguments(preflight):
    for request, args, reason in (
        (f"{SAVED_REQUEST} extra", (), "unexpected preflight request"),
        (SAVED_REQUEST, ("extra",), "expected no arguments"),
    ):
        result, trace = preflight(request, *args)
        assert result.returncode != 0
        assert result.stdout == ""
        assert reason in result.stderr
        assert trace == []


def test_staged_reboot_proof_checks_armed_executable_before_and_after_readback(preflight):
    request = "/bin/false uxg-commit-snapshot-reboot"
    result, trace = preflight(request, TEST_TIMER="active")
    assert result.returncode == 0, result.stderr
    assert result.stdout == f"uxg-commit-staged_reboot {FINGERPRINT}\n"
    assert trace.count("check timer target") == trace.count("check rollback executable") == 2
    for overrides in ({"TEST_ACTION": "revert_soft"}, {"TEST_TARGET": "another.service"}):
        result, _ = preflight(request, TEST_TIMER="active", **overrides)
        assert result.returncode != 0
        assert result.stdout == ""
