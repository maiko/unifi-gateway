import json
import sys
from threading import Event, Thread

import pytest

from gateway_profiles.uxg_speedtest import SpeedTestError, WanSpeedTest


RESULT = {"download_bps": 82_250_000, "upload_bps": 14_500_000, "latency_ms": 4.2, "timestamp": 1_800_000_000}


def helper(tmp_path, body):
    command = tmp_path / "measure"
    command.write_text(f"#!{sys.executable}\n{body}\n")
    command.chmod(0o700)
    return command


def test_runs_one_fixed_command_and_returns_measured_mbps(tmp_path):
    command = helper(tmp_path, "import sys; assert len(sys.argv) == 1 and not sys.stdin.read()\n"
                     f"print({json.dumps(RESULT)!r})")
    speedtest = WanSpeedTest(command)
    assert speedtest.measure() == {"download": 82.25, "upload": 14.5, "ping": 4.2, "lastrun": 1_800_000_000}


def test_streams_a_measured_download_before_the_command_finishes(tmp_path):
    download = {key: value for key, value in RESULT.items() if key != "upload_bps"}
    gate = tmp_path / "continue"
    command = helper(tmp_path, "from pathlib import Path\nimport time\n"
                     f"print({json.dumps(download | {'phase': 'download'})!r}, flush=True)\n"
                     f"while not Path({str(gate)!r}).exists(): time.sleep(0.01)\n"
                     f"print({json.dumps(RESULT | {'phase': 'upload'})!r}, flush=True)\n"
                     f"print({json.dumps(RESULT)!r}, flush=True)")
    received = Event()
    observations = []
    results = []

    def observe(phase, measurement):
        observations.append((phase, measurement))
        received.set()

    def measure():
        try:
            results.append(WanSpeedTest(command, timeout=5).measure(on_progress=observe))
        except (SpeedTestError, TypeError) as error:
            results.append(error)

    worker = Thread(target=measure)
    worker.start()
    try:
        assert received.wait(1), results
        assert worker.is_alive()
        assert observations == [("download", {"download": 82.25, "ping": 4.2, "lastrun": 1_800_000_000})]
    finally:
        gate.touch()
        worker.join(timeout=5)
    assert [phase for phase, _ in observations] == ["download", "upload"]
    assert results == [{"download": 82.25, "upload": 14.5, "ping": 4.2, "lastrun": 1_800_000_000}]


@pytest.mark.parametrize("output", ["not JSON", "{", *[
    json.dumps(RESULT | update) for update in ({"download_bps": True}, {"download_bps": float("nan")},
                                               {"upload_bps": 0}, {"latency_ms": -2}, {"timestamp": 1.5},
                                               {"timestamp": 0}, {"fabricated": True})
], json.dumps(RESULT)[:-1] + ', "upload_bps": 5}'])
def test_rejects_invalid_or_ambiguous_measurements(tmp_path, output):
    command = helper(tmp_path, f"print({output!r})")
    with pytest.raises(SpeedTestError, match="measurement"):
        WanSpeedTest(command).measure()


def test_rejects_oversized_or_failed_execution(tmp_path):
    command = helper(tmp_path, "print('x' * 100_000)")
    with pytest.raises(SpeedTestError, match="output"):
        WanSpeedTest(command).measure()
    command = helper(tmp_path, f"print({json.dumps(RESULT)!r}); raise SystemExit(1)")
    with pytest.raises(SpeedTestError, match="failed"):
        WanSpeedTest(command).measure()


def test_times_out_and_rechecks_executable_permissions(tmp_path):
    command = helper(tmp_path, "import time; time.sleep(3)")
    speedtest = WanSpeedTest(command, timeout=0.1)
    with pytest.raises(SpeedTestError, match="timed out"):
        speedtest.measure()
    command.chmod(0o722)
    with pytest.raises(SpeedTestError, match="owned executable"):
        speedtest.measure()


def test_rejects_ambiguous_executable_paths(tmp_path):
    command = helper(tmp_path, "pass")
    alias = tmp_path / "alias"
    alias.symlink_to(command)
    for value in ("measure", alias, tmp_path / "missing"):
        with pytest.raises(SpeedTestError):
            WanSpeedTest(value)
