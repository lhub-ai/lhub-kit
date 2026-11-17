"""`serve --exec` (seller-door D-10): the hardened per-job command runner.

Matrix per task 4.10: success delivers stdout; a non-zero exit records the
failure and leaves the job queued; a timeout kills the whole process group;
oversize stdout kills the child; a non-UUID deal id is refused; the child gets
a minimal environment (never the kit home or key path).
"""

from __future__ import annotations

import base64
import json
import sys
import time
from pathlib import Path
from typing import Any

import pytest
from routerkit import RouterKit

import lhub

DEAL_ID = "d0000000-0000-4000-8000-00000000d001"
LISTING_ID = "7a1d2f30-1111-4222-8333-944444444444"


def py(code: str) -> list[str]:
    return [sys.executable, "-c", code]


@pytest.fixture
def job(tmp_path: Path) -> tuple[Path, Path]:
    job_dir = tmp_path / "job"
    job_dir.mkdir()
    input_path = job_dir / "input"
    input_path.write_bytes(b"line one\nline two\n")
    return job_dir, input_path


def test_success_captures_stdout_and_input_path_is_last_argv(
    job: tuple[Path, Path],
) -> None:
    job_dir, input_path = job
    outcome = lhub.run_exec_command(
        py("import sys; sys.stdout.write(open(sys.argv[-1]).read())"),
        input_path=input_path,
        job_dir=job_dir,
        timeout_seconds=10,
    )
    assert outcome.status == "ok"
    assert outcome.exit_code == 0
    assert outcome.stdout == b"line one\nline two\n"


def test_nonzero_exit_reported(job: tuple[Path, Path]) -> None:
    job_dir, input_path = job
    outcome = lhub.run_exec_command(
        py("import sys; sys.stderr.write('boom\\n'); sys.exit(3)"),
        input_path=input_path,
        job_dir=job_dir,
        timeout_seconds=10,
    )
    assert outcome.status == "exit"
    assert outcome.exit_code == 3
    assert "boom" in outcome.stderr_tail


def test_timeout_kills_the_process_group(job: tuple[Path, Path], tmp_path: Path) -> None:
    job_dir, input_path = job
    beat = tmp_path / "beat"
    # The child spawns a GRANDCHILD that heartbeats a file, then sleeps. After
    # the timeout, the whole group must be dead: the heartbeat stops.
    code = (
        "import subprocess, sys, time\n"
        f"subprocess.Popen([sys.executable, '-c', '''\n"
        "import time\n"
        f"while True:\n"
        f"    open({str(beat)!r}, 'a').write('x')\n"
        "    time.sleep(0.1)\n"
        "'''])\n"
        "time.sleep(30)\n"
    )
    started = time.monotonic()
    outcome = lhub.run_exec_command(
        py(code), input_path=input_path, job_dir=job_dir, timeout_seconds=1.0
    )
    assert outcome.status == "timeout"
    assert time.monotonic() - started < 10
    time.sleep(0.5)  # allow any surviving grandchild to beat again
    size_after_kill = beat.stat().st_size if beat.exists() else 0
    time.sleep(0.6)
    size_later = beat.stat().st_size if beat.exists() else 0
    assert size_later == size_after_kill  # nothing in the group is alive


def test_oversize_stdout_kills_the_child(job: tuple[Path, Path]) -> None:
    job_dir, input_path = job
    outcome = lhub.run_exec_command(
        py("import sys\nwhile True:\n    sys.stdout.write('x' * 65536)\n    sys.stdout.flush()"),
        input_path=input_path,
        job_dir=job_dir,
        timeout_seconds=30,
    )
    assert outcome.status == "oversize"


def test_child_environment_is_minimal(
    job: tuple[Path, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    job_dir, input_path = job
    monkeypatch.setenv("LHUB_KIT_HOME", "/secret/kit/home")
    monkeypatch.setenv("SOME_SECRET", "hunter2")
    outcome = lhub.run_exec_command(
        py("import os, json; print(json.dumps(dict(os.environ)))"),
        input_path=input_path,
        job_dir=job_dir,
        timeout_seconds=10,
    )
    assert outcome.status == "ok"
    env = json.loads(outcome.stdout)
    # PATH + LHUB_JOB_DIR + LANG only. LC_CTYPE may be coerced in by Python
    # (PEP 538) and __CF_USER_TEXT_ENCODING is injected by macOS libc on exec;
    # neither comes from the kit's env dict.
    assert set(env) <= {"PATH", "LHUB_JOB_DIR", "LANG", "LC_CTYPE", "__CF_USER_TEXT_ENCODING"}
    assert env["LHUB_JOB_DIR"] == str(job_dir)
    assert "LHUB_KIT_HOME" not in env
    assert "SOME_SECRET" not in env


# ---------------------------------------------------------------------------
# run_serve_job — the deliver / failure / never-redeliver wiring.
# ---------------------------------------------------------------------------


class ServeWorld:
    def __init__(self, tmp_path: Path) -> None:
        self.proofs: list[dict[str, Any]] = []
        self.kit = RouterKit(tmp_path / "home", self.route)
        self.kit.ensure_key()
        core = {
            "pricing": {
                "model": "flat",
                "currency": lhub.SETTLEMENT_UNIT,
                "amount": "0.50",
                "unit": "job",
            },
            "capability": {"extension_input": {"turnaround_hours": 1}},
        }
        self.kit.store_listing(LISTING_ID, "ab" * 32, core)
        job_dir = self.kit.job_dir(DEAL_ID)
        (job_dir / "input").write_bytes(b"payload\n")
        # D-4a: inbox items carry listing_content_hash, never a listing UUID.
        self.item: dict[str, Any] = {
            "deal_id": DEAL_ID,
            "listing_content_hash": "ab" * 32,
            "todo": "fulfil",
        }

    def route(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        if name == "upload_deal_file":
            data = base64.b64decode(arguments["content_b64"])
            return {"sha256": lhub.sha256_ref(data).removeprefix("sha256:"), "size": len(data)}
        if name == "submit_proof":
            self.proofs.append(arguments)
            return {"deal_id": arguments["deal_id"], "state": "PROOF_SUBMITTED"}
        raise AssertionError(f"unexpected tool {name}")


def test_serve_job_success_delivers_and_marks(tmp_path: Path) -> None:
    world = ServeWorld(tmp_path)
    out = lhub.run_serve_job(
        world.kit,
        world.item,
        py("import sys; sys.stdout.write(open(sys.argv[-1]).read().upper())"),
    )
    assert out["action"] == "delivered"
    (proof,) = world.proofs
    assert proof["proof_payload"]["hash"] == lhub.sha256_ref(b"PAYLOAD\n")
    assert (world.kit.jobs_dir / DEAL_ID / "delivered.json").exists()

    # Never re-delivered: the local marker short-circuits the next round.
    again = lhub.run_serve_job(world.kit, world.item, py("print('x')"))
    assert again["action"] == "already_delivered"
    assert len(world.proofs) == 1


def test_serve_job_failure_recorded_and_left_queued(tmp_path: Path) -> None:
    world = ServeWorld(tmp_path)
    out = lhub.run_serve_job(world.kit, world.item, py("import sys; sys.exit(9)"))
    assert out["action"] == "exec_failed"
    assert world.proofs == []
    failed = json.loads((world.kit.jobs_dir / DEAL_ID / "failed.json").read_text())
    assert failed["exit_code"] == 9

    # The failure marker keeps the job queued for a human — no silent retry.
    again = lhub.run_serve_job(world.kit, world.item, py("print('x')"))
    assert again["action"] == "failed_previously"
    assert world.proofs == []


def test_serve_job_deal_with_platform_deliverable_never_rerun(tmp_path: Path) -> None:
    world = ServeWorld(tmp_path)
    world.item["deliverable"] = {"sha256": "ab" * 32, "size": 3}
    out = lhub.run_serve_job(world.kit, world.item, py("print('x')"))
    assert out["action"] == "already_delivered"
    assert world.proofs == []


def test_serve_job_refuses_non_uuid_deal_id(tmp_path: Path) -> None:
    world = ServeWorld(tmp_path)
    world.item["deal_id"] = "../sneaky"
    with pytest.raises(lhub.KitError, match="not a UUID"):
        lhub.run_serve_job(world.kit, world.item, py("print('x')"))


def test_serve_job_waits_for_input(tmp_path: Path) -> None:
    world = ServeWorld(tmp_path)
    (world.kit.jobs_dir / DEAL_ID / "input").unlink()
    out = lhub.run_serve_job(world.kit, world.item, py("print('x')"))
    assert out["action"] == "waiting_input"
    assert world.proofs == []


def test_job_timeout_uses_listing_turnaround_capped(tmp_path: Path) -> None:
    world = ServeWorld(tmp_path)
    # The listing is resolved by its content hash (D-4a). 1h turnaround, but
    # the hard cap is 30 min.
    assert lhub._job_timeout_seconds(world.kit, "ab" * 32) == 1800.0
    core = {"capability": {"extension_input": {"turnaround_hours": 168}}}
    world.kit.store_listing(LISTING_ID, "cd" * 32, core)
    assert lhub._job_timeout_seconds(world.kit, "cd" * 32) == float(lhub.SERVE_TIMEOUT_CAP_SECONDS)
    # Unknown hash: the cap.
    assert lhub._job_timeout_seconds(world.kit, "ee" * 32) == float(lhub.SERVE_TIMEOUT_CAP_SECONDS)


# ---------------------------------------------------------------------------
# Spawn failures and the fail-safe boundaries (sec B-1 / N-2): a missing or
# non-executable --exec command — or any unexpected exception in the job
# path — records the failure and keeps the serve loop alive.
# ---------------------------------------------------------------------------


def test_missing_command_returns_spawn_failed(job: tuple[Path, Path]) -> None:
    job_dir, input_path = job
    # Pre-fix: subprocess.Popen raised FileNotFoundError (not a KitError)
    # straight through run_serve_job/do_serve_round and killed `serve`.
    outcome = lhub.run_exec_command(
        ["/nonexistent/lhub-kit-no-such-command"],
        input_path=input_path,
        job_dir=job_dir,
        timeout_seconds=5,
    )
    assert outcome.status == "spawn_failed"
    assert outcome.exit_code is None
    assert "could not be started" in outcome.detail


def test_non_executable_command_returns_spawn_failed(
    job: tuple[Path, Path], tmp_path: Path
) -> None:
    job_dir, input_path = job
    script = tmp_path / "not-executable.sh"
    script.write_text("#!/bin/sh\necho hi\n")
    script.chmod(0o600)  # no execute bit -> Popen raises PermissionError
    outcome = lhub.run_exec_command(
        [str(script)], input_path=input_path, job_dir=job_dir, timeout_seconds=5
    )
    assert outcome.status == "spawn_failed"
    assert "could not be started" in outcome.detail


def test_serve_job_spawn_failure_recorded_and_left_queued(tmp_path: Path) -> None:
    world = ServeWorld(tmp_path)
    out = lhub.run_serve_job(world.kit, world.item, ["/nonexistent/lhub-kit-no-such-command"])
    assert out["action"] == "exec_failed"
    assert out["status"] == "spawn_failed"
    assert world.proofs == []
    failed = json.loads((world.kit.jobs_dir / DEAL_ID / "failed.json").read_text())
    assert failed["status"] == "spawn_failed"
    # The marker keeps the job queued for a human; nothing is re-run.
    again = lhub.run_serve_job(world.kit, world.item, ["/nonexistent/lhub-kit-no-such-command"])
    assert again["action"] == "failed_previously"


def test_serve_job_unexpected_exception_recorded_and_left_queued(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    world = ServeWorld(tmp_path)

    def boom(*_args: Any, **_kwargs: Any) -> lhub.ExecOutcome:
        raise RuntimeError("latent exec bug")

    monkeypatch.setattr(lhub, "run_exec_command", boom)
    out = lhub.run_serve_job(world.kit, world.item, ["true"])
    assert out["action"] == "error"
    assert out["status"] == "unexpected"
    assert "RuntimeError" in out["reason"]
    assert world.proofs == []
    failed = json.loads((world.kit.jobs_dir / DEAL_ID / "failed.json").read_text())
    assert failed["status"] == "unexpected"


class RoundWorld:
    """A do_serve_round world: one funded job, input already placed."""

    def __init__(self, tmp_path: Path) -> None:
        self.kit = RouterKit(tmp_path / "home", self.route)
        self.kit.ensure_key()
        (self.kit.job_dir(DEAL_ID) / "input").write_bytes(b"payload\n")
        self.item: dict[str, Any] = {
            "deal_id": DEAL_ID,
            "listing_content_hash": "ab" * 32,
            "todo": "fulfil",
        }

    def route(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        if name == "get_inbox":
            return {"items": [self.item], "polled_at": "now", "poll_hint_seconds": 30}
        raise AssertionError(f"unexpected tool {name}")


def test_serve_round_survives_unexpected_job_exception(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    world = RoundWorld(tmp_path)

    def boom(kit: lhub.Kit, item: Any, argv_base: Any) -> dict[str, Any]:
        raise RuntimeError("latent job bug")

    monkeypatch.setattr(lhub, "run_serve_job", boom)
    out = lhub.do_serve_round(world.kit, argv_base=["true"])  # must RETURN, not raise
    (job,) = out["jobs"]
    assert job["action"] == "error"
    assert "RuntimeError" in job["reason"]


def test_serve_round_spawn_failure_end_to_end(tmp_path: Path) -> None:
    # The N-2 reproduction at the do_serve_round level: a missing --exec
    # command yields a recorded per-job outcome and the round completes.
    world = RoundWorld(tmp_path)
    out = lhub.do_serve_round(world.kit, argv_base=["/nonexistent/lhub-kit-no-such-command"])
    (job,) = out["jobs"]
    assert job["action"] == "exec_failed"
    assert job["status"] == "spawn_failed"
    assert (
        json.loads((world.kit.jobs_dir / DEAL_ID / "failed.json").read_text())["status"]
        == "spawn_failed"
    )


# ---------------------------------------------------------------------------
# run_serve_loop: the loop survives marketplace outages (a seller loop that
# dies on a bridge restart becomes an OFFLINE listing). Transport failures
# back off at interval x 2^n capped at 5 min, reset on success; only a
# non-transport error (e.g. the D-14 missing-"items" contract error) ends it.
# ---------------------------------------------------------------------------


class StopLoop(Exception):
    """Raised by the patched sleep to end the (otherwise infinite) loop under test."""


class FlakyInboxWorld:
    """get_inbox raises a TRANSPORT error ``failures`` times, then succeeds."""

    def __init__(self, tmp_path: Path, *, failures: int) -> None:
        self.remaining = failures
        self.polls = 0
        self.kit = RouterKit(tmp_path / "home", self.route)
        self.kit.ensure_key()
        (self.kit.job_dir(DEAL_ID) / "input").write_bytes(b"payload\n")
        self.item: dict[str, Any] = {
            "deal_id": DEAL_ID,
            "listing_content_hash": "ab" * 32,
            "todo": "fulfil",
        }

    def route(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        if name == "get_inbox":
            self.polls += 1
            if self.remaining > 0:
                self.remaining -= 1
                raise lhub.KitTransportError("cannot reach http://localhost:19999/mcp/v1: down")
            return {"items": [self.item], "polled_at": "now", "poll_hint_seconds": 30}
        raise AssertionError(f"unexpected tool {name}")


def patch_sleep(monkeypatch: pytest.MonkeyPatch, *, stop_after: int) -> list[float]:
    sleeps: list[float] = []

    def fake_sleep(seconds: float) -> None:
        sleeps.append(seconds)
        if len(sleeps) >= stop_after:
            raise StopLoop

    monkeypatch.setattr(time, "sleep", fake_sleep)
    return sleeps


def test_serve_loop_survives_transport_failures_with_backoff(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    world = FlakyInboxWorld(tmp_path, failures=2)
    # Two backoff sleeps, then the post-success interval sleep ends the test.
    sleeps = patch_sleep(monkeypatch, stop_after=3)
    with pytest.raises(StopLoop):
        lhub.run_serve_loop(world.kit, argv_base=None, interval_seconds=30.0, once=False)
    # Backoff: 30 x 2^0, 30 x 2^1 — then the SUCCESS resets to the plain interval.
    assert sleeps == [30.0, 60.0, 30.0]
    assert world.polls == 3  # two failed rounds + the successful third
    captured = capsys.readouterr()
    # One stderr line per failed round; the loop never emitted a failure payload.
    assert captured.err.count("marketplace unreachable") == 2
    # The third round PROCESSED the funded item and was emitted on stdout.
    payload = json.loads(captured.out)
    assert payload["round"] == 3
    assert payload["todo_counts"] == {"fulfil": 1}
    (action,) = payload["actions"]
    assert action["action"] == "input_present"


def test_serve_loop_backoff_caps_at_five_minutes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    world = FlakyInboxWorld(tmp_path, failures=6)
    sleeps = patch_sleep(monkeypatch, stop_after=6)
    with pytest.raises(StopLoop):
        lhub.run_serve_loop(world.kit, argv_base=None, interval_seconds=30.0, once=False)
    assert sleeps == [30.0, 60.0, 120.0, 240.0, 300.0, 300.0]  # capped at 5 min
    assert world.polls == 6


def test_serve_loop_survives_thousands_of_failures_at_the_cap(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # sec R2 N-2: pre-clamp, 2**(failures-1) stopped converting to float
    # around failure ~1024 and the backoff multiply raised OverflowError —
    # a days-long outage crashed the loop it was built to survive. The
    # exponent is clamped, so failure 2000 still sleeps exactly the cap.
    world = FlakyInboxWorld(tmp_path, failures=2000)
    sleeps = patch_sleep(monkeypatch, stop_after=2000)
    with pytest.raises(StopLoop):
        lhub.run_serve_loop(world.kit, argv_base=None, interval_seconds=30.0, once=False)
    assert len(sleeps) == 2000
    assert world.polls == 2000
    assert sleeps[-1] == float(lhub.SERVE_BACKOFF_CAP_SECONDS)
    assert max(sleeps) == float(lhub.SERVE_BACKOFF_CAP_SECONDS)


def test_serve_loop_contract_error_still_exits(tmp_path: Path) -> None:
    # A get_inbox payload without the pinned "items" key is a bridge/kit
    # CONTRACT error, not an outage: the loop must NOT retry it.
    kit = RouterKit(tmp_path / "home", lambda name, arguments: {"results": []})
    kit.ensure_key()
    with pytest.raises(lhub.KitError, match="'items'") as excinfo:
        lhub.run_serve_loop(kit, argv_base=None, interval_seconds=1.0, once=False)
    assert not isinstance(excinfo.value, lhub.KitTransportError)


def test_serve_once_transport_failure_raises(tmp_path: Path) -> None:
    # --once keeps the current semantics: a transport failure exits non-zero
    # (the KitError surfaces through main) instead of backing off.
    world = FlakyInboxWorld(tmp_path, failures=1)
    with pytest.raises(lhub.KitTransportError):
        lhub.run_serve_loop(world.kit, argv_base=None, interval_seconds=1.0, once=True)
    assert world.polls == 1
