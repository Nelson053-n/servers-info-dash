"""Run the deploy script against fakes instead of grepping it.

The script runs as root on the live host, so the failure paths that
matter — pip breaking, health never coming up — are exercised here with
runuser/systemctl/curl replaced by stubs on PATH.
"""
import os
import subprocess
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "deploy" / "dash-autodeploy.sh"

# Stub layout: each fake records its calls and honours a *_FAIL switch.
_RUNUSER = """#!/bin/bash
# args: -u USER -- CMD...
shift 2; shift            # drop -u USER --
echo "runuser: $*" >> "$CALL_LOG"
case "$*" in
  *"--show-toplevel"*) echo "${REPO_ROOT:-$APP_DIR}"; exit "${TOPLEVEL_FAIL:-0}" ;;
  *"git rev-parse"*)   echo "$LOCAL_SHA"; exit "${REVPARSE_FAIL:-0}" ;;
  *"git ls-remote"*)   printf '%s\\trefs/heads/main\\n' "$REMOTE_SHA"; exit 0 ;;
  *"git fetch"*)       exit "${FETCH_FAIL:-0}" ;;
  *"git reset"*)
      # ROLLBACK_RESET_FAIL fails only the reset back to LOCAL_SHA, so
      # the rollback path can be tested without aborting the forward one.
      if [ -n "${ROLLBACK_RESET_FAIL:-}" ] && [[ "$*" == *"$LOCAL_SHA"* ]]; then
          echo "error: could not reset (index.lock exists)" >&2
          exit 128
      fi
      echo "reset to $3" ; exit "${RESET_FAIL:-0}" ;;
  *pip*install*)
      # PIP_FAIL_SECOND lets the forward install succeed and fails the
      # one inside rollback, which is a different code path.
      if [ -n "${PIP_FAIL_SECOND:-}" ]; then
          if [ -f "$STATE_DIR/pip_ran" ]; then
              echo "ERROR: could not install package" >&2
              exit 1
          fi
          touch "$STATE_DIR/pip_ran"
          exit 0
      fi
      if [ -n "${PIP_FAIL:-}" ] && [ "${PIP_FAIL}" != "0" ]; then
          echo "ERROR: could not install package" >&2
          exit 1
      fi
      exit 0 ;;
esac
exit 0
"""

_SYSTEMCTL = """#!/bin/bash
echo "systemctl: $*" >> "$CALL_LOG"
case "$1" in
  is-active) exit "${SERVICE_INACTIVE:-0}" ;;
esac
exit 0
"""

_CURL = """#!/bin/bash
echo "curl: $*" >> "$CALL_LOG"
exit "${HEALTH_FAIL:-0}"
"""


@pytest.fixture
def deploy(tmp_path):
    """Return a runner that executes the script with stubbed commands."""
    bindir = tmp_path / "bin"
    bindir.mkdir()
    for name, body in (
        ("runuser", _RUNUSER),
        ("systemctl", _SYSTEMCTL),
        ("curl", _CURL),
    ):
        path = bindir / name
        path.write_text(body, encoding="utf-8")
        path.chmod(0o755)

    app_dir = tmp_path / "app"
    (app_dir / ".venv" / "bin").mkdir(parents=True)
    (app_dir / "requirements.txt").write_text("fastapi\n", encoding="utf-8")

    call_log = tmp_path / "calls.log"
    call_log.touch()
    state_dir = tmp_path / "state"
    state_dir.mkdir()

    def run(**env_overrides):
        env = {
            **os.environ,
            "PATH": f"{bindir}:{os.environ['PATH']}",
            "APP_DIR": str(app_dir),
            "APP_USER": "tester",
            "SERVICE": "fake.service",
            "HEALTH_URL": "http://127.0.0.1:9/api/health",
            "HEALTH_TIMEOUT": "2",
            "CALL_LOG": str(call_log),
            "STATE_DIR": str(state_dir),
            "LOCK_FILE": str(tmp_path / "deploy.lock"),
            "LOCAL_SHA": "1111111111111111111111111111111111111111",
            "REMOTE_SHA": "2222222222222222222222222222222222222222",
        }
        env.update({k: str(v) for k, v in env_overrides.items()})
        proc = subprocess.run(
            ["bash", str(SCRIPT)],
            env=env, capture_output=True, text=True, timeout=120,
        )
        return proc, call_log.read_text(encoding="utf-8")

    return run


def test_up_to_date_does_nothing(deploy):
    """Matching SHAs must not restart the service."""
    sha = "3333333333333333333333333333333333333333"
    proc, calls = deploy(LOCAL_SHA=sha, REMOTE_SHA=sha)

    assert proc.returncode == 0
    assert "restart" not in calls


def test_successful_deploy_restarts_and_stops(deploy):
    proc, calls = deploy()

    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "systemctl: restart fake.service" in calls
    assert "deploy OK" in proc.stdout


def test_pip_failure_rolls_back_without_restarting_broken_venv(deploy):
    """A failed install must not be handed to the running service."""
    proc, calls = deploy(PIP_FAIL=1)

    assert proc.returncode == 1, proc.stdout
    assert "pip install failed" in proc.stdout, "failure was swallowed"
    # The reason must reach the journal, not just the fact of failure.
    assert "could not install package" in proc.stdout, "pip output lost"
    assert "rolling back" in proc.stdout
    # The rollback reset must happen before any restart, so the service
    # never runs the new code against a half-installed venv.
    reset_at = calls.index("git reset --hard 1111111111111111111111111111111111111111")
    restart_at = calls.index("systemctl: restart")
    assert reset_at < restart_at, "restarted before rolling back"


def test_failed_health_triggers_rollback(deploy):
    proc, calls = deploy(HEALTH_FAIL=1)

    assert proc.returncode == 1
    assert "rolling back" in proc.stdout
    assert "git reset --hard 1111111111111111111111111111111111111111" in calls


def test_rollback_reports_when_pip_also_fails(deploy):
    """If the rollback's own install breaks, say so instead of 'works'.

    The forward install must succeed here, or the rollback is entered
    through the pip path and this asserts nothing new.
    """
    proc, _ = deploy(HEALTH_FAIL=1, PIP_FAIL_SECOND=1)

    assert proc.returncode == 1
    assert "pip install failed during rollback" in proc.stdout


def test_failed_rollback_reset_does_not_claim_recovery(deploy):
    """A rollback whose reset fails must not report a working dashboard."""
    proc, _ = deploy(HEALTH_FAIL=1, ROLLBACK_RESET_FAIL=1)

    assert proc.returncode == 1
    assert "rollback reset failed" in proc.stdout, (
        "failed rollback reset went unnoticed"
    )


def test_fetch_failure_is_reported(deploy):
    proc, calls = deploy(FETCH_FAIL=1)

    assert proc.returncode == 1
    assert "fetch failed" in proc.stdout
    assert "systemctl: restart" not in calls, "restarted despite failed fetch"


def test_unreachable_origin_skips_quietly(deploy):
    proc, calls = deploy(REMOTE_SHA="")

    assert proc.returncode == 0
    assert "cannot reach origin" in proc.stdout
    assert "restart" not in calls


def test_repeated_unreachable_origin_alerts(deploy, tmp_path):
    """A pipeline dead for hours must not stay silent."""
    state = tmp_path / "misses"
    # One short of the threshold: the next run is the one that alerts.
    state.write_text("2", encoding="utf-8")

    proc, _ = deploy(
        REMOTE_SHA="", STATE_FILE=str(state), UNREACHABLE_ALERT_AFTER=3,
    )

    assert proc.returncode == 0
    assert "consecutive misses: 3" in proc.stdout, proc.stdout
    assert state.read_text(encoding="utf-8").strip() == "3"
    # notify has no venv to run in here, and says so — which is the
    # observable evidence that it was called at all.
    assert "notify failed" in proc.stdout, (
        f"no alert attempted at the threshold: {proc.stdout}"
    )


def test_below_threshold_stays_quiet(deploy, tmp_path):
    """Transient blips must not alert on every run."""
    state = tmp_path / "misses"

    proc, _ = deploy(
        REMOTE_SHA="", STATE_FILE=str(state), UNREACHABLE_ALERT_AFTER=3,
    )

    assert "consecutive misses: 1" in proc.stdout
    assert "notify failed" not in proc.stdout, "alerted on the first miss"


def test_reachable_origin_resets_the_miss_counter(deploy, tmp_path):
    state = tmp_path / "misses"
    state.write_text("7", encoding="utf-8")

    deploy(STATE_FILE=str(state))

    assert not state.exists(), "miss counter survived a successful check"
