import importlib.util
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('vanished_export', ROOT/'deploy/backups/export-projects.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)

MISSING = "tar: opt/app/cache/sync.tar.gz.transfer-error: Cannot stat: No such file or directory\n"
CHANGED = "tar: opt/app/site/wp-content/x.php: file changed as we read it\n"
TAIL = "tar: Exiting with failure status due to previous errors\n"


def test_vanished_transient_file_is_accepted():
    assert m.tar_changed_only(2, (MISSING+TAIL).encode()) is True


def test_mix_of_changed_and_vanished_is_accepted():
    assert m.tar_changed_only(2, (CHANGED+MISSING+TAIL).encode()) is True


def test_present_file_cannot_be_treated_as_vanished(tmp_path):
    present = Path('/tmp/info-tar-present-probe')
    present.write_text('x')
    try:
        line = f"tar: {present}: Cannot stat: No such file or directory\n"
        assert m.tar_changed_only(2, (line+TAIL).encode()) is False
    finally:
        present.unlink(missing_ok=True)


def test_other_tar_errors_stay_fatal():
    assert m.tar_changed_only(2, b"tar: opt/app: Cannot open: Permission denied\n" + TAIL.encode()) is False
    assert m.tar_changed_only(1, b"tar: opt/app: Cannot read: Input/output error\n") is False
    assert m.tar_changed_only(3, (MISSING+TAIL).encode()) is False


def test_empty_stderr_is_not_success():
    assert m.tar_changed_only(2, b"") is False
