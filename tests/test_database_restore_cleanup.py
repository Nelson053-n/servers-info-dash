import importlib.util
from pathlib import Path
from types import SimpleNamespace
import pytest

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('isolated_restore_test',ROOT/'deploy/backups/db-restore-check.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)

@pytest.mark.parametrize('failed_command',[['docker','rm'],['docker','volume','rm']])
def test_cleanup_failure_cannot_report_success(tmp_path,monkeypatch,failed_command):
    payload=tmp_path/'db.sql';payload.write_text('-- SQL')
    calls=[]
    def run(args,**kw):
        calls.append(args)
        return SimpleNamespace(returncode=1 if args[:len(failed_command)]==failed_command else 0,stdout=b'mysqld\n',stderr=b'')
    monkeypatch.setattr(m.subprocess,'run',run);monkeypatch.setattr(m.time,'sleep',lambda n:None)
    with pytest.raises(RuntimeError,match='isolated_restore_cleanup_failed'):
        m.restore_dump(payload,'mysql','fixed-image','mysql')
    assert any(c[:3]==['docker','volume','rm'] for c in calls)
    assert all('info-db-restore-' in c[-1] for c in calls if c[:2]==['docker','rm'] or c[:3]==['docker','volume','rm'])
