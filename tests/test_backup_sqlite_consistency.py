import importlib.util
from pathlib import Path
import sqlite3
import pytest

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('sqlite_export_test',ROOT/'deploy/backups/export-projects.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)


def make_db(path,value=7):
    path.parent.mkdir(parents=True,exist_ok=True)
    with sqlite3.connect(path) as c:
        c.execute('CREATE TABLE t(v)');c.execute('INSERT INTO t VALUES(?)',(value,))


def force_fallback(monkeypatch,source):
    original=m.sqlite3.connect
    def connect(path,*args,**kw):
        if str(path)==source.as_uri()+'?mode=ro':
            raise sqlite3.OperationalError('readonly WAL mount')
        return original(path,*args,**kw)
    monkeypatch.setattr(m.sqlite3,'connect',connect)


def test_unreadable_main_db_cannot_become_empty_success(tmp_path,monkeypatch):
    p=tmp_path/'source.db';make_db(p);force_fallback(monkeypatch,p)
    original=Path.open
    def open_(self,mode='r',*args,**kw):
        if self==p and mode=='rb':raise PermissionError('denied')
        return original(self,mode,*args,**kw)
    monkeypatch.setattr(Path,'open',open_)
    target=tmp_path/'output.db'
    with pytest.raises(RuntimeError,match='sqlite_snapshot_failed'):
        m.snapshot_sqlite(p,target,tmp_path/'scratch')
    assert not target.exists()


def test_wal_read_error_is_not_silently_ignored(tmp_path,monkeypatch):
    p=tmp_path/'source.db';make_db(p);wal=Path(str(p)+'-wal');wal.write_bytes(b'wal')
    original=Path.open
    def open_(self,mode='r',*args,**kw):
        if self==wal and mode=='rb':raise PermissionError('denied WAL')
        return original(self,mode,*args,**kw)
    monkeypatch.setattr(Path,'open',open_)
    with pytest.raises(PermissionError):m.copy_wal_files(p,tmp_path/'scratch')


def test_changing_database_fails_closed(tmp_path,monkeypatch):
    p=tmp_path/'source.db';make_db(p)
    calls=iter([(1,None),(2,None)])
    monkeypatch.setattr(m,'sqlite_file_state',lambda p: next(calls))
    with pytest.raises(RuntimeError,match='sqlite_changed_during_copy'):
        m.copy_wal_files(p,tmp_path/'scratch')


def test_missing_main_cannot_be_created_by_fallback(tmp_path,monkeypatch):
    p=tmp_path/'missing.db';force_fallback(monkeypatch,p)
    with pytest.raises(RuntimeError,match='sqlite_snapshot_failed'):
        m.snapshot_sqlite(p,tmp_path/'output.db',tmp_path/'scratch')
    assert not (tmp_path/'output.db').exists()


def test_same_basename_has_no_cross_database_wal_or_data(tmp_path,monkeypatch):
    p=tmp_path/'one'/'app.db';q=tmp_path/'two'/'app.db';make_db(p,1);make_db(q,2)
    original=m.sqlite3.connect
    def connect(path,*args,**kw):
        if str(path) in {p.as_uri()+'?mode=ro',q.as_uri()+'?mode=ro'}:
            raise sqlite3.OperationalError('read-only WAL')
        return original(path,*args,**kw)
    monkeypatch.setattr(m.sqlite3,'connect',connect)
    for i,source in enumerate([p,q],1):
        target=tmp_path/f'out-{i}.db'
        assert m.snapshot_sqlite(source,target,tmp_path/'scratch')=='file_copy_wal'
        with original(target) as c:assert c.execute('SELECT v FROM t').fetchall()==[(i,)]
    assert list((tmp_path/'scratch').iterdir())==[]
