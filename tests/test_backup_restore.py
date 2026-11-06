import importlib.util
import io
import json
from pathlib import Path
import sqlite3
import tarfile
import pytest

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('collect_backup',ROOT/'deploy/backups/collect-projects.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)


def archive(path,db):
    with tarfile.open(path,'w') as tar:
        payload=json.dumps({'databases':[{'kind':'sqlite','dump':'databases/db.sqlite'}]}).encode()
        member=tarfile.TarInfo('./manifest.json');member.size=len(payload);tar.addfile(member,io.BytesIO(payload))
        tar.add(db,arcname='./databases/db.sqlite')


def test_restore_checks_actual_sqlite_pages(tmp_path):
    db=tmp_path/'original.sqlite';c=sqlite3.connect(db);c.execute('CREATE TABLE rows(value)');c.execute('INSERT INTO rows VALUES(7)');c.commit();c.close()
    a=tmp_path/'backup.tar';archive(a,db)
    assert m.verify_archive(a,tmp_path)['databases'][0]['kind']=='sqlite'
    db.write_bytes(b'corrupted SQLite data')
    archive(a,db)
    with pytest.raises(sqlite3.DatabaseError):m.verify_archive(a,tmp_path)


def test_restore_requires_manifest(tmp_path):
    a=tmp_path/'empty.tar'
    with tarfile.open(a,'w'):pass
    with pytest.raises(RuntimeError,match='manifest_invalid'):m.verify_archive(a,tmp_path)
