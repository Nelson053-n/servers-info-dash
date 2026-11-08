import importlib.util
import io
import json
import tarfile
from pathlib import Path
import pytest

ROOT = Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('collector_db_coverage', ROOT/'deploy/backups/collect-projects.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)

def archive(tmp_path, manifest, dumps=()):
    path=tmp_path/'test.tar'
    with tarfile.open(path,'w') as tar:
        data=json.dumps(manifest).encode();i=tarfile.TarInfo('./manifest.json');i.size=len(data);tar.addfile(i,io.BytesIO(data))
        for name,body in dumps:
            i=tarfile.TarInfo('./'+name);i.size=len(body);tar.addfile(i,io.BytesIO(body))
    return path


def test_lv3_without_mysql_is_not_a_complete_backup(tmp_path):
    p=archive(tmp_path,{'source':'lv3','databases':[],'skipped':[]})
    with pytest.raises(RuntimeError,match='required_database_coverage_missing'):
        m.verify_archive(p,tmp_path)


def test_manifest_skips_are_never_silently_successful(tmp_path):
    p=archive(tmp_path,{'source':'test','databases':[],'skipped':[{'kind':'mysql','reason':'client_unavailable'}]})
    with pytest.raises(RuntimeError,match='required_database_coverage_missing'):
        m.verify_archive(p,tmp_path)


def test_mysql_dump_must_exist_and_be_nonempty(tmp_path):
    manifest={'source':'lv3','databases':[{'kind':'mysql','container':'amnezia-panel-db','database':'amnezia_panel','dump':'databases/mysql.sql'}]}
    p=archive(tmp_path,manifest,[('databases/mysql.sql',b'')])
    with pytest.raises(RuntimeError,match='database_dump_empty'):
        m.verify_archive(p,tmp_path)
    p=archive(tmp_path,manifest,[('databases/mysql.sql',b'-- SQL dump\nCREATE DATABASE test;')])
    assert m.verify_archive(p,tmp_path)==manifest
