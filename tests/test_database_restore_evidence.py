import copy
import datetime as dt
import importlib.util
from pathlib import Path
import pytest

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('db_restore_publish',ROOT/'deploy/backups/publish-project-status.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)

@pytest.fixture
def evidence():
    receipt={'snapshot_id':'ab'*32,'archive_sha256':'cd'*32,'verified_at':'2026-11-08T12:00:00+00:00','manifest':{'databases':[{'kind':'mysql','container':'db','database':'app','dump':'databases/app.sql'}]}}
    proof={'source':'lv3','scope':'database_import_from_sha_verified_restic_archive','snapshot_id':receipt['snapshot_id'],'archive_sha256':receipt['archive_sha256'],'verified_at':'2026-11-08T12:10:00+00:00','checks':[{'kind':'mysql','container':'db','database':'app','result':'passed','network':'none'}]}
    return proof,receipt,dt.datetime(2026,11,8,13,tzinfo=dt.timezone.utc)

def test_exact_snapshot_database_import_is_evidence(evidence):
    p,r,n=evidence
    assert m.database_restore_evidence(p,r,'lv3',n)==p['verified_at']

@pytest.mark.parametrize('field,value',[('snapshot_id','old'),('archive_sha256','wrong'),('source','ru3'),('scope','fresh_source_dump_only'),('checks',[]),('verified_at','2026-11-08T11:00:00+00:00')])
def test_wrong_or_incomplete_proof_is_rejected(evidence,field,value):
    p,r,n=evidence;p[field]=value
    with pytest.raises(ValueError):m.database_restore_evidence(p,r,'lv3',n)

def test_failed_import_cannot_be_published_as_verified(evidence):
    p,r,n=evidence;p['checks'][0]['result']='failed'
    with pytest.raises(ValueError):m.database_restore_evidence(p,r,'lv3',n)
