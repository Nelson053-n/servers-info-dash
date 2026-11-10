import datetime as dt
import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('exact_import_scope', ROOT/'deploy/backups/project-status.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
NOW = dt.datetime(2026,11,10,11,tzinfo=dt.timezone.utc)


def document(imports):
    ts = NOW.isoformat()
    sources = {}
    for source in ('ru3','lv3','vm300-code'):
        row = dict(result='success',restore_result='passed',error_code=None,last_backup_success_at=ts,last_restore_verified_at=ts,protected_projects=list(m.SOURCES[source]))
        if source in imports:
            row.update(database_restore_result='passed',database_restore_verified_at=ts)
        sources[source] = row
    data = dict(schema_version=2,source_id='giga-projects',collector_status='ok',observed_at=ts,attempted_at=ts,schedule_enabled=True,sources=sources,check_result='passed',last_check_verified_at=ts)
    return m.analytics(m.validate(data,NOW),NOW)


def test_exact_archive_import_scope_is_not_standalone_dump_scope():
    doc = document({'ru3','lv3','vm300-code'})
    assert next(k['value'] for k in doc['kpis'] if k['id']=='database_imports') == '3/3'
    limitation = doc['limitations'][0]
    assert limitation['id'] == 'backup_restore_scope_exact_archive'
    assert 'текущих архивов' in limitation['impact']
    # Legacy card enrichment only rewrites the historical generic scope id.
    for item in doc['limitations']:
        if item['id'] == 'backup_restore_scope':
            item['impact'] = 'Not an import from a Restic archive'
    assert 'текущих архивов' in limitation['impact']


def test_incomplete_import_set_does_not_claim_full_restore():
    doc = document({'lv3'})
    assert next(k['value'] for k in doc['kpis'] if k['id']=='database_imports') == '1/3'
    assert doc['limitations'][0]['id'] == 'backup_restore_scope'
