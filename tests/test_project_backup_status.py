import copy,datetime as dt,importlib.util
from pathlib import Path
import pytest

spec=importlib.util.spec_from_file_location('project_status',Path(__file__).resolve().parents[1]/'deploy/backups/project-status.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
NOW=dt.datetime(2026,11,6,10,tzinfo=dt.timezone.utc)


def data():
    return dict(schema_version=2,source_id='giga-projects',collector_status='ok',observed_at=NOW.isoformat(),attempted_at=NOW.isoformat(),schedule_enabled=True,sources={'ru2':dict(result='success',restore_result='passed',error_code=None,last_backup_success_at=NOW.isoformat(),last_restore_verified_at=NOW.isoformat(),logical_bytes=300,protected_projects=['info-public','bonds'])},check_result='passed',last_check_verified_at=NOW.isoformat())


def test_incomplete_coverage_never_claims_all_projects():
    d=m.validate(data(),NOW);doc=m.analytics(d,NOW)
    assert doc['kpis'][0]['value']==2
    assert doc['kpis'][1]['value']==13
    assert any(x['status']=='Нет свежей копии' for x in doc['tables'][0]['rows'])
    assert doc['status']=='partial'
    old=m.analytics(d,NOW+dt.timedelta(days=2))
    assert old['kpis'][0]['value']==0 and old['stale']


def test_private_fields_and_false_success_rejected():
    for mutate in [lambda d:d['sources']['ru2'].update(path='/private/key'),lambda d:d['sources']['ru2'].update(last_backup_success_at=None),lambda d:d['sources']['ru2'].update(protected_projects=['unknown-project'])]:
        d=data();mutate(d)
        with pytest.raises(ValueError):m.validate(d,NOW)


def test_publish_is_idempotent_and_replay_rejected(tmp_path):
    d=data();assert m.receive(d,tmp_path,NOW)=='accepted'
    assert m.receive(d,tmp_path,NOW)=='already accepted'
    d['attempted_at']=(NOW-dt.timedelta(seconds=1)).isoformat();d['observed_at']=d['attempted_at'];d['sources']={};d['last_check_verified_at']=None;d['check_result']='unknown'
    with pytest.raises(ValueError):m.receive(d,tmp_path,NOW)


def test_fresh_observation_cannot_refresh_old_backup_evidence():
    d=data();old=(NOW-dt.timedelta(days=3)).isoformat()
    d['sources']['ru2']['last_backup_success_at']=old
    d['sources']['ru2']['last_restore_verified_at']=old
    doc=m.analytics(m.validate(d,NOW),NOW)
    assert not doc['stale'] and doc['kpis'][0]['value']==0
    assert any(x['severity']=='warn' for x in doc['alerts'])

def test_bob_is_a_covered_source_not_deferred():
    doc=m.analytics(data(),NOW)
    row=next(x for x in doc['tables'][0]['rows'] if x['project']=='График отпусков (стенд)')
    assert row['status']=='Нет свежей копии' and 'PostgreSQL' in row['scope']
    assert not any(x['status']=='Отложен владельцем' for x in doc['tables'][0]['rows'])
    d=data();d['sources']['bob']=dict(result='success',restore_result='passed',error_code=None,last_backup_success_at=NOW.isoformat(),last_restore_verified_at=NOW.isoformat(),logical_bytes=400*1024**2,protected_projects=['otpuska','moodle'])
    fresh=m.analytics(m.validate(d,NOW),NOW)
    assert next(x for x in fresh['tables'][0]['rows'] if x['project']=='График отпусков (стенд)')['status']=='Копия проверена'
    assert next(x for x in fresh['tables'][0]['rows'] if x['project']=='Учебный отдел (Moodle)')['status']=='Копия проверена'


def test_restore_failure_cannot_be_reported_as_healthy():
    d=data();d['sources']['ru2']['restore_result']='failed'
    doc=m.analytics(d,NOW)
    assert any(x['severity']=='bad' and 'восстановления' in x['text'] for x in doc['alerts'])
    d['check_result']='failed'
    assert any(x['severity']=='bad' and 'целостности' in x['text'] for x in m.analytics(d,NOW)['alerts'])


def test_one_failed_host_does_not_flood_panel_with_duplicate_alerts():
    d=data();d['sources']['ru3']={'result':'failed','restore_result':'unknown','error_code':'export_failed','protected_projects':[]}
    doc=m.analytics(m.validate(d,NOW),NOW)
    assert len([x for x in doc['alerts'] if 'Проекты на RU3' in x['text']])==1
    assert len([x for x in doc['tables'][0]['rows'] if x['status']=='Ошибка копирования'])==7


def test_sizes_are_shown_per_source_and_in_total():
    d=data();d['sources']['ru2']['logical_bytes']=14*1024**3+140*1024**2
    d['sources']['ru3']=dict(result='success',restore_result='passed',error_code=None,last_backup_success_at=NOW.isoformat(),last_restore_verified_at=NOW.isoformat(),logical_bytes=440*1024**2,protected_projects=['kendo'])
    doc=m.analytics(m.validate(d,NOW),NOW)
    size_kpi=next(x for x in doc['kpis'] if x['id']=='size_total')
    assert size_kpi['unit']=='ГиБ' and size_kpi['value']==round((14*1024**3+140*1024**2+440*1024**2)/1024**3,1)
    rows=doc['tables'][0]['rows']
    info_row=next(x for x in rows if x['project']=='Info (публичный)')
    assert info_row['size']=='14,1 ГиБ'
    kendo_row=next(x for x in rows if x['project']=='KendoSolki')
    assert kendo_row['size']=='440 МиБ'
    assert any(x['key']=='size' for x in doc['tables'][0]['columns'])


def test_missing_size_is_not_invented():
    d=data();d['sources']['ru2']['logical_bytes']=None
    doc=m.analytics(m.validate(d,NOW),NOW)
    assert next(x for x in doc['kpis'] if x['id']=='size_total')['value'] is None
    assert next(x for x in doc['tables'][0]['rows'] if x['project']=='BondAI')['size']=='нет данных'
    d2=data();del d2['sources']['ru2']['logical_bytes']
    assert next(x for x in m.analytics(m.validate(d2,NOW),NOW)['tables'][0]['rows'] if x['project']=='BondAI')['size']=='нет данных'


def test_size_text_formats_and_rejects_garbage():
    assert m.size_text(14*1024**3)==('14,0 ГиБ')
    assert m.size_text(1536*1024**2)=='1,5 ГиБ'
    assert m.size_text(440*1024**2)=='440 МиБ'
    assert m.size_text(0)=='0 МиБ'
    assert m.size_text(2048)=='2 КиБ'
    for bad in [None,-1,'10',10.5,True]:
        assert m.size_text(bad)=='нет данных'


def test_failed_source_size_is_not_counted_in_total():
    d=data();d['sources']['ru3']=dict(result='failed',restore_result='unknown',error_code='export_failed',logical_bytes=99*1024**3,protected_projects=[])
    doc=m.analytics(m.validate(d,NOW),NOW)
    assert next(x for x in doc['kpis'] if x['id']=='size_total')['value']==round(300/1024**3,1)
