#!/usr/bin/python3
"""Publish verified project aggregates; retain last success on reader errors."""
import copy
import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path
import yaml

BASE=Path('/opt/info-collectors')
OUT=Path('/var/lib/infodash/projects')

def load(name,file):
    spec=importlib.util.spec_from_file_location(name,file);module=importlib.util.module_from_spec(spec);sys.modules[name]=module;spec.loader.exec_module(module);return module

sources=load('business_sources',BASE/'info-business-sources.py')
flux=load('flux_source_reader',BASE/'source_reader.py')
flux_october=load('flux_october_evidence',BASE/'flux-october-evidence.py')
flux_monthly=load('flux_monthly_ledger',BASE/'flux-monthly-ledger.py')
acquire=load('flux_acquisition',BASE/'collect_flux_sources.py')
proposal=json.loads((BASE/'flux-panel-otpuska-proposal.json').read_text())
config=yaml.safe_load(Path('/opt/info-recovery/config/projects.yaml').read_text())


def previous(project):
    try:return json.loads((OUT/('otpuska-business.json' if project=='otpuska' else project+'.json')).read_text())
    except (OSError,ValueError):return {}


def publish(project,doc):
    for item in doc.get('kpis',[]):
        item.setdefault('metric',item['id']);item.setdefault('unit','');item.setdefault('period','не указан');item.setdefault('source','Источник не указан');item.setdefault('generated_at',doc.get('generated_at'));item.setdefault('last_success',doc.get('last_success') if item.get('value') is not None else None);item.setdefault('error',None);item.setdefault('status','unknown' if item.get('value') is None else 'ok')
    for kind in ['tables','charts','matrices']:
        for item in doc.get(kind,[]):
            item.setdefault('generated_at',doc.get('generated_at'));item.setdefault('last_success',doc.get('last_success'));item.setdefault('source',(doc.get('kpis') or [{}])[0].get('source'));item.setdefault('period','См. даты/ограничения источника');item.setdefault('status',doc.get('status'));item.setdefault('error',doc.get('error'))
    target=OUT/('otpuska-business.json' if project=='otpuska' else project+'.json');tmp=target.with_name('.'+project+'.business.tmp');tmp.write_text(json.dumps(doc,ensure_ascii=False));os.chmod(tmp,0o644);os.replace(tmp,target)
    print(json.dumps({'project':project,'generated_at':doc.get('generated_at'),'last_success':doc.get('last_success'),'kpis':len(doc.get('kpis',[])),'tables':len(doc.get('tables',[])),'status':doc.get('status'),'error_present':bool(doc.get('error'))}))


def failed(project,error):
    doc=copy.deepcopy(previous(project));stamp=sources.now()
    if not doc:doc=sources.document([sources.metric('source','Источник данных',None,source=project,error=error)])
    doc.update(generated_at=stamp,error=error,status='stale' if doc.get('last_success') else 'unknown')
    for kind in ['kpis','charts','tables','matrices']:
        for item in doc.get(kind,[]):item.update(status='stale' if kind!='kpis' or item.get('value') is not None else 'unknown',error=error)
    return doc

readers={'nanabanana':sources.read_nanabanana,'wakeparty':sources.read_wakeparty,'bonds':sources.read_bonds,'cars':sources.read_cars,'globalauto':sources.read_globalauto,'kendo':sources.read_kendo,'trade':sources.read_trade}
for name,reader in readers.items():
    try:doc=reader()
    except Exception as exc:doc=failed(name,type(exc).__name__)
    publish(name,doc)

try:
    snapshot=acquire.read_flux_sources();doc=flux.build_flux(snapshot,snapshot['ops'],previous('flux'))
    doc=flux_october.apply_october(doc,json.loads((BASE/'audit-aggregates/flux-october-safe.json').read_text()))
except Exception as exc:doc=failed('flux',type(exc).__name__);snapshot={}
doc=flux_monthly.collect(doc,previous('flux'))
publish('flux',doc)

for name in ['vpn','otpuska']:
    try:
        if name=='vpn':
            import urllib.request
            source=next(x for x in config['projects'] if x['id']=='vpn')['analytics'];request=urllib.request.Request(source['url'],headers={'Authorization':'Bearer '+source['token']})
            with urllib.request.urlopen(request,timeout=75) as response:raw=json.load(response)
        else:
            raw=snapshot.get('otpuska_document') or previous('otpuska')
            if raw and raw.get('source_generated_at'):raw={**raw,'generated_at':raw['source_generated_at']}
        key='panel' if name=='vpn' else name
        doc=flux.annotate_existing(raw,key,proposal['projects'][key],previous(name))
    except Exception as exc:doc=failed(name,type(exc).__name__)
    publish(name,doc)

rows=[]
for item in config['projects']:
    doc=previous(item['id']);rows.append(dict(project=item['name'],status=doc.get('status','unknown'),generated_at=doc.get('generated_at'),last_success=doc.get('last_success'),error=doc.get('error'),metrics=len(doc.get('kpis',[]))))
known=sum(bool(r['last_success']) for r in rows);kpis=[sources.metric('commercial_model','Тип проекта','Некоммерческий мониторинг',source='Info architecture',category='noncommercial'),sources.metric('projects','Проекты в панели',len(config['projects']),'шт',source='Info projects config'),sources.metric('sources_with_success','Источники с успешными данными',known,'шт',source='Aggregate documents'),sources.metric('incomplete_sources','Неполные источники',sum(r['status']!='ok' for r in rows),'шт',source='Aggregate document statuses')]+sources.unknown_finance('Info не является коммерческим проектом','не применимо',True)
doc=sources.document(kpis,[sources.table('source_freshness','Источники и последние успешные данные',[('project','Проект',False),('status','Статус',False),('generated_at','Попытка сбора',False),('last_success','Последний успех',False),('error','Ошибка/ограничение',False),('metrics','Показателей',True)],rows)])
publish('info-public',doc)
