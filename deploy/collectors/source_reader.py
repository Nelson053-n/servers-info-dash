"""Private proposal helper. Reads supplied aggregate snapshots; never changes live Info."""
import argparse
import copy
import datetime as dt
import json
from pathlib import Path


def now():
    return dt.datetime.now(dt.timezone.utc).isoformat()


def metric(id, label, value, unit, period, source, generated_at, category='activity',
           error=None, previous=None, status=None, **extra):
    item = dict(id=id, metric=id, label=label, value=value, unit=unit, period=period,
                source=source, generated_at=generated_at,
                last_success=generated_at if value is not None and error is None else None,
                error=error, status=status or ('stale' if error and value is not None else 'ok' if value is not None else 'unknown'),
                category=category, **extra)
    if error and previous and previous.get('value') is not None and previous.get('last_success'):
        item.update(value=previous['value'], last_success=previous['last_success'], status='stale')
        if previous.get('period') != period:
            item.update(period=previous['period'], requested_period=period)
        if previous.get('data_as_of'):
            item['data_as_of'] = previous['data_as_of']
    return item


def previous_metrics(previous):
    return {x['id']: x for x in (previous or {}).get('kpis', [])}


def metadata_object(item, source, period, stamp, previous=None, error=None):
    item = copy.deepcopy(item)
    item.update(source=source, period=period, generated_at=stamp,
                last_success=stamp, error=error,
                status='stale' if error else 'ok')
    if error and previous and previous.get('last_success'):
        item = copy.deepcopy(previous)
        item.update(generated_at=stamp, error=error, status='stale')
    return item


def finish(doc, previous=None):
    usable = [x for x in doc['kpis'] if x['value'] is not None]
    doc['status'] = 'partial' if any(x['status'] != 'ok' for x in doc['kpis']) else 'ok'
    if not usable:
        doc['status'] = 'unknown'
    times=[x['last_success'] for x in doc['kpis'] if x.get('last_success')]
    doc['last_success'] = max(times) if times else (previous or {}).get('last_success')
    doc['error'] = '; '.join(sorted({x['error'] for x in doc['kpis'] if x.get('error')})) or None
    return doc


def build_flux(snapshot, ops, previous=None):
    stamp = now()
    doc = dict(generated_at=stamp, kpis=[], charts=[], tables=[], alerts=[])
    old = previous_metrics(previous)
    sources = snapshot.get('flux', {})
    def source(label):
        row = sources.get(label, {})
        return row.get('body') if row.get('http') == 200 else None
    def add(id, label, value, unit, period, src, category='activity', error=None, **kw):
        item=metric(id, label, value, unit, period, src, stamp, category,
                    error=error, previous=old.get(id), **kw)
        source_name=('wallet_summary' if 'summary' in src or 'Fusion' in src else
                     'wallet_nodes' if 'wallet/owner/nodes' in src else
                     'price' if 'network/price' in src else
                     'network_nodes' if 'network/nodes' in src else
                     'ready' if '/ready' in src else None)
        if value is not None and error is None:
            item['last_success']=(sources.get(source_name,{}) or {}).get('last_success') if source_name else ops.get('generated_at')
        doc['kpis'].append(item)
    price, summary, nodes = source('price'), source('wallet_summary'), source('wallet_nodes')
    ready = source('ready')
    readiness=('ok' if ready.get('redis') and ready.get('flux_api') else 'degraded') if isinstance(ready,dict) else None
    add('ready', 'Готовность API', readiness, '', 'snapshot', 'flux.API:/api/v1/ready',
        error=None if ready is not None else 'API readiness unavailable')
    for id, label, field, unit in [('price','Курс FLUX','flux_usd','USD/FLUX'),
                                   ('price_change_24h','Изменение курса','change_24h','%')]:
        value = price.get(field) if price else None
        add(id, label, value, unit, '24h change' if field == 'change_24h' else 'snapshot',
            'flux.API:network/price', 'valuation', None if value is not None else 'Price unavailable')
    simple = [('balance_flux','Баланс FLUX',('balance','flux'),'FLUX','valuation'),
              ('balance_usd','Баланс по текущему курсу',('balance','usd'),'USD','valuation'),
              ('my_nodes','Ноды кошелька',('total_nodes',),'шт','activity'),
              ('my_bench','Прошли benchmark',('bench_passed',),'шт','activity'),
              ('fleet_uptime','Доля CONFIRMED сейчас',('fleet_uptime_pct',),'%','activity'),
              ('hosted_apps','Приложений на нодах',('hosted_apps',),'шт','activity')]
    for id, label, keys, unit, category in simple:
        value = summary
        for key in keys:
            value = value.get(key) if isinstance(value,dict) else None
        if id == 'balance_usd' and price is None:
            value = None
        add(id,label,value,unit,'snapshot','flux.API:wallet/owner/summary',category,
            None if value is not None else 'Wallet field or valuation source unavailable')
    fleet = nodes.get('nodes') if nodes else None
    active = sum(x.get('status') == 'CONFIRMED' for x in fleet) if fleet is not None else None
    add('my_active','Ноды CONFIRMED',active,'шт','snapshot','flux.API:wallet/owner/nodes',
        error=None if active is not None else 'Node list unavailable')
    for period in ['daily','monthly','yearly']:
        value = (((summary or {}).get('earnings') or {}).get(period) or {}).get('flux')
        add('earn_day' if period=='daily' else 'forecast_'+period,'Прогноз начислений '+period,value,'FLUX-экв.',
            'model '+period,'flux.API:wallet/owner/summary.earnings','forecast',
            None if value is not None else 'Forecast unavailable',
            hint='Native + PA до комиссий; не факт выплат, не cash и не прибыль')
    apy=((summary or {}).get('earnings') or {}).get('apy_percent')
    add('apy','Модельный APY',apy,'%','annualized model','flux.API:wallet/owner/summary.earnings','forecast',
        None if apy is not None else 'APY model unavailable')
    network=source('network_nodes')
    add('network_nodes','Нод в сети Flux',(network or {}).get('total'),'шт','snapshot',
        'flux.API:network/nodes',error=None if network is not None else 'Network aggregate unavailable')
    totals = (summary or {}).get('totals') or {}
    chains = (summary or {}).get('pa_chains') or []
    real_pa = totals.get('is_estimate') is False and bool(chains)
    mined=(totals.get('mined') or {}).get('flux') if real_pa else None
    add('mined','PA начислено накопительно',mined,'FLUX-экв.','cumulative Fusion',
        'flux.Fusion via summary','activity',None if mined is not None else 'Verified Fusion accrual unavailable',
        hint='Начислено, не cash; факт получения всей суммы не утверждается')
    for field in ['claimable','claimed','received','fees']:
        values = [x.get(field) for x in chains]
        value = sum(values) if real_pa and all(isinstance(x,(int,float)) for x in values) else None
        add('pa_'+field,'PA '+field+' накопительно',value,'FLUX-экв.',
            'cumulative Fusion; monthly timing unavailable','flux.Fusion via wallet summary',
            'activity',None if value is not None else 'Verified Fusion aggregate unavailable',
            hint='Активы по сетям; не рублёвая касса и не месячная прибыль')
    for id,label,unit,category in [('native_month','Native получено за месяц','FLUX','cash_receipts'),
                                  ('revenue_month','Денежные поступления за месяц','RUB','cash_receipts'),
                                  ('revenue_prev_month','Денежные поступления прошлого месяца','RUB','cash_receipts'),
                                  ('pa_accrued_month','PA начислено за месяц','FLUX-экв.','activity'),
                                  ('expenses_month','Расходы за месяц','RUB','expenses'),
                                  ('profit_month','Прибыль за месяц','RUB','profit')]:
        add(id,label,None,unit,'previous calendar month Asia/Vladivostok' if id=='revenue_prev_month' else 'calendar MTD Asia/Vladivostok','source not restored',category,
            'Monthly native ledger/cost coverage unavailable; not zero')
    if fleet is not None:
        rows=[{k:x.get(k) for k in ['ip','tier','status','rank','age_secs','payout_eta_secs','last_paid','flux_os_version']} for x in fleet]
        doc['tables'].append(metadata_object(dict(id='my_nodes',title='Ноды кошелька',
            columns=[dict(key=k,label=k,num=k in ['rank','age_secs','payout_eta_secs','last_paid']) for k in rows[0]] if rows else [],rows=rows),
            'flux.API:wallet/owner/nodes','snapshot',stamp))
    if real_pa:
        doc['tables'].append(metadata_object(dict(id='pa',title='PA накопительно, не cash',
            columns=[dict(key=k,label=k,num=k!='chain') for k in ['chain','claimable','claimed','received','fees']],rows=chains),
            'flux.Fusion via summary','cumulative; exact monthly receipts unknown',stamp))
    history = source('price_history')
    points = (history or {}).get('points')
    if points:
        for window in [30,365]:
            selected = points[-window:]
            doc['charts'].append(metadata_object(dict(id='price_'+str(window)+'d',title='Курс FLUX '+str(window)+' дней',kind='line',unit='USD/FLUX',
                series=[dict(name='USD/FLUX',points=[[dt.datetime.fromtimestamp(p['t'],dt.timezone.utc).isoformat(),p['usd']] for p in selected])]),
                'flux.API:network/price/history',str(window)+' daily quotes; API cache<=1h',sources['price_history'].get('last_success') or stamp))
    pg = ops.get('pg') or {}
    for field in ['subscriptions','snapshots','alerts']:
        add('historical_'+field,'Историческая БД: '+field,pg.get(field),'шт',
            'snapshot as of '+str(pg.get('snapshot_updated')),'restored local PG16 July24',
            error=None if field in pg else 'Historical PG aggregate unavailable',
            status='partial',data_as_of=pg.get('snapshot_updated'),
            hint='Восстановленная копия; не текущая prod-активность')
    if pg:
        doc['tables'].append(metadata_object(dict(id='historical_pg',title='Историческая БД Flux, не live',
            columns=[dict(key=k,label=k) for k in pg],rows=[pg]),'restored local PG16 July24',
            'data as of '+str(pg.get('snapshot_updated')),stamp))
    if 'containers' in ops:
        doc['tables'].append(metadata_object(dict(id='services',title='Контейнеры Flux',
            columns=[dict(key=k,label=k) for k in ['name','state','status']],rows=ops['containers']),
            'local docker ps filter project=flux-recovery','snapshot',stamp))
    source_rows=[dict(source=name,http=row.get('http'),last_success=row.get('last_success'),error=row.get('error')) for name,row in sources.items()]
    doc['tables'].append(metadata_object(dict(id='source_status',title='Источники Flux',
        columns=[dict(key=k,label=k) for k in ['source','http','last_success','error']],rows=source_rows),
        'read-only source acquisition','last collection attempt',stamp))
    vis = ops.get('visitor_pfcount') or {}
    for key in ['today','total']:
        value = vis.get(key)
        add('visitors_'+key,'Уникальные IP '+key,value,'approx IP',
            ('UTC day '+str(ops.get('visitor_day_utc'))) if key=='today' else 'с запуска Redis '+str(ops.get('visitor_counter_since') or '?'),
            'redis PFCOUNT '+('visitors:day:'+str(ops.get('visitor_day_utc')) if key=='today' else 'visitors:total'),error=None if value is not None else 'HLL key absent/unavailable',
            hint='HLL; не люди/сессии. Redis Flux без сохранения: счётчики обнуляются при перезапуске контейнера. GET stats/visitors не вызывать: он пишет PFADD')
    retain_missing_objects(doc,previous)
    return finish(doc,previous)


def retain_missing_objects(doc, previous):
    for kind in ['tables','charts','matrices']:
        found={x['id'] for x in doc.get(kind,[])}
        for item in (previous or {}).get(kind,[]):
            if item['id'] not in found:
                saved=copy.deepcopy(item)
                saved.update(generated_at=doc['generated_at'],status='stale',error='Source block absent from latest response')
                doc.setdefault(kind,[]).append(saved)


def annotate_existing(document, project, mapping, previous=None):
    stamp = now()
    old = previous_metrics(previous)
    if document is None:
        result=copy.deepcopy(previous or dict(kpis=[],tables=[],charts=[],alerts=[]))
        result.update(generated_at=stamp,status='stale' if previous else 'unknown',error='Aggregate source unavailable')
        for item in result.get('kpis',[]):
            item.update(generated_at=stamp,status='stale' if item.get('value') is not None else 'unknown',error='Aggregate source unavailable')
        for kind in ['charts','tables','matrices']:
            for item in result.get(kind,[]):
                item.update(generated_at=stamp,status='stale',error='Aggregate source unavailable')
        return result
    source_stamp=document.get('generated_at')
    out=copy.deepcopy(document)
    out['generated_at']=stamp
    out['source_generated_at']=source_stamp
    age=(dt.datetime.now(dt.timezone.utc)-dt.datetime.fromisoformat(source_stamp.replace('Z','+00:00'))).total_seconds() if source_stamp else None
    stale=age is None or age>mapping['max_age_seconds']
    original={x['id']:x for x in document.get('kpis',[])}
    out['kpis']=[]
    for id, spec in mapping['metrics'].items():
        raw=original.get(id)
        value=raw.get('value') if raw else None
        error='Source document stale' if stale else (None if value is not None else spec.get('gap','Metric absent from successful aggregate'))
        item=metric(id,spec.get('label') or (raw or {}).get('label',id),value,
                    spec.get('unit',(raw or {}).get('unit','')),spec['period'],spec['source'],stamp,
                    spec['category'],error,old.get(id))
        if value is not None:
            item['last_success']=source_stamp
        if raw:
            for field in ['state','hint','delta','delta_label']:
                if field in raw:item[field]=raw[field]
        out['kpis'].append(item)
    for kind in ['tables','charts','matrices']:
        out[kind]=[metadata_object(item,mapping['source'],mapping.get('object_periods',{}).get(item['id'],'source-defined; see inventory'),
                                   source_stamp or stamp,error='Source document stale' if stale else None)
                   for item in document.get(kind,[])]
    if project=='otpuska':
        delivery=next((t for t in out.get('tables',[]) if t['id']=='delivery'),None)
        for row in (delivery or {}).get('rows',[]):
            for field in ['pending','sent','failed','read','cancelled']:
                id='delivery_'+row['channel']+'_'+field
                item=metric(id,'Уведомления '+row['channel']+' '+field,row.get(field),'шт',
                    'current queue state; cumulative DB rows, no date filter','otpuska.API:notifications/delivery',stamp,
                    'noncommercial','Source document stale' if stale else None,old.get(id))
                if row.get(field) is not None:item['last_success']=source_stamp
                out['kpis'].append(item)
    retain_missing_objects(out,previous)
    return finish(out,previous)


def main():
    p=argparse.ArgumentParser()
    p.add_argument('--snapshot',type=Path,required=True)
    p.add_argument('--ops',type=Path,required=True)
    p.add_argument('--panel',type=Path,required=True)
    p.add_argument('--proposal',type=Path,default=Path(__file__).with_name('proposal.json'))
    p.add_argument('--previous-dir',type=Path)
    p.add_argument('--output-dir',type=Path,required=True)
    a=p.parse_args();snap=json.loads(a.snapshot.read_text());ops=json.loads(a.ops.read_text());proposal=json.loads(a.proposal.read_text())
    a.output_dir.mkdir(parents=True,exist_ok=True,mode=0o700)
    for project in ['flux','panel','otpuska']:
        prevpath=a.previous_dir/(project+'.json') if a.previous_dir else None
        previous=json.loads(prevpath.read_text()) if prevpath and prevpath.exists() else None
        if project=='flux':doc=build_flux(snap,ops,previous)
        else:
            document=json.loads(a.panel.read_text()) if project=='panel' else snap.get('otpuska_document')
            doc=annotate_existing(document,project,proposal['projects'][project],previous)
        target=a.output_dir/(project+'.json');target.write_text(json.dumps(doc,ensure_ascii=False,indent=2));target.chmod(0o600)
        print(json.dumps(dict(project=project,kpis=len(doc['kpis']),tables=len(doc.get('tables',[])),charts=len(doc.get('charts',[])),status=doc['status'])))


if __name__=='__main__':main()
