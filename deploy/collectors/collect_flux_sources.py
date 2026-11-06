"""Run read-only on RU3; stdout is an aggregate envelope, not a deployment."""
import datetime as dt
import json
from pathlib import Path
import subprocess
import urllib.request

WALLET='t1MRWH9Q9sWA1XvqmwGoWqynaFFquq8pb7K'
def stamp():return dt.datetime.now(dt.timezone.utc).isoformat()
def cmd(args,data=None):
    return subprocess.check_output(args,input=data,text=True,timeout=10).strip()

def read_flux_sources():
    result={'at':stamp(),'flux':{},'ops':{}}
    for name,path in [('health','health'),('ready','ready'),('price','network/price'),
                      ('price_history','network/price/history'),('network_nodes','network/nodes'),
                      ('wallet_summary','wallet/'+WALLET+'/summary'),('wallet_nodes','wallet/'+WALLET+'/nodes')]:
        try:
            with urllib.request.urlopen('http://127.0.0.1:8011/api/v1/'+path,timeout=10) as response:
                raw=response.read()
                try:body=json.loads(raw)
                except ValueError:body=raw.decode().strip()
                result['flux'][name]={'http':response.status,'body':body,'last_success':stamp()}
        except Exception as exc:result['flux'][name]={'http':getattr(exc,'code',None),'error':type(exc).__name__}
    try:
        query="""BEGIN READ ONLY;
    SET LOCAL statement_timeout='5s';
    SELECT json_build_object('subscriptions',(SELECT count(*) FROM telegram_subscriptions),
    'snapshots',(SELECT count(*) FROM node_status_snapshots),'alerts',(SELECT count(*) FROM alerts_history),
    'snapshot_last_seen',(SELECT max(last_seen_at) FROM node_status_snapshots),
    'snapshot_updated',(SELECT max(updated_at) FROM node_status_snapshots),'last_alert',(SELECT max(sent_at) FROM alerts_history));
    ROLLBACK;"""
        raw=cmd(['docker','exec','-i','flux-recovery-db-1','sh','-c',
                 'psql -X -q -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" -d "$POSTGRES_DB" -At'],query)
        result['ops']['pg']=json.loads(raw)
    except Exception as exc:result['ops']['pg_error']=type(exc).__name__
    date=dt.datetime.now(dt.timezone.utc).strftime('%Y-%m-%d')
    result['ops'].update(generated_at=stamp(),visitor_day_utc=date,visitor_pfcount={})
    try:
        raw=cmd(['docker','ps','-a','--filter','label=com.docker.compose.project=flux-recovery','--format',
                 '{"name":{{json .Names}},"state":{{json .State}},"status":{{json .Status}}}'])
        result['ops']['containers']=[json.loads(line) for line in raw.splitlines()]
    except Exception as exc:result['ops']['containers_error']=type(exc).__name__
    for name,key in [('total','visitors:total'),('today','visitors:day:'+date)]:
        try:
            exists=int(cmd(['docker','exec','flux-recovery-redis-1','redis-cli','EXISTS',key]))
            result['ops']['visitor_pfcount'][name]=int(cmd(['docker','exec','flux-recovery-redis-1','redis-cli','PFCOUNT',key])) if exists else None
        except Exception as exc:result['ops']['visitor_'+name+'_error']=type(exc).__name__
    try:result['otpuska_document']=json.loads(Path('/var/lib/infodash/projects/otpuska.json').read_text())
    except Exception as exc:result['otpuska_error']=type(exc).__name__
    return result


if __name__=='__main__':
    print(json.dumps(read_flux_sources(),ensure_ascii=False,indent=2))
