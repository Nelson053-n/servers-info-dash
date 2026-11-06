import json,os,stat
from pathlib import Path
source=Path('/var/lib/infodash/projects/backups/projects-current.json')
if not source.exists():source=Path('/var/lib/infodash/projects/backups/current.json')
s=source.lstat()
assert stat.S_ISREG(s.st_mode) and s.st_size<=65536
raw=json.loads(source.read_text())
allowed={'generated_at','last_success','stale','status','error','kpis','tables','charts','alerts','limitations'}
doc={k:v for k,v in raw.items() if k in allowed}
assert isinstance(doc.get('kpis'),list) and doc.get('generated_at')
for item in doc['kpis']:
 item.update(source='Giga: проверенные результаты резервирования',period='На момент наблюдения')
doc['source']='Giga: результаты и фактический охват резервирования'
legacy=Path('/var/lib/infodash/projects/backups/current.json')
if source.name=='projects-current.json' and legacy.exists():
 import datetime as dt
 old=json.loads(legacy.read_text());observed=old.get('generated_at');metrics={x['id']:x for x in old.get('kpis',[])}
 if observed:
  age=(dt.datetime.now(dt.timezone.utc)-dt.datetime.fromisoformat(observed.replace('Z','+00:00'))).total_seconds()
  free=metrics.get('free_space',{})
  doc['kpis'].append(dict(id='giga_free_space',metric='giga_free_space',label='Свободно на Giga',value=free.get('value'),unit='ГиБ',period='На момент наблюдения диска',source='Giga: пространство backup-диска',generated_at=observed,last_success=observed,status='stale' if age>1800 else free.get('status','unknown'),error='Наблюдение диска устарело' if age>1800 else None))
  if age<=1800 and isinstance(free.get('value'),(int,float)) and free['value']<30:doc['alerts'].append(dict(severity='bad' if free['value']<20 else 'warn',text='Мало свободного места на Giga для следующих копий'))
  doc['tables'].append(dict(id='local_info_code',title='Дополнительно: локальный Info CT120',columns=[dict(key='source',label='Источник'),dict(key='backup',label='Последняя копия UTC'),dict(key='restore',label='Проверка восстановления UTC'),dict(key='scope',label='Охват')],rows=[dict(source='Локальный Info CT120',backup=metrics.get('last_backup',{}).get('value'),restore=metrics.get('restore',{}).get('value'),scope='Только код; отдельно от рабочего публичного Info')],generated_at=observed,last_success=observed,source='Отдельный источник CT120',period='Последнее наблюдение',status='stale' if age>1800 else 'ok',error=None))
target=Path('/var/lib/infodash/projects/backups-visible.json');tmp=target.with_suffix('.tmp');tmp.write_text(json.dumps(doc,ensure_ascii=False));tmp.chmod(0o644);os.replace(tmp,target)
print(json.dumps({'metadata_published':True,'observed_at':doc['generated_at'],'scope':'local Info CT120 only'}))
