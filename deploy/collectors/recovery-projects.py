#!/usr/bin/python3
import datetime as dt,json,os,sqlite3,subprocess,urllib.request
from pathlib import Path
OUT=Path('/var/lib/infodash/projects')
def kpi(id,label,value,state='ok',hint=''):return {'id':id,'label':label,'value':value,'state':state,'hint':hint}
def get(url):
 with urllib.request.urlopen(url,timeout=8) as r:
  body=r.read(256*1024)
  try:data=json.loads(body)
  except ValueError:data={}
  return r.status,data
def pg(database,sql,container='nana-wake-recovery-db'):
 command=['docker','exec','-i',container,'sh','-c','exec psql -X -qAt -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" -d '+database]
 return subprocess.run(command,input='BEGIN READ ONLY;\n'+sql+'\nCOMMIT;\n',text=True,capture_output=True,check=True,timeout=15).stdout.strip().split('|')
def status(names):
 result=[]
 for name in names:
  x=json.loads(subprocess.run(['docker','inspect',name],capture_output=True,text=True,check=True,timeout=8).stdout)[0]
  s=x['State'];health=s.get('Health',{}).get('Status','не задан');ok=s['Status']=='running' and health!='unhealthy' and not s['OOMKilled']
  result.append({'name':name,'status':s['Status'],'health':health,'restarts':x['RestartCount'],'state':'ok' if ok else 'bad'})
 return {'id':'runtime','title':'Живые контейнеры RU3','columns':[{'key':'name','label':'Контейнер'},{'key':'status','label':'Состояние'},{'key':'health','label':'Health'},{'key':'restarts','label':'Рестарты','num':True},{'key':'state','label':'Статус','state':True}],'rows':result}
PROJECTS={
'nanabanana':('http://127.0.0.1:8020/api/health',['nana-recovery-api-1','nana-recovery-web-1','nana-wake-recovery-db'],'БД 18.05.2026; только чтение. AI/оплаты отключены. После снимка расход токенов и балансы не восстановлены.'),
'wakeparty':('http://127.0.0.1:8030/api/health',['wakeparty-recovery-app-1','nana-wake-recovery-db'],'Новая текущая БД, не восстановление production. Legacy 62 Booking/4 GiftCard отдельно. Оплаты отключены; BookNow только чтение.'),
'bonds':('http://127.0.0.1:8040/health',['bonds-recovery-app-1'],'SQLite из копии 29.10.2026. Брокерская синхронизация, LLM и платные API отключены; актуальная рыночная стоимость не рассчитана.'),
'cars':('http://127.0.0.1:8050/',['cars-recovery-app-1'],'Production volume не найден. Восстановлены код и локальные справочники; статистика клиентов/заявок не восстановлена.'),
'flux':('http://127.0.0.1:8011/api/v1/ready',['flux-recovery-api-1','flux-recovery-web-1','flux-recovery-db-1'],'Копия Flux БД 24.07.2026: 2 subscriptions, 453 snapshots, 105 alerts (проверено при восстановлении). Сейчас проверяется /api/v1/ready; исторические счётчики не live. Telegram worker выключен; actual PA недоступны.')}
for project,(url,names,note) in PROJECTS.items():
 doc={'generated_at':dt.datetime.now(dt.timezone.utc).isoformat(timespec='seconds'),'kpis':[],'tables':[],'charts':[],'alerts':[{'severity':'warn','text':note}]}
 try:
  code,body=get(url);doc['kpis'].append(kpi('health','HTTP health',code,'ok' if code==200 else 'bad','Проверено на RU3 сейчас; это доступность, не полнота данных'))
  doc['tables'].append(status(names))
  if project=='nanabanana':
   values=pg('nanabanana','SELECT (SELECT count(*) FROM "User"),(SELECT count(*) FROM "Generation"),(SELECT count(*) FROM "Transaction"),(SELECT max("createdAt") FROM "Generation");')
   for id,label,v in zip(['users','generations','transactions'],['Пользователи в копии','Генерации в копии','Транзакции в копии'],values):doc['kpis'].append(kpi(id,label,int(v),'warn','Источник: восстановленная БД 18.05.2026'))
   doc['kpis'].append(kpi('snapshot_latest','Последняя генерация в БД',values[3],'warn'));doc['kpis'].append(kpi('mode','Режим',body.get('mode','read_only_recovery'),'warn'))
  elif project=='wakeparty':
   values=pg('wakeparty','SELECT (SELECT count(*) FROM "GiftCard"),(SELECT count(*) FROM "PendingBooking"),(SELECT count(*) FROM "CrmBooking"),(SELECT count(*) FROM "CrmCustomer");')
   for id,label,v in zip(['giftcards','pending_bookings','crm_bookings','crm_customers'],['Сертификаты в новой БД','Брони в новой БД','CRM брони в новой БД','CRM клиенты в новой БД'],values):doc['kpis'].append(kpi(id,label,int(v),'warn','Измерено в текущей новой БД; legacy и BookNow сюда не входят'))
   code,services=get('http://127.0.0.1:8030/api/services')
   if isinstance(services,list):count=len(services)
   elif isinstance(services,dict):
    candidate=services.get('services',services.get('data'));count=len(candidate) if isinstance(candidate,list) else None
   else:count=None
   if count is not None:doc['kpis'].append(kpi('booknow_services','Услуги BookNow',count,hint='Живой readonly GET /api/services'))
  elif project=='bonds':
   db=sqlite3.connect('file:/opt/bonds-recovery/data/portfolio.db?mode=ro',uri=True)
   for table,label in [('users','Пользователи в копии'),('portfolios','Портфели в копии'),('portfolio_items','Позиции в копии')]:doc['kpis'].append(kpi(table,label,db.execute('SELECT count(*) FROM '+table).fetchone()[0],'warn','Источник: SQLite 29.10.2026, без синхронизации брокера'))
   db.close();doc['kpis'].append(kpi('snapshot','Копия БД','29.10.2026','warn'))
  elif project=='cars':
   doc['kpis'].append(kpi('production_data','Данные production','Не найдены','warn'))
   files=Path('/opt/cars-recovery/data');rows=[]
   for file in sorted(files.glob('*.json')):
    json.loads(file.read_text());rows.append({'file':file.name,'bytes':file.stat().st_size,'source':'Восстановленный локальный справочник','state':'warn'})
   doc['kpis'].append(kpi('reference_files','Справочники JSON',len(rows),'warn','Наличие/валидность файлов проверены сейчас; это не восстановление production volume'))
   doc['tables'].append({'id':'sources','title':'Доступные источники','columns':[{'key':'file','label':'Файл'},{'key':'bytes','label':'Байт','num':True},{'key':'source','label':'Ограничение'},{'key':'state','label':'Статус','state':True}],'rows':rows})
  elif project=='flux':
   values=pg('fluxscope','SELECT (SELECT count(*) FROM telegram_subscriptions),(SELECT count(*) FROM node_status_snapshots),(SELECT count(*) FROM alerts_history),(SELECT max(updated_at) FROM node_status_snapshots);','flux-recovery-db-1')
   for id,label,v in zip(['subscriptions','snapshots','alerts'],['Подписки в копии','Снимки нод в БД','Алерты в БД'],values):doc['kpis'].append(kpi(id,label,int(v),'warn','Восстановленная историческая БД, не свежая prod-копия'))
   doc['kpis'].append(kpi('last_snapshot','Последний snapshot в БД',values[3],'warn'))
 except Exception as e:doc['alerts'].append({'severity':'bad','text':'Ошибка источника: '+type(e).__name__})
 dest=OUT/(project+'.json');tmp=OUT/('.'+project+'.tmp');tmp.write_text(json.dumps(doc,ensure_ascii=False));os.chmod(tmp,0o644);os.replace(tmp,dest)
 print(json.dumps({'project':project,'kpis':len(doc['kpis']),'tables':len(doc['tables']),'source_error':any(x['severity']=='bad' for x in doc['alerts'])}))
