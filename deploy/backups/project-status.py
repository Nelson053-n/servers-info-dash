"""Metadata contract for Giga project backups. Never accepts repository or file contents."""
import datetime as dt
from pathlib import Path
import json
import subprocess

UTC=dt.timezone.utc
SOURCES={'ru2':{'info-public':'Info (публичный)','bonds':'BondAI'},'ru3':{'nanabanana':'Бананоген','wakeparty':'Wakeparty','flux':'FluxRadar','globalauto':'GlobalAuto','cars':'Машины','kendo':'KendoSolki','trade':'Трейдинг'},'lv3':{'vpn':'OneYearSolution'},'vm300-code':{'local-project-code':'Рабочие копии проектов'},'kuma-host':{'kuma':'Uptime Kuma'}}
MISSING={}
DEFERRED={'otpuska':'График отпусков'}
FIELDS={'result','restore_result','error_code','last_backup_success_at','last_restore_verified_at','logical_bytes','protected_projects'}
ERRORS={None,'export_failed','storage_space_low','source_scope_mismatch','repository_operation_failed','archive_restore_mismatch','sqlite_restore_failed','verification_failed'}


def when(s):
    if not isinstance(s,str):raise ValueError('timestamp required')
    d=dt.datetime.fromisoformat(s.replace('Z','+00:00'))
    if d.utcoffset()!=dt.timedelta(0):raise ValueError('UTC required')
    return d


def validate(d,now):
    if not isinstance(d,dict) or set(d)-{'schema_version','source_id','collector_status','observed_at','attempted_at','schedule_enabled','sources','last_check_verified_at','check_result'}:raise ValueError('unexpected fields')
    if type(d.get('schema_version')) is not int or d['schema_version']!=2 or d.get('source_id')!='giga-projects' or d.get('collector_status')!='ok':raise ValueError('scope mismatch')
    observed=when(d['observed_at']);attempted=when(d['attempted_at'])
    if not observed<=attempted<=now+dt.timedelta(minutes=5):raise ValueError('future observation')
    if type(d.get('schedule_enabled')) is not bool:raise ValueError('schedule required')
    if not isinstance(d.get('sources'),dict) or set(d['sources'])-set(SOURCES):raise ValueError('source mismatch')
    for source,row in d['sources'].items():
        if not isinstance(row,dict) or set(row)-FIELDS:raise ValueError('private fields forbidden')
        if row.get('result') not in {'success','failed','unknown'} or row.get('restore_result','unknown') not in {'passed','failed','unknown'} or row.get('error_code') not in ERRORS:raise ValueError('invalid result')
        protected=row.get('protected_projects',[])
        if not isinstance(protected,list) or any(type(x) is not str for x in protected) or set(protected)-set(SOURCES[source]):raise ValueError('unknown protected project')
        for k in ['last_backup_success_at','last_restore_verified_at']:
            if row.get(k) is not None and when(row[k])>observed:raise ValueError('future evidence')
        if row.get('result')=='success' and not row.get('last_backup_success_at'):raise ValueError('success without evidence')
        if row.get('restore_result')=='passed' and not row.get('last_restore_verified_at'):raise ValueError('restore without evidence')
        size=row.get('logical_bytes')
        if size is not None and (type(size) is not int or not 0<=size<2**63):raise ValueError('invalid size')
    if d.get('check_result','unknown') not in {'passed','failed','unknown'}:raise ValueError('invalid check')
    if d.get('last_check_verified_at') is not None and when(d['last_check_verified_at'])>observed:raise ValueError('future check')
    if d.get('check_result')=='passed' and not d.get('last_check_verified_at'):raise ValueError('check without evidence')
    return d


def display_date(value):
    return when(value).astimezone(dt.timezone(dt.timedelta(hours=10))).strftime('%d.%m.%Y %H:%M') if value else None


def analytics(d,now):
    rows=[];good=0;alerts=[];emitted=set();stale=(now-when(d['observed_at'])).total_seconds()>1800
    for source,projects in SOURCES.items():
        r=d['sources'].get(source,{})
        overdue=not r.get('last_backup_success_at') or (now-when(r['last_backup_success_at'])).total_seconds()>36*3600
        healthy=r.get('result')=='success' and not overdue and not stale
        for id,name in projects.items():
            if id=='local-project-code':continue
            protected=healthy and id in r.get('protected_projects',[])
            if protected:good+=1
            text='Копия проверена' if protected and r.get('restore_result')=='passed' else 'Копия есть; проверка не завершена' if protected else 'Ошибка копирования' if r.get('result')=='failed' else 'Нет свежей копии'
            rows.append(dict(project=name,status=text,last_backup=display_date(r.get('last_backup_success_at')),last_restore=display_date(r.get('last_restore_verified_at')),scope={'info-public':'Код, настройки, доступы и образ','bonds':'Код, SQLite и образ','nanabanana':'Код, загрузки, PostgreSQL, Redis, образы','wakeparty':'Код, PostgreSQL и образ','flux':'Сайт, API, PostgreSQL и Redis','globalauto':'WordPress, загрузки и MariaDB','cars':'Приложение, файлы данных и образ','kendo':'Файлы восстановленного статического сайта','trade':'Код, настройки и состояния sandbox','vpn':'Панель, MySQL и сохранённые конфигурации нод','kuma':'SQLite, настройки и образ'}.get(id,'Текущее состояние')))
            label={'ru2':'Публичный Info и BondAI','ru3':'Проекты на RU3','lv3':'OneYearSolution','kuma-host':'Uptime Kuma'}.get(source,source)
            if not protected and (source,'copy') not in emitted:
                emitted.add((source,'copy'));alerts.append(dict(severity='bad' if r.get('result')=='failed' else 'warn',text=label+': '+('ошибка копирования' if r.get('result')=='failed' else 'свежая копия подтверждена не для всех проектов')+'; охват указан в таблице'))
            elif protected and r.get('restore_result')!='passed' and (source,'restore') not in emitted:
                emitted.add((source,'restore'));alerts.append(dict(severity='bad' if r.get('restore_result')=='failed' else 'warn',text=label+': проверка восстановления архива не пройдена'))
    rows.extend(dict(project=name,status='Не подключен',last_backup=None,last_restore=None,scope='Рабочий источник и база не подтверждены') for name in MISSING.values())
    rows.extend(dict(project=name,status='Отложен владельцем',last_backup=None,last_restore=None,scope='Нужен новый SSH-маршрут к Bob; рабочая база пока не копируется') for name in DEFERRED.values())
    for name in MISSING.values():alerts.append(dict(severity='warn',text=name+': резервирование рабочего источника ещё не подключено'))
    if not d['schedule_enabled']:alerts.append(dict(severity='warn',text='Автоматическое расписание полных копий ещё не включено'))
    if d.get('check_result')=='failed':alerts.append(dict(severity='bad',text='Проверка целостности репозитория завершилась ошибкой'))
    elif d.get('check_result')!='passed':alerts.append(dict(severity='warn',text='Полная проверка чтением репозитория ещё не завершена'))
    local=d['sources'].get('vm300-code',{})
    if local.get('result')!='success' or local.get('restore_result')!='passed':alerts.append(dict(severity='bad' if local.get('result')=='failed' else 'warn',text='Рабочие копии проектов и локальные базы: резервирование ещё не подтверждено'))
    extra_table=dict(id='working_copy_backups',title='Дополнительно: рабочие копии и локальные базы',columns=[dict(key=k,label=v) for k,v in [('source','Источник'),('status','Копия'),('backup','Последний успех ВЛД'),('restore','Проверка архива ВЛД')]],rows=[dict(source='Рабочие копии проектов и локальные БД',status='Архив проверен' if local.get('result')=='success' and local.get('restore_result')=='passed' else 'Ещё не подтверждено',backup=display_date(local.get('last_backup_success_at')),restore=display_date(local.get('last_restore_verified_at')))],source='Giga: отдельный источник рабочей VM',period='Последние результаты',generated_at=d['observed_at'],last_success=d['observed_at'],status='stale' if stale else 'ok',error=None)
    metrics=[]
    for id,label,value,unit in [('covered','Проекты со свежей копией',good,'шт'),('expected','Проектов в охвате',sum(len(x) for x in SOURCES.values())-1+len(MISSING),'шт'),('check','Репозиторий проверен чтением',(display_date(d['last_check_verified_at'])+' ВЛД') if d.get('last_check_verified_at') else None,''),('schedule','Автоматическое копирование','Ежедневно в 01:30 ВЛД' if d['schedule_enabled'] else 'Не включено','')]:
        metrics.append(dict(id=id,metric=id,label=label,value=value,unit=unit,period='На момент наблюдения',source='Giga: резервирование проектов',generated_at=d['observed_at'],last_success=d['observed_at'],status='stale' if stale else 'ok',error=None))
    limitations=[dict(id='backup_restore_scope',title='Что проверено при восстановлении',impact='Восстановление архива из Restic, совпадение SHA и целостность SQLite. Запуск PostgreSQL/MySQL и приложений из копии пока отдельно не проверен.',action='Проверить восстановление серверных баз и запуск приложений в изоляции.'),dict(id='backup_offsite_retention',title='Копии находятся на одном Giga',impact='Независимая внешняя копия не подключена. Удаление старых копий пока не включено.',action='Согласовать внешнее хранилище и политику хранения.')]
    return dict(generated_at=d['observed_at'],last_success=d['observed_at'],status='stale' if stale else 'partial' if alerts else 'ok',stale=stale,kpis=metrics,tables=[dict(id='project_backup_coverage',title='Охват проектов и баз',columns=[dict(key=k,label=v) for k,v in [('project','Проект'),('status','Копия'),('last_backup','Последняя копия ВЛД'),('last_restore','Проверка архива ВЛД'),('scope','Охват')]],rows=rows,source='Giga: подтверждённые результаты',period='Последние результаты',generated_at=d['observed_at'],last_success=d['observed_at'],status='stale' if stale else 'ok',error=None),extra_table],charts=[],alerts=alerts,limitations=limitations,error=None)


def receive(data,directory,now):
    import fcntl,hashlib,os,stat
    d=validate(data,now)
    lock=os.open(directory/'.projects.lock',os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o600)
    try:
        s=os.fstat(lock)
        if not stat.S_ISREG(s.st_mode) or s.st_uid!=os.getuid() or s.st_nlink!=1:raise ValueError('lock rejected')
        fcntl.flock(lock,fcntl.LOCK_EX)
        name=directory/'projects-current.json';prior=None
        try:
            fd=os.open(name,os.O_RDONLY|os.O_NOFOLLOW)
        except FileNotFoundError:pass
        else:
            with os.fdopen(fd,'rb') as f:
                s=os.fstat(f.fileno())
                if not stat.S_ISREG(s.st_mode) or s.st_uid!=os.getuid() or s.st_size>65536:raise ValueError('prior rejected')
                prior=json.load(f)
        digest=hashlib.sha256(json.dumps(d,sort_keys=True,separators=(',',':')).encode()).hexdigest()
        if prior:
            old=when(prior['_last_attempt_at']);current=when(d['attempted_at'])
            if current<old:raise ValueError('replay')
            if current==old:
                if prior['_source_digest']==digest:return 'already accepted'
                raise ValueError('conflicting retry')
        doc=analytics(d,now);doc['_last_attempt_at']=d['attempted_at'];doc['_source_digest']=digest
        raw=json.dumps(doc,ensure_ascii=False,allow_nan=False).encode()
        if len(raw)>65536:raise ValueError('normalized output too large')
        tmp=directory/('.projects-'+os.urandom(16).hex());fd=os.open(tmp,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o644)
        try:
            with os.fdopen(fd,'wb') as f:os.fchmod(f.fileno(),0o644);f.write(raw);f.flush();os.fsync(f.fileno())
            os.replace(tmp,name)
        finally:tmp.unlink(missing_ok=True)
        return 'accepted'
    finally:os.close(lock)
