#!/usr/bin/python3
"""Pull fixed source exports into an encrypted append-only repository on Giga."""
import datetime as dt
import fcntl
import hashlib
import json
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
import tarfile

BASE=Path('/var/lib/info-backup/projects')
STAGE=Path('/var/lib/info-backup/projects/staging')
SOURCES=Path('/opt/info-backup/project-sources.json')


def stamp():return dt.datetime.now(dt.timezone.utc).isoformat()


def digest(path):
    h=hashlib.sha256()
    with path.open('rb') as f:
        for block in iter(lambda:f.read(4*2**20),b''):h.update(block)
    return h.hexdigest()


def restic(args,env):
    p=subprocess.run(['/usr/bin/restic']+args,env=env,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=3600)
    if p.returncode:raise RuntimeError('repository_operation_failed')
    return p.stdout


def validate_database_coverage(manifest):
    if manifest.get('skipped'):
        raise RuntimeError('required_database_coverage_missing')
    required = {
        'ru3': {('mysql','globalauto-db-1','globalauto'),('postgres','nana-wake-recovery-db','nanabanana'),('postgres','nana-wake-recovery-db','wakeparty'),('postgres','flux-recovery-db-1','fluxscope'),('redis','nana-recovery-redis-1',None),('redis','flux-recovery-redis-1',None)},
        'lv3': {('mysql','amnezia-panel-db','amnezia_panel')},
        'vm300-code': {('mysql','004a973abee7_amnezia-panel-db','amnezia_panel'),('postgres','native','wakeparty'),('postgres','fluxscope_pg','fluxscope'),('redis','fluxscope_redis',None)},
    }.get(manifest.get('source'), set())
    actual = {(x.get('kind'),x.get('container'),x.get('database')) for x in manifest['databases'] if x.get('dump')}
    if not required <= actual:
        raise RuntimeError('required_database_coverage_missing')


def verify_archive(path,folder):
    with tarfile.open(path,'r:') as tar:
        members=[m for m in tar if m.name=='./manifest.json']
        if len(members)!=1:raise RuntimeError('manifest_invalid')
        m=members[0]
        if m.size>2**20:raise RuntimeError('manifest_size_invalid')
        manifest=json.load(tar.extractfile(m))
        validate_database_coverage(manifest)
        for db in manifest['databases']:
            if db.get('dump'):
                member=tar.getmember('./'+db['dump'])
                if not member.isfile() or member.size == 0:
                    raise RuntimeError('database_dump_empty')
        for i,db in enumerate(manifest['databases']):
            if db['kind']!='sqlite':continue
            member=tar.getmember('./'+db['dump'])
            target=folder/('verify-'+str(i)+'.sqlite')
            with tar.extractfile(member) as source,target.open('wb') as output:shutil.copyfileobj(source,output)
            c=sqlite3.connect(target.as_uri()+'?mode=ro',uri=True)
            try:
                if c.execute('PRAGMA integrity_check').fetchall()!=[('ok',)]:raise RuntimeError('sqlite_restore_failed')
            finally:c.close();target.unlink()
    return manifest


def main():
    os.umask(0o077);BASE.mkdir(mode=0o700,exist_ok=True)
    lock=(BASE/'lock').open('a');fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
    env={'PATH':'/usr/bin:/bin','HOME':'/var/lib/info-backup','LANG':'C.UTF-8','GOMAXPROCS':'1',
         'RESTIC_REPOSITORY':'rest:http://127.0.0.1:8000/projects/',
         'RESTIC_PASSWORD_FILE':str(BASE/'repository-password'),
         'RESTIC_REST_USERNAME':'info-backup',
         'RESTIC_REST_PASSWORD':Path('/var/lib/info-backup/secrets/api-password').read_text().strip()}
    if not (BASE/'initialized').exists():
        restic(['init'],env);(BASE/'initialized').write_text(stamp())
    status_path=BASE/'status.json'
    prior=json.loads(status_path.read_text()) if status_path.exists() else {'sources':{}}
    all_ok=True
    for source in json.loads(SOURCES.read_text()):
        name=source['id'];row=dict(prior['sources'].get(name,{}));row.update(attempted_at=stamp(),projects=source['projects'],result='failed',error_code='export_failed')
        folder=STAGE/name;folder.mkdir(mode=0o700,exist_ok=True)
        archive=folder/'source.tar';restore=folder/'restored'
        try:
            if shutil.disk_usage(STAGE).free<30*2**30:raise RuntimeError('storage_space_low')
            ssh=['ssh','-C','-F','/dev/null','-T','-i','/var/lib/info-backup/.ssh/projects-export',
                 '-o','IdentitiesOnly=yes','-o','IdentityAgent=none','-o','BatchMode=yes','-o','StrictHostKeyChecking=yes',
                 '-o','UserKnownHostsFile=/var/lib/info-backup/.ssh/known_hosts.projects',
                 '-o','GlobalKnownHostsFile=/dev/null','-o','ConnectTimeout=10',
                 '-o','ServerAliveInterval=15','-o','ServerAliveCountMax=3',
                 source.get('user','projects-backup-source')+'@'+source['host'],'export-projects-v1']
            with archive.open('wb') as output:
                process=subprocess.Popen(ssh,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL)
                try:
                    while True:
                        block=process.stdout.read(2**20)
                        if not block:break
                        if shutil.disk_usage(STAGE).free<20*2**30:raise RuntimeError('storage_space_low')
                        output.write(block)
                    if process.wait(timeout=30):raise RuntimeError('export_failed')
                finally:
                    if process.poll() is None:process.kill();process.wait()
            manifest=verify_archive(archive,folder)
            if manifest['source']!=name or set(manifest['projects'])!=set(source['projects']):raise RuntimeError('source_scope_mismatch')
            expected=digest(archive)
            raw=restic(['backup','--json','--tag','source='+name,str(archive)],env)
            summary=next(json.loads(line) for line in raw.splitlines() if json.loads(line).get('message_type')=='summary')
            row.update(last_backup_success_at=stamp(),result='success',error_code=None,logical_bytes=archive.stat().st_size)
            restic(['restore',summary['snapshot_id'],'--target',str(restore)],env)
            copies=list(restore.rglob('source.tar'))
            if len(copies)!=1 or digest(copies[0])!=expected:raise RuntimeError('archive_restore_mismatch')
            verify_archive(copies[0],folder)
            row.update(last_restore_verified_at=stamp(),restore_result='passed',restore_scope='archive_sha_and_sqlite_integrity',database_dumps=sum(1 for item in manifest['databases'] if item.get('dump')))
            receipts=BASE/'receipts';receipts.mkdir(mode=0o700,exist_ok=True)
            proof=receipts/(name+'.json');temporary=proof.with_suffix('.tmp');temporary.write_text(json.dumps({'source':name,'snapshot_id':summary['snapshot_id'],'archive_sha256':expected,'verified_at':row['last_restore_verified_at'],'manifest':manifest}));os.replace(temporary,proof)
        except Exception as exc:
            all_ok=False;row.update(error_code=str(exc) if str(exc) in {'export_failed','storage_space_low','source_scope_mismatch','repository_operation_failed','archive_restore_mismatch','sqlite_restore_failed'} else 'verification_failed')
            row['result']='failed'
            row['restore_result']='failed'
        finally:
            archive.unlink(missing_ok=True)
            if restore.exists():shutil.rmtree(restore)
        prior['sources'][name]=row;prior['observed_at']=stamp()
        tmp=status_path.with_suffix('.tmp');tmp.write_text(json.dumps(prior));os.replace(tmp,status_path)
        print(json.dumps({'source':name,'result':row['result'],'restore':row.get('restore_result'),'error_code':row.get('error_code')}),flush=True)
    try:
        restic(['check','--read-data'],env);prior['last_check_verified_at']=stamp();prior['check_result']='passed'
    except Exception:all_ok=False;prior['check_result']='failed'
    prior['observed_at']=stamp();tmp=status_path.with_suffix('.tmp');tmp.write_text(json.dumps(prior));os.replace(tmp,status_path)
    return 0 if all_ok else 1


if __name__=='__main__':raise SystemExit(main())
