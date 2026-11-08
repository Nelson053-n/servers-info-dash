#!/usr/bin/python3
"""Publish only whitelisted metadata; never send archives, keys or raw worker errors."""
import datetime as dt
import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess


def load(name,file):
    spec=importlib.util.spec_from_file_location(name,file);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m


def database_restore_evidence(proof, receipt, source, now):
    """Only an import of the exact latest SHA-verified archive is evidence."""
    if (proof.get('scope') != 'database_import_from_sha_verified_restic_archive'
            or proof.get('source') != source
            or proof.get('snapshot_id') != receipt.get('snapshot_id')
            or proof.get('archive_sha256') != receipt.get('archive_sha256')):
        raise ValueError('database restore evidence scope mismatch')
    expected={(x['kind'],x.get('container'),x.get('database')) for x in receipt['manifest']['databases']
              if x.get('dump') and x['kind'] in ('postgres','mysql')
              and x.get('database') not in ('mysql','information_schema','performance_schema','sys')}
    checks=proof['checks']
    actual={(x['kind'],x.get('container'),x.get('database')) for x in checks}
    if not expected or expected != actual or len(checks) != len(expected):
        raise ValueError('database restore evidence incomplete')
    if any(x.get('result') != 'passed' or x.get('network') != 'none' for x in checks):
        raise ValueError('database restore import failed')
    verified=dt.datetime.fromisoformat(proof['verified_at'].replace('Z','+00:00'))
    archive=dt.datetime.fromisoformat(receipt['verified_at'].replace('Z','+00:00'))
    if verified.utcoffset()!=dt.timedelta(0) or not archive <= verified <= now:
        raise ValueError('database restore evidence timestamp invalid')
    return proof['verified_at']


if __name__=='__main__':
    contract=load('contract',Path(__file__).with_name('project_status.py'))
    coverage=load('coverage',Path(__file__).with_name('collect-projects.py'))
    transport=load('transport',Path(__file__).with_name('status_publish.py'))
    path=Path('/var/lib/info-backup/projects/status.json');fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
    with os.fdopen(fd,'rb') as f:
        st=os.fstat(f.fileno())
        if not stat.S_ISREG(st.st_mode) or st.st_uid!=os.getuid() or st.st_size>65536:raise SystemExit(1)
        raw=json.load(f)
    now=dt.datetime.now(dt.timezone.utc);sources={}
    for name,row in raw['sources'].items():
        if name not in contract.SOURCES:raise SystemExit(1)
        clean={k:v for k,v in row.items() if k in contract.FIELDS}
        if clean.get('result') == 'success':
            try:
                proof=json.loads((path.parent/'receipts'/(name+'.json')).read_text())
                coverage.validate_database_coverage(proof['manifest'])
                if name in {'ru3','lv3','vm300-code'}:
                    try:
                        dbproof=json.loads((path.parent/'database-restore-proofs'/(name+'.json')).read_text())
                        clean['database_restore_verified_at']=database_restore_evidence(dbproof,proof,name,now)
                        clean['database_restore_result']='passed'
                    except (OSError,ValueError,KeyError,TypeError):
                        clean['database_restore_result']='unknown'
                        clean.pop('database_restore_verified_at',None)
            except (OSError,ValueError,KeyError,RuntimeError):
                clean.update(result='failed',restore_result='failed',error_code='verification_failed')
        clean['protected_projects']=row.get('projects',[])
        sources[name]=clean
    enabled=subprocess.run(['systemctl','is-enabled','--quiet','projects-backup.timer'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL).returncode==0
    d=dict(schema_version=2,source_id='giga-projects',collector_status='ok',observed_at=now.isoformat(),attempted_at=now.isoformat(),schedule_enabled=enabled,sources=sources,check_result=raw.get('check_result','unknown'),last_check_verified_at=raw.get('last_check_verified_at'))
    contract.validate(d,now)
    r=subprocess.run(transport.ssh_argv()[:-1]+['publish-projects-backup-status-v1'],input=json.dumps(d,allow_nan=False).encode(),stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=35,env=transport.CLEAN_ENV)
    if r.returncode==0 and r.stdout in (b'accepted\n',b'already accepted\n'):
        print('delivered');raise SystemExit(0)
    print('delivery_uncertain' if r.returncode not in (64,65) else 'remote_rejected');raise SystemExit(1)
