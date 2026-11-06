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


if __name__=='__main__':
    contract=load('contract',Path(__file__).with_name('project_status.py'))
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
        clean['protected_projects']=row.get('projects',[])
        sources[name]=clean
    enabled=subprocess.run(['systemctl','is-enabled','--quiet','projects-backup.timer'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL).returncode==0
    d=dict(schema_version=2,source_id='giga-projects',collector_status='ok',observed_at=now.isoformat(),attempted_at=now.isoformat(),schedule_enabled=enabled,sources=sources,check_result=raw.get('check_result','unknown'),last_check_verified_at=raw.get('last_check_verified_at'))
    contract.validate(d,now)
    r=subprocess.run(transport.ssh_argv()[:-1]+['publish-projects-backup-status-v1'],input=json.dumps(d,allow_nan=False).encode(),stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=35,env=transport.CLEAN_ENV)
    if r.returncode==0 and r.stdout in (b'accepted\n',b'already accepted\n'):
        print('delivered');raise SystemExit(0)
    print('delivery_uncertain' if r.returncode not in (64,65) else 'remote_rejected');raise SystemExit(1)
