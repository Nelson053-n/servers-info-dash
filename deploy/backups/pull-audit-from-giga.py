#!/usr/bin/python3
"""Private admin transfer of a small compressed DB audit payload via existing QGA.

Run on vm-claude. No new guest keys, listeners, ports or relaxed SSH checks.
"""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import shlex
import subprocess


def guest(code):
    encoded=base64.b64encode(code.encode()).decode()
    cmd='qm guest exec 310 --timeout 60 -- /usr/bin/python3 -c '+shlex.quote('import base64;exec(base64.b64decode('+repr(encoded)+'))')
    p=subprocess.run(['ssh','-o','BatchMode=yes','-o','StrictHostKeyChecking=yes','-o','ConnectTimeout=10','root@192.168.10.100',cmd],stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=90)
    if p.returncode:raise RuntimeError('guest transfer command failed')
    d=json.loads(p.stdout)
    if d.get('exitcode')!=0 or d.get('out-truncated'):raise RuntimeError('guest transfer response invalid')
    return d.get('out-data','').strip()


def main():
    parser=argparse.ArgumentParser();parser.add_argument('source',choices=['ru3','lv3','vm300-code']);parser.add_argument('--into',required=True,type=Path);a=parser.parse_args()
    os.umask(0o077)
    folder=a.into.resolve();st=folder.stat();assert folder.is_dir() and st.st_uid==os.getuid() and st.st_mode & 0o077==0
    # QGA is outside the collector's private BindPaths mount namespace.
    source='/srv/restic/projects-staging/'+a.source+'-db-restore-audit.tar.gz'
    meta=json.loads(guest("from pathlib import Path\nimport hashlib,json\np=Path("+repr(source)+")\nh=hashlib.sha256()\nwith p.open('rb') as f:\n for b in iter(lambda:f.read(2**20),b''):h.update(b)\nprint(json.dumps({'size':p.stat().st_size,'sha256':h.hexdigest()}))"))
    assert 0<meta['size']<2**31
    dest=folder/(a.source+'-db-restore-audit.tar.gz');assert dest.parent==folder
    digest=hashlib.sha256();chunk=256*1024
    with dest.open('xb') as output:
        for offset in range(0,meta['size'],chunk):
            n=min(chunk,meta['size']-offset)
            text=guest("import base64\nwith open("+repr(source)+",'rb') as f:\n f.seek("+str(offset)+");print(base64.b64encode(f.read("+str(n)+")).decode())")
            data=base64.b64decode(text,validate=True);assert len(data)==n
            output.write(data);digest.update(data)
    assert digest.hexdigest()==meta['sha256'], 'audit payload checksum mismatch'
    print(json.dumps({'source':a.source,'private_bytes':meta['size'],'transfer_sha_verified':True}))

if __name__=='__main__':main()
