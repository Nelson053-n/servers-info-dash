#!/usr/bin/python3
"""Materialize only DB dumps from one verified Restic archive for isolated restore tests.

Run as info-backup with the normal staging BindPaths. Output is PRIVATE payload.
No application files, environment files, Docker inspect, or credentials are exported.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile

BASE=Path('/var/lib/info-backup/projects')
STAGE=BASE/'staging'

class HashedReader:
    def __init__(self,stream):self.stream=stream;self.sha=hashlib.sha256()
    def read(self,size=-1):
        data=self.stream.read(size);self.sha.update(data);return data


def main():
    parser=argparse.ArgumentParser();parser.add_argument('source',choices=['ru3','lv3','vm300-code']);args=parser.parse_args()
    os.umask(0o077)
    receipt=json.loads((BASE/'receipts'/(args.source+'.json')).read_text())
    snapshot=receipt['snapshot_id'];expected=receipt['archive_sha256']
    assert len(expected)==64 and snapshot and all(c in '0123456789abcdef' for c in snapshot)
    selected=[x for x in receipt['manifest']['databases'] if x.get('dump') and x['kind'] in ('postgres','mysql') and x.get('database') not in ('mysql','information_schema','performance_schema','sys')]
    assert selected
    by_name={'./'+x['dump']:x for x in selected}
    env={'PATH':'/usr/bin:/bin','HOME':'/var/lib/info-backup','LANG':'C.UTF-8','GOMAXPROCS':'1',
         'RESTIC_REPOSITORY':'rest:http://127.0.0.1:8000/projects/',
         'RESTIC_PASSWORD_FILE':str(BASE/'repository-password'),'RESTIC_REST_USERNAME':'info-backup',
         'RESTIC_REST_PASSWORD':Path('/var/lib/info-backup/secrets/api-password').read_text().strip()}
    output=STAGE/(args.source+'-db-restore-audit.tar.gz')
    assert not output.exists(), 'audit payload already exists: review rather than overwrite'
    with tempfile.TemporaryDirectory(prefix='db-audit-'+args.source+'-',dir=STAGE) as temp:
        folder=Path(temp);records=[]
        proc=subprocess.Popen(['/usr/bin/restic','dump',snapshot,str(STAGE/args.source/'source.tar')],env=env,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL)
        stream=HashedReader(proc.stdout)
        try:
            with tarfile.open(fileobj=stream,mode='r|') as tar:
                for member in tar:
                    row=by_name.get(member.name)
                    if row is None:continue
                    assert member.isfile() and member.size>0
                    assert not any(x['dump']==row['dump'] for x in records), 'duplicate dump member'
                    name=f'dump-{len(records)}'+('.dump' if row['kind']=='postgres' else '.sql')
                    with tar.extractfile(member) as src,(folder/name).open('xb') as dst:shutil.copyfileobj(src,dst)
                    records.append({**row,'audit_file':name,'bytes':member.size})
            while stream.read(2**20):pass
            assert proc.wait(timeout=60)==0, 'restic dump failed'
            assert stream.sha.hexdigest()==expected, 'archive checksum mismatch'
            assert len(records)==len(selected), 'missing database dump'
            proof={'source':args.source,'snapshot_id':snapshot,'archive_sha256':expected,'archive_sha_verified':True,'databases':records}
            (folder/'audit.json').write_text(json.dumps(proof))
            with tarfile.open(output,'w:gz',compresslevel=3) as tar:
                for p in folder.iterdir():tar.add(p,arcname=p.name,recursive=False)
            print(json.dumps({'source':args.source,'archive_sha_verified':True,'database_dumps':len(records),'private_audit_bytes':output.stat().st_size}))
        finally:
            if proc.poll() is None:proc.kill();proc.wait()
    return 0

if __name__=='__main__':raise SystemExit(main())
