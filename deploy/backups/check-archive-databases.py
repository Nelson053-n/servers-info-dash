#!/usr/bin/python3
"""Import DB dumps taken from a SHA-verified Restic archive into isolated containers."""
import datetime as dt
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile


def main():
    os.umask(0o077)
    payload,config_path,proof_path=map(Path,sys.argv[1:])
    config=json.loads(config_path.read_text())
    spec=importlib.util.spec_from_file_location('restore',Path(__file__).with_name('db-restore-check.py'))
    restore=importlib.util.module_from_spec(spec);spec.loader.exec_module(restore)
    with tempfile.TemporaryDirectory(prefix='info-archive-db-restore-') as temp:
        root=Path(temp);checks=[]
        with tarfile.open(payload,'r:*') as tar:
            member=tar.getmember('audit.json');assert member.isfile() and member.size<2**20
            proof=json.load(tar.extractfile(member))
            assert proof['source']==config['source'] and proof['archive_sha_verified'] is True
            for row in proof['databases']:
                name=row['audit_file'];assert re.fullmatch(r'dump-\d+\.(sql|dump)',name)
                member=tar.getmember(name);assert member.isfile() and member.size==row['bytes'] and member.size>0
                path=root/name
                with tar.extractfile(member) as src,path.open('xb') as dst:shutil.copyfileobj(src,dst)
                c=row['container'];client=None
                if row['kind']=='mysql':
                    entry=next(x for x in config['mysql'] if x['container']==c);client=entry['client']
                else:
                    assert row['kind']=='postgres'
                    assert c=='native' or c in config['postgres']
                if c=='native':image=config['native_postgres']['image']
                else:image=subprocess.check_output(['docker','inspect','-f','{{.Image}}',c],stderr=subprocess.DEVNULL,timeout=30).decode().strip()
                result=restore.restore_dump(path,row['kind'],image,client)
                checks.append({**result,'container':c,'database':row['database'],'bytes':row['bytes']})
                path.unlink()
        result={'source':config['source'],'verified_at':dt.datetime.now(dt.timezone.utc).isoformat(),'scope':'database_import_from_sha_verified_restic_archive','snapshot_id':proof['snapshot_id'],'archive_sha256':proof['archive_sha256'],'checks':checks}
        proof_path.write_text(json.dumps(result,indent=2))
        print(json.dumps({'source':result['source'],'verified_at':result['verified_at'],'scope':result['scope'],'checks':checks}))

if __name__=='__main__':main()
