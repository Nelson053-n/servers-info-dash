#!/usr/bin/python3
"""Reconstruct SQLite files in a new isolated directory; never overwrite a live tree."""
import argparse
import json
import os
from pathlib import Path,PurePosixPath
import shutil
import sqlite3
import tarfile


def restore(archive,destination):
    destination=Path(destination)
    destination.mkdir(mode=0o700,exist_ok=False)
    with tarfile.open(archive,'r:') as tar:
        manifest=json.load(tar.extractfile('./manifest.json'))
        for entry in manifest['databases']:
            if entry['kind']!='sqlite':continue
            path=PurePosixPath(entry['source'])
            if not path.is_absolute() or '..' in path.parts:raise ValueError('unsafe source path')
            if not all(k in entry for k in ['uid','gid','mode']):raise ValueError('legacy snapshot requires operator ownership review')
            target=destination.joinpath(*path.parts[1:]);target.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
            with tar.extractfile('./'+entry['dump']) as source,target.open('xb') as output:shutil.copyfileobj(source,output)
            if (target.stat().st_uid,target.stat().st_gid)!=(entry['uid'],entry['gid']):os.chown(target,entry['uid'],entry['gid'])
            target.chmod(entry['mode'] & 0o777)
            c=sqlite3.connect(target.as_uri()+'?mode=ro',uri=True)
            try:
                if c.execute('PRAGMA integrity_check').fetchall()!=[('ok',)]:raise ValueError('database integrity failed')
            finally:c.close()
    return destination


if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('archive');p.add_argument('--into',required=True);args=p.parse_args();restore(args.archive,args.into)
