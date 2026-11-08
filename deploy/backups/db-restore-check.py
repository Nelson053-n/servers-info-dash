"""Isolated initial restore checks for native database dumps. No app processes or network ports."""
import json
import secrets
import subprocess
import time


def _run(args, **kw):
    p = subprocess.run(args, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, timeout=600, **kw)
    if p.returncode:
        import re
        text = p.stderr.decode('utf-8','replace')
        lines = [line for line in text.splitlines() if line.startswith(('ERROR ', 'pg_restore: error:'))]
        safe = re.sub(r"'[^']*'", "'<redacted>'", ' '.join(lines))[:500]
        raise RuntimeError('isolated_restore_failed:' + safe)
    return p


def restore_dump(path, kind, image, client=None):
    name = 'info-db-restore-' + secrets.token_hex(8)
    volume = name + '-data'
    labels = ['--label', 'info.backup.restore-test=true']
    args = ['docker','run','-d','--network','none','--memory','768m','--cpus','0.5','--pids-limit','128'] + labels + ['--name',name]
    if kind == 'postgres':
        args += ['--mount','type=volume,source='+volume+',target=/var/lib/postgresql/data','-e','POSTGRES_HOST_AUTH_METHOD=trust',image]
        ping = ['docker','exec',name,'pg_isready','-U','postgres']
    else:
        args += ['--mount','type=volume,source='+volume+',target=/var/lib/mysql','-e','MYSQL_ALLOW_EMPTY_PASSWORD=yes','-e','MARIADB_ALLOW_EMPTY_ROOT_PASSWORD=yes',image,'--innodb-buffer-pool-size=64M','--performance-schema=OFF','--max-connections=10','--innodb-log-file-size=32M']
        ping = ['docker','exec',name,client,'-uroot','-N','-e','SELECT 1']
    try:
        _run(args)
        stable = 0
        for _ in range(180):
            ready = subprocess.run(ping,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=10).returncode == 0
            # Entry points start a temporary initialization server before the final process.
            comm = subprocess.run(['docker','exec',name,'cat','/proc/1/comm'],stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=10).stdout.decode().strip()
            stable = stable + 1 if ready and comm in ('postgres','mysqld','mariadbd') else 0
            if stable >= 5:
                break
            time.sleep(2)
        else:
            raise RuntimeError('restore_check_start_timeout')
        if kind == 'postgres':
            _run(['docker','exec',name,'createdb','-U','postgres','restore_check'])
            command=['docker','exec','-i',name,'pg_restore','-U','postgres','--no-owner','--no-acl','--exit-on-error','-d','restore_check']
        else:
            command=['docker','exec','-i',name,client,'-uroot']
        with open(path,'rb') as f:
            _run(command,stdin=f)
        return {'result':'passed','kind':kind,'scope':'isolated_database_import','network':'none'}
    finally:
        # Only the exact randomly named container created above is a cleanup target.
        removed = subprocess.run(['docker','rm','-f',name],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=30)
        removed_volume = subprocess.run(['docker','volume','rm',volume],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=30)
        if removed.returncode or removed_volume.returncode:
            raise RuntimeError('isolated_restore_cleanup_failed:'+name+':'+volume)
