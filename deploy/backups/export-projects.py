#!/usr/bin/python3
"""Fixed, root-configured export over SSH. Payload is private, never a status document."""
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import shutil
import secrets
import sqlite3
import subprocess
import sys
import stat
import tarfile
import tempfile

CONFIG = Path('/etc/projects-backup/export.json')
EXPORT_ROOT = Path('/var/lib/projects-backup-export')
SKIP = {'node_modules', '.venv', '__pycache__', '.cache', 'target', '.pytest_cache'}


def run(args, destination):
    with open(destination, 'wb') as output:
        EXPORT_ROOT.mkdir(mode=0o700,exist_ok=True)
        with (EXPORT_ROOT/'last-command-error.txt').open('wb') as errors:
            result = subprocess.run(args, stdout=output, stderr=errors, timeout=600)
    if result.returncode:
        raise RuntimeError('database_or_image_export_failed:'+Path(destination).name)


def docker_available():
    """Docker CLI внутри образа выгрузки может не запускаться (старый glibc в образе против нового бинаря хоста).
    Тогда Docker-часть пропускается с явной пометкой, а файлы и SQLite копируются как обычно."""
    try:
        return bool(subprocess.run(['docker','version','--format','{{.Server.Version}}'],
                                   stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=15).returncode == 0)
    except Exception:
        return False


def tool_available(name):
    return shutil.which(name) is not None


def sqlite_file_state(p):
    """Metadata for the whole copy window; never hide permission or I/O errors."""
    result = []
    for suffix in ('', '-wal'):
        try:
            s = Path(str(p)+suffix).stat()
        except FileNotFoundError:
            if not suffix:
                raise
            result.append(None)
        else:
            result.append((s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns))
    return tuple(result)


def copy_wal_files(p, scratch):
    """Fail-closed stable-window fallback, not an atomic filesystem snapshot.

    The caller supplies a unique empty private directory. A changing database is
    rejected; all main-file/WAL read errors propagate. SHM is regenerated locally.
    """
    scratch.mkdir(mode=0o700, exist_ok=True)
    before = sqlite_file_state(p)
    copy = Path(scratch)/(p.name+'.copy')
    if copy.exists() or Path(str(copy)+'-wal').exists():
        raise RuntimeError('sqlite_scratch_not_empty')
    for index, suffix in enumerate(('', '-wal')):
        if before[index] is not None:
            # Unlike read_bytes, streaming does not load large live DBs into RAM.
            with Path(str(p)+suffix).open('rb') as source, Path(str(copy)+suffix).open('xb') as target:
                shutil.copyfileobj(source, target, length=2**20)
    if before != sqlite_file_state(p):
        raise RuntimeError('sqlite_changed_during_copy')
    return copy


def snapshot_sqlite(p, target, scratch):
    """Снимок живой SQLite через backup API. Возвращает пометку способа или None.

    1) открываем базу как mode=ro и снимаем копию backup API;
    2) если так не вышло (частый случай: WAL без -shm, writer не держит базу) — повторяем
       на копии файлов db+wal во временном каталоге.
    Ошибка в обоих случаях — исключение с путём к файлу."""
    errors = []
    scratch.mkdir(mode=0o700, exist_ok=True)
    # First use SQLite's own consistent backup. If a read-only WAL mount cannot
    # provide SHM, allow at most three stable-window copies in unique directories.
    for attempt in range(4):
        source = output = None
        copied = None
        method = None if attempt == 0 else 'file_copy_wal'
        try:
            if method is None:
                source = sqlite3.connect(p.as_uri()+'?mode=ro', uri=True, timeout=30)
            else:
                copied = tempfile.TemporaryDirectory(prefix='sqlite-', dir=scratch)
                copy = copy_wal_files(p, Path(copied.name))
                # mode=rw refuses to create an empty DB if the copy is missing.
                source = sqlite3.connect(copy.as_uri()+'?mode=rw', uri=True, timeout=30)
            output = sqlite3.connect(target)
            source.backup(output)
            if output.execute('PRAGMA integrity_check').fetchall() != [('ok',)]:
                raise RuntimeError('sqlite_integrity_failed:'+str(p))
            return method
        except (sqlite3.Error, RuntimeError, OSError) as exc:
            errors.append(exc)
        finally:
            if output is not None: output.close()
            if source is not None: source.close()
            if copied is not None: copied.cleanup()
        target.unlink(missing_ok=True)
    raise RuntimeError('sqlite_snapshot_failed:'+str(p)) from (errors[-1] if errors else None)


def export(config):
    os.nice(15)
    roots = [Path(x) for x in config['roots']]
    if not roots or any(not p.exists() or not p.is_absolute() for p in roots):
        raise RuntimeError('source_missing')
    base = EXPORT_ROOT;base.mkdir(mode=0o700, exist_ok=True)
    minimum_free = config.get('min_free_bytes', 3 * 2**30)
    if shutil.disk_usage(base).free < minimum_free:
        raise RuntimeError('source_space_low')
    with tempfile.TemporaryDirectory(prefix='run-', dir=base) as name:
        stage = Path(name);db = stage/'databases';db.mkdir(mode=0o700)
        excluded = [];verified = [];unreadable = [];skipped = []
        docker_ok = docker_available()
        if not docker_ok and any(config.get(k) for k in ('postgres','mysql','redis','native_postgres','image_containers','images')):
            raise RuntimeError('required_docker_unavailable')
        # SQLite's backup API captures committed WAL data without stopping the application.
        for root in roots:
            for folder, dirs, files in os.walk(root, followlinks=False):
                dirs[:] = [d for d in dirs if d not in SKIP and not (Path(folder)/d).is_symlink()]
                for filename in files:
                    p = Path(folder)/filename
                    if p.suffix not in {'.db', '.sqlite', '.sqlite3'} or p.is_symlink():
                        continue
                    try:
                        with p.open('rb') as stream:
                            if stream.read(16) != b'SQLite format 3\x00':
                                continue
                    except FileNotFoundError:
                        continue          # временная БД исчезла между обходом и чтением
                    except PermissionError:
                        unreadable.append(str(p)); continue
                    target = db/(hashlib.sha256(str(p).encode()).hexdigest()[:16]+'.sqlite')
                    try:
                        method = snapshot_sqlite(p, target, base/'walsrc')
                    except RuntimeError as e:
                        target.unlink(missing_ok=True)
                        if not p.exists() and str(p) not in config.get('required_sqlite', []):
                            continue      # тестовая/временная БД удалена во время копирования — это не ошибка копии
                        raise
                    excluded.extend([str(p).lstrip('/'),str(p).lstrip('/')+'-wal',str(p).lstrip('/')+'-shm',str(p).lstrip('/')+'-journal'])
                    metadata=p.stat()
                    record={'kind':'sqlite','source':str(p),'dump':str(target.relative_to(stage)),'integrity':'passed','uid':metadata.st_uid,'gid':metadata.st_gid,'mode':metadata.st_mode & 0o777}
                    if method:
                        record['snapshot_method'] = method
                        record['limitation'] = 'WAL-база скопирована файлом (db+wal) во временный каталог, затем backup API'
                    verified.append(record)
        for container in config.get('postgres', []):
            if not docker_ok:
                skipped.append({'kind':'postgres_container','container':container,'reason':'docker_cli_unavailable'})
                continue
            state=json.loads(subprocess.check_output(['docker','inspect',container],stderr=subprocess.DEVNULL,timeout=15))[0]
            if not state['State']['Running']:
                temporary=state.get('HostConfig',{}).get('Tmpfs') or {}
                if container in config.get('nonpersistent_test_containers',[]) and '/var/lib/postgresql/data' in temporary:
                    verified.append({'kind':'nonpersistent_test_database','container':container,'database_state':'stopped_tmpfs_no_data'})
                    continue
                mount=next(x for x in state['Mounts'] if x['Destination']=='/var/lib/postgresql/data')
                location=mount.get('Name') if mount['Type']=='volume' else mount['Source']
                argument='type='+mount['Type']+',src='+location+',dst=/data,readonly'
                target=db/(container+'-cold.tar')
                run(['docker','run','--rm','--network','none','--read-only','--user','postgres','--mount',argument,state['Image'],'tar','--numeric-owner','-C','/data','-cf','-','.'],target)
                after=json.loads(subprocess.check_output(['docker','inspect',container],timeout=15))[0]
                if after['State']['Running'] or after['State']['StartedAt']!=state['State']['StartedAt']:raise RuntimeError('cold_database_started_during_copy')
                with tarfile.open(target) as archive:
                    names={x.name.removeprefix('./') for x in archive}
                    if not {'PG_VERSION','global/pg_control'}<=names:raise RuntimeError('cold_postgres_incomplete')
                    if any(n.startswith('pg_tblspc/') for n in names):raise RuntimeError('external_tablespace_requires_separate_backup')
                verified.append({'kind':'postgres_cold','container':container,'dump':str(target.relative_to(stage)),'image':state['Image'],'database_state':'stopped'})
                continue
            command=['docker','exec',container,'sh','-c','exec psql -X -U "$POSTGRES_USER" -d postgres -At -c "SELECT datname FROM pg_database WHERE NOT datistemplate"']
            names=subprocess.check_output(command,stderr=subprocess.DEVNULL,timeout=30).decode().splitlines()
            for database in names:
                if not database or '/' in database or database.startswith('-'):raise RuntimeError('invalid_database_name')
                target=db/(container+'-'+hashlib.sha256(database.encode()).hexdigest()[:12]+'.dump')
                run(['docker','exec',container,'sh','-c','exec pg_dump -U "$POSTGRES_USER" -Fc -- "$1"','sh',database],target)
                result=subprocess.run(['docker','exec','-i',container,'pg_restore','--list'],stdin=target.open('rb'),stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=60)
                if result.returncode:raise RuntimeError('postgres_catalog_invalid')
                verified.append({'kind':'postgres','container':container,'database':database,'dump':str(target.relative_to(stage)),'catalog':'passed'})
            run(['docker','exec',container,'sh','-c','exec pg_dumpall -U "$POSTGRES_USER" --roles-only'],db/(container+'-roles.sql'))
        native=config.get('native_postgres')
        if native and not docker_ok:
            skipped.append({'kind':'native_postgres','reason':'pg_dump_unavailable'})
        elif native:
            client=['docker','run','--rm','--network','none','--user',str(native['uid']),'--mount','type=bind,src='+native['socket']+',dst='+native['socket']+',readonly',native['image']]
            auth=['-h',native['socket'],'-U','postgres']
            names=subprocess.check_output(client+['psql','-X']+auth+['-d','postgres','-At','-c','SELECT datname FROM pg_database WHERE NOT datistemplate'],stderr=subprocess.DEVNULL,timeout=30).decode().splitlines()
            for database in names:
                target=db/('native-postgres-'+hashlib.sha256(database.encode()).hexdigest()[:12]+'.dump')
                run(client+['pg_dump']+auth+['-Fc','--',database],target)
                verify=['docker','run','--rm','-i','--network','none',native['image'],'pg_restore','--list']
                with target.open('rb') as stream:
                    result=subprocess.run(verify,stdin=stream,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=60)
                if result.returncode:raise RuntimeError('postgres_catalog_invalid')
                verified.append({'kind':'postgres','container':'native','database':database,'dump':str(target.relative_to(stage)),'catalog':'passed'})
            run(client+['pg_dumpall']+auth+['--roles-only'],db/'native-postgres-roles.sql')
        for entry in config.get('mysql', []):
            if not docker_ok:
                skipped.append({'kind':'mysql','container':entry.get('container'),'reason':'mysql_client_unavailable'})
                continue
            container=entry['container'];client=entry['client'];dumper=entry['dumper']
            user=entry.get('user','root')
            secrets_file=entry.get('secret_path','/run/secrets/db_root_password')
            setup=('export MYSQL_PWD="$(cat '+secrets_file+')"; ' if entry.get('secret_file') else 'export MYSQL_PWD="$MYSQL_ROOT_PASSWORD"; ')
            if entry.get('database'):
                names=[entry['database']]
            else:
                names=subprocess.check_output(['docker','exec',container,'sh','-c',setup+'exec '+client+' -u'+user+' -N -e "SHOW DATABASES"'],stderr=subprocess.DEVNULL,timeout=30).decode().splitlines()
            for database in names:
                if database in ['information_schema','performance_schema','sys']:continue
                target=db/(container+'-'+hashlib.sha256(database.encode()).hexdigest()[:12]+'.sql')
                run(['docker','exec',container,'sh','-c',setup+'exec '+dumper+' -u'+user+' --single-transaction --routines --events --databases "$1"','sh',database],target)
                verified.append({'kind':'mysql','container':container,'database':database,'dump':str(target.relative_to(stage)),'result':'completed'})
        for container in config.get('redis', []):
            if not docker_ok:
                skipped.append({'kind':'redis','container':container,'reason':'docker_cli_unavailable'})
                continue
            target=db/(container+'.rdb')
            temporary='/tmp/projects-backup-'+secrets.token_hex(16)
            subprocess.run(['docker','exec',container,'mkdir','-m','700','--',temporary],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=15)
            try:
                result=subprocess.run(['docker','exec',container,'sh','-c','umask 077; exec redis-cli --rdb "$1"','sh',temporary+'/dump.rdb'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=120)
                if result.returncode:raise RuntimeError('redis_export_failed')
                subprocess.run(['docker','cp',container+':'+temporary+'/dump.rdb',str(target)],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=60)
            finally:
                subprocess.run(['docker','exec',container,'rm','-f','--',temporary+'/dump.rdb'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=15)
                subprocess.run(['docker','exec',container,'rmdir','--',temporary],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=15)
            with target.open('rb') as stream:
                if stream.read(5)!=b'REDIS':raise RuntimeError('redis_export_invalid')
            with target.open('rb') as stream:
                result=subprocess.run(['docker','exec','-i',container,'redis-check-rdb','/dev/stdin'],stdin=stream,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=60)
            if result.returncode:raise RuntimeError('redis_integrity_failed')
            verified.append({'kind':'redis','container':container,'dump':str(target.relative_to(stage)),'integrity':'passed'})
        directory_snapshots=[]
        for index,root_name in enumerate(config.get('stable_directories',[])):
            original=Path(root_name);snapshot=stage/'directory-snapshots'/str(index)
            entries=[original]+sorted(original.rglob('*'))
            # Freeze the selected path set; later arrivals belong to the next backup.
            for source_path in entries:
                relative=source_path.relative_to(original);destination=snapshot/relative;before=source_path.lstat()
                if stat.S_ISDIR(before.st_mode):destination.mkdir(parents=True,exist_ok=True,mode=0o700)
                elif stat.S_ISREG(before.st_mode):
                    destination.parent.mkdir(parents=True,exist_ok=True,mode=0o700);shutil.copy2(source_path,destination)
                    after=source_path.lstat()
                    if (before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns)!=(after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns):raise RuntimeError('snapshot_file_changed')
                else:raise RuntimeError('unsupported_snapshot_file')
                os.chown(destination,before.st_uid,before.st_gid)
            for source_path in reversed(entries):
                if source_path.is_dir():shutil.copystat(source_path,snapshot/source_path.relative_to(original))
            excluded.append(str(original).lstrip('/'))
            directory_snapshots.append({'source':str(original),'dump':str(snapshot.relative_to(stage))})
        required=set(config.get('required_sqlite',[]))
        if required-set(x.get('source') for x in verified if x['kind']=='sqlite'):raise RuntimeError('required_sqlite_missing')
        if config.get('image_containers'):
            if docker_ok:
                run(['docker','inspect']+config['image_containers'],stage/'containers.json')
            else:
                skipped.append({'kind':'containers_metadata','reason':'docker_cli_unavailable'})
        images=stage/'images';images.mkdir()
        current_images = (sorted({json.loads(subprocess.check_output(['docker','inspect',name],stderr=subprocess.DEVNULL,timeout=15))[0]['Image'] for name in config.get('image_containers',[])})
                          if config.get('image_containers') and docker_ok else config.get('images',[]) if docker_ok else [])
        for image in current_images:
            identity=subprocess.check_output(['docker','image','inspect',image,'--format','{{.Id}}'],stderr=subprocess.DEVNULL,timeout=15).decode().strip()
            cache=base/('image-'+identity.split(':')[-1]+'.tar')
            if not cache.exists():
                size=int(subprocess.check_output(['docker','image','inspect',image,'--format','{{.Size}}'],timeout=15))
                if shutil.disk_usage(base).free < size + minimum_free:raise RuntimeError('image_cache_space_low')
                tmp=cache.with_suffix('.tmp');run(['docker','image','save',image],tmp);os.replace(tmp,cache)
            os.link(cache,images/cache.name)
        def selected_paths(root,excluded_paths=(),apply_filters=True):
            selected=[]
            def blocked(path):
                if not apply_filters:return False
                parts=path.parts
                if any(x in SKIP for x in parts) or any(parts[i:i+2]==('.next','cache') for i in range(len(parts)-1)) or any(str(path)==x or str(path).startswith(x+'/') for x in excluded_paths):
                    return True
                # Нечитаемое для экспортёра (на рабочей VM он работает не от root) — пропускаем с записью
                # в manifest, а не роняем всю копию источника ошибкой tar «Cannot open».
                try:
                    if path.is_symlink():return False
                    need=os.R_OK|os.X_OK if path.is_dir() else os.R_OK
                    if not os.access(path,need):
                        unreadable.append(str(path));return True
                except OSError:
                    return True
                return False
            if blocked(root):return selected
            selected.append(root)
            if root.is_dir() and not root.is_symlink():
                for directory,dirs,files in os.walk(root,followlinks=False):
                    parent=Path(directory)
                    for name in dirs+files:
                        path=parent/name
                        if not blocked(path):selected.append(path)
                    dirs[:]=[name for name in dirs if not blocked(parent/name) and not (parent/name).is_symlink()]
            return selected
        original_paths=set()
        excluded_absolute=['/'+x for x in excluded]
        for root in roots:original_paths.update(selected_paths(root,excluded_absolute))
        # A live service may delete its own temporary files between listing and archiving.
        # Drop paths that are already gone, record them, and keep everything still present.
        vanished=sorted(str(p) for p in original_paths if not os.path.lexists(p))
        if vanished:original_paths={p for p in original_paths if os.path.lexists(p)}
        manifest={'schema_version':2,'source':config['source'],'projects':config['projects'],'observed_at':dt.datetime.now(dt.timezone.utc).isoformat(),'databases':verified,'directory_snapshots':directory_snapshots,'roots':[str(p) for p in roots],
                  'unreadable_skipped':sorted(set(unreadable))[:500],
                  'vanished_skipped':[x for x in vanished if not os.path.lexists(x)][:500],
                  'skipped':skipped,
                  'limitations':['File copies are live; databases use logical dumps/SQLite backup API. PostgreSQL restore catalog check is not an actual database restore.',
                                 'Files changed while being read are archived as read (tar "file changed as we read it" is accepted).',
                                 'Transient files deleted by the running service before being read are listed in vanished_skipped and are not in the archive.']
                  + (['Docker-контейнеры, их базы и образы не снимались: docker/клиенты БД недоступны в образе выгрузки. Файлы и SQLite сохранены.'] if skipped else [])}
        (stage/'manifest.json').write_text(json.dumps(manifest,ensure_ascii=False,indent=2))
        source_list=stage/'source-paths.list';stage_list=stage/'stage-paths.list'
        source_list.write_bytes(b''.join(os.fsencode(str(p).lstrip('/'))+b'\0' for p in sorted(original_paths)))
        staged=[p for p in selected_paths(stage,apply_filters=False) if p!=stage and p not in {source_list,stage_list}]
        stage_list.write_bytes(b''.join(os.fsencode('./'+str(p.relative_to(stage)))+b'\0' for p in staged))
        args=['tar','--create','--file=-','--numeric-owner','--null','--no-recursion','--directory=/','--files-from='+str(source_list),'--directory='+str(stage),'--files-from='+str(stage_list)]
        with (base/'last-tar-error.txt').open('wb') as errors:
            result=subprocess.run(args,stdout=sys.stdout.buffer,stderr=errors,timeout=7200)
        if result.returncode and not tar_changed_only(result.returncode,(base/'last-tar-error.txt').read_bytes()):
            raise RuntimeError('file_export_failed_'+str(result.returncode))


def tar_changed_only(returncode, stderr):
    """Принимаем только два безопасных гонки: живой файл изменился во время чтения (код 1)
    и файл исчез между листингом и чтением (код 2, «Cannot stat»). Любое другое сообщение
    или код — ошибка: нельзя принять архив, в котором потеряно существующее."""
    if returncode not in (1, 2):
        return False
    suffix_missing = ': Cannot stat: No such file or directory'
    lines = [line for line in stderr.decode('utf-8', 'replace').splitlines()
             if line.strip() and not line.startswith('tar: Exiting with failure status')]
    if not lines:
        return False
    vanished = 0
    for line in lines:
        if not line.startswith('tar: '):
            return False
        if line.endswith(': file changed as we read it'):
            continue
        if not line.endswith(suffix_missing):
            return False
        path = line[len('tar: '):-len(suffix_missing)]
        if os.path.lexists('/' + path):
            return False          # файл на месте — значит потеря данных, а не гонка
        vanished += 1
    # Код 2 означает фатальную ошибку: он допустим только когда реально исчез файл.
    return returncode == 1 or vanished > 0


if __name__ == '__main__':
    if len(sys.argv)!=1 or os.geteuid()!=0 or os.environ.get('SSH_ORIGINAL_COMMAND')!='export-projects-v1':
        raise SystemExit(64)
    os.umask(0o077)
    try:
        export(json.loads(CONFIG.read_text()))
        (EXPORT_ROOT/'last-error.txt').unlink(missing_ok=True)
    except Exception as exc:
        EXPORT_ROOT.mkdir(mode=0o700,exist_ok=True)
        (EXPORT_ROOT/'last-error.txt').write_text(type(exc).__name__+': '+str(exc)+'\n')
        print('project export failed',file=sys.stderr);raise SystemExit(65)
