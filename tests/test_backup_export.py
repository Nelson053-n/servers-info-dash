import importlib.util
from pathlib import Path
import sqlite3
import sys
import tarfile
from types import SimpleNamespace
import pytest

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('backup_export',ROOT/'deploy/backups/export-projects.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)


def test_sqlite_export_includes_committed_wal_and_required_config(tmp_path,monkeypatch):
    source=tmp_path/'project';source.mkdir();db=source/'live.db'
    connection=sqlite3.connect(db);connection.execute('PRAGMA journal_mode=WAL');connection.execute('CREATE TABLE records(id)');connection.execute('INSERT INTO records VALUES(42)');connection.commit()
    (source/'runtime-config').write_text('restore-required')
    (source/'logs').mkdir();(source/'logs'/'metrics.csv').write_text('historical traffic data')
    (source/'backups').mkdir();(source/'backups'/'old').write_text('saved node configuration')
    (tmp_path/'.cache').mkdir(exist_ok=True)
    monkeypatch.setattr(m,'EXPORT_ROOT',tmp_path/'.cache'/'stage')
    archive=tmp_path/'result.tar'
    with archive.open('wb') as stream:
        monkeypatch.setattr(m.sys,'stdout',SimpleNamespace(buffer=stream))
        m.export(dict(roots=[str(source)],source='test',projects=['test']))
    with tarfile.open(archive) as tar:
        names=tar.getnames();assert any(x.endswith('/runtime-config') for x in names)
        assert any(x.endswith('/logs/metrics.csv') for x in names)
        import json,os
        manifest=json.load(tar.extractfile('./manifest.json'))
        record=next(x for x in manifest['databases'] if x['kind']=='sqlite')
        assert record['uid']==db.stat().st_uid and record['mode']==(db.stat().st_mode & 0o777)
        assert not any(x.endswith('/live.db') for x in names)
        saved=next(x for x in tar.getmembers() if x.name.endswith('/backups/old'))
        assert tar.extractfile(saved).read()==b'saved node configuration'
        member=next(x for x in tar.getmembers() if x.name.startswith('./databases/') and x.name.endswith('.sqlite'))
        restored=tmp_path/'restore.sqlite';restored.write_bytes(tar.extractfile(member).read())
    restored_db=sqlite3.connect(restored)
    assert restored_db.execute('SELECT id FROM records').fetchall()==[(42,)]
    restored_db.close();connection.close()
    assert not list((tmp_path/'.cache'/'stage').glob('run-*'))
    restore_spec=importlib.util.spec_from_file_location('restore_sqlite',ROOT/'deploy/backups/restore-sqlite.py')
    restore_module=importlib.util.module_from_spec(restore_spec);restore_spec.loader.exec_module(restore_module)
    destination=tmp_path/'isolated';restore_module.restore(archive,destination)
    copied=destination.joinpath(*db.parts[1:])
    assert copied.stat().st_uid==db.stat().st_uid
    assert copied.stat().st_mode & 0o777==db.stat().st_mode & 0o777
    check=sqlite3.connect(copied);assert check.execute('SELECT id FROM records').fetchall()==[(42,)];check.close()
    with pytest.raises(FileExistsError):restore_module.restore(archive,destination)



def test_missing_source_fails_closed(tmp_path):
    with pytest.raises(RuntimeError,match='source_missing'):
        m.export(dict(roots=[str(tmp_path/'absent')],source='test',projects=['test']))


def test_changing_directory_uses_frozen_copy_set(tmp_path,monkeypatch):
    source=tmp_path/'project';folder=source/'backups'/'servers';folder.mkdir(parents=True)
    (folder/'one.conf').write_text('saved node configuration')
    original_copy=m.shutil.copy2
    def copy_with_new_arrival(a,b,*args,**kwargs):
        (folder/'arrived-later.conf').write_text('next run')
        return original_copy(a,b,*args,**kwargs)
    monkeypatch.setattr(m.shutil,'copy2',copy_with_new_arrival)
    (tmp_path/'.cache').mkdir(exist_ok=True)
    monkeypatch.setattr(m,'EXPORT_ROOT',tmp_path/'.cache'/'stage')
    archive=tmp_path/'result.tar'
    with archive.open('wb') as stream:
        monkeypatch.setattr(m.sys,'stdout',SimpleNamespace(buffer=stream))
        m.export(dict(roots=[str(source)],source='test',projects=['test'],stable_directories=[str(folder)]))
    with tarfile.open(archive) as tar:
        import json
        manifest=json.load(tar.extractfile('./manifest.json'));mapping=manifest['directory_snapshots'][0]
        assert mapping['source']==str(folder)
        assert tar.extractfile('./'+mapping['dump']+'/one.conf').read()==b'saved node configuration'
        assert not any(x.name.endswith('arrived-later.conf') for x in tar.getmembers())


def test_tar_uses_frozen_path_set_when_directory_receives_new_files(tmp_path,monkeypatch):
    source=tmp_path/'project';source.mkdir();(source/'initial.txt').write_text('initial')
    (tmp_path/'.cache').mkdir(exist_ok=True)
    monkeypatch.setattr(m,'EXPORT_ROOT',tmp_path/'.cache'/'stage')
    original_run=m.subprocess.run
    def arrive_at_archive_start(args,*a,**kw):
        if args[0]=='tar':(source/'arrived-later.txt').write_text('next backup')
        return original_run(args,*a,**kw)
    monkeypatch.setattr(m.subprocess,'run',arrive_at_archive_start)
    archive=tmp_path/'result.tar'
    with archive.open('wb') as stream:
        monkeypatch.setattr(m.sys,'stdout',SimpleNamespace(buffer=stream))
        m.export(dict(roots=[str(source)],source='test',projects=['test']))
    with tarfile.open(archive) as tar:
        names=tar.getnames();assert any(x.endswith('/initial.txt') for x in names)
        assert not any(x.endswith('/arrived-later.txt') for x in names)


def test_unreadable_files_are_skipped_and_listed_in_manifest(tmp_path,monkeypatch):
    import json,os
    if os.geteuid()==0: pytest.skip('root reads everything')
    source=tmp_path/'project';source.mkdir();(source/'ok.txt').write_text('ok')
    locked=source/'locked';locked.write_text('');locked.chmod(0)
    (tmp_path/'.cache').mkdir(exist_ok=True)
    monkeypatch.setattr(m,'EXPORT_ROOT',tmp_path/'.cache'/'stage')
    archive=tmp_path/'result.tar'
    with archive.open('wb') as stream:
        monkeypatch.setattr(m.sys,'stdout',SimpleNamespace(buffer=stream))
        m.export(dict(roots=[str(source)],source='test',projects=['test']))
    with tarfile.open(archive) as tar:
        names=tar.getnames();assert any(x.endswith('/ok.txt') for x in names) and not any(x.endswith('/locked') for x in names)
        assert str(locked) in json.load(tar.extractfile('./manifest.json'))['unreadable_skipped']
    locked.chmod(0o600)


def test_tar_changed_only_accepts_only_live_file_change_warning():
    ok=b"tar: opt/globalauto/site/wp-content: file changed as we read it\n"
    assert m.tar_changed_only(1, ok)
    assert not m.tar_changed_only(2, ok)
    assert not m.tar_changed_only(1, b"")
    assert not m.tar_changed_only(1, ok+b"tar: opt/x: Cannot open: Permission denied\n")
    assert not m.tar_changed_only(1, b"tar: opt/x: file changed as we read it\ntar: Exiting with failure status due to previous errors\n")

def test_wal_database_without_shm_is_snapshotted_via_file_copy(tmp_path):
    """Живая WAL-база в режиме только-чтения не читается backup API, пока писатель не держит -shm.
    Тогда снимок снимается с копии db+wal — и это отмечается в manifest."""
    import json, os
    source=tmp_path/'app';source.mkdir();db=source/'live.db'
    writer=sqlite3.connect(db);writer.execute('PRAGMA journal_mode=WAL')
    writer.execute('CREATE TABLE t(id)');writer.execute('INSERT INTO t VALUES(7)');writer.commit()
    writer.close()                      # WAL остаётся на диске, -shm исчезает вместе с последним соединением
    assert not (tmp_path/'app'/'live.db-shm').exists()
    (tmp_path/'.cache').mkdir(exist_ok=True)
    m.EXPORT_ROOT=tmp_path/'.cache'/'stage'
    archive=tmp_path/'result.tar'
    with archive.open('wb') as stream:
        m.sys.stdout=SimpleNamespace(buffer=stream)
        m.export(dict(roots=[str(source)],source='test',projects=['test']))
    with tarfile.open(archive) as tar:
        manifest=json.load(tar.extractfile('./manifest.json'))
        record=next(x for x in manifest['databases'] if x['kind']=='sqlite')
        assert record['integrity']=='passed'
        member=next(x for x in tar.getmembers() if x.name.endswith(record['dump']))
        restored=tmp_path/'restored.db';restored.write_bytes(tar.extractfile(member).read())
    check=sqlite3.connect(restored);assert check.execute('SELECT id FROM t').fetchall()==[(7,)];check.close()


def test_missing_docker_skips_container_parts_instead_of_failing(tmp_path, monkeypatch):
    """В образе выгрузки docker CLI не запускается (glibc). Копия не должна падать:
    файлы и SQLite сохраняются, Docker-часть уходит в manifest.skipped с ограничением."""
    import json
    source=tmp_path/'project';source.mkdir();(source/'code.py').write_text('print(1)')
    db=sqlite3.connect(source/'app.db');db.execute('CREATE TABLE t(x)');db.execute('INSERT INTO t VALUES(1)');db.commit();db.close()
    (tmp_path/'.cache').mkdir(exist_ok=True)
    monkeypatch.setattr(m,'EXPORT_ROOT',tmp_path/'.cache'/'stage')
    monkeypatch.setattr(m,'docker_available',lambda: False)
    archive=tmp_path/'result.tar'
    with archive.open('wb') as stream:
        monkeypatch.setattr(m.sys,'stdout',SimpleNamespace(buffer=stream))
        m.export(dict(roots=[str(source)],source='test',projects=['test'],postgres=['pg-int'],mysql=[{'container':'c','dumper':'mysqldump'}],redis=['r'],native_postgres={'socket':'/var/run/postgresql'},image_containers=['pg-int']))
    with tarfile.open(archive) as tar:
        manifest=json.load(tar.extractfile('./manifest.json'))
        kinds={x['kind'] for x in manifest['skipped']}
        assert kinds=={'postgres_container','mysql','redis','native_postgres','containers_metadata'}
        assert any('Docker' in x for x in manifest['limitations'])
        assert any(x['kind']=='sqlite' and x['integrity']=='passed' for x in manifest['databases'])
        assert any(x.endswith('/code.py') for x in tar.getnames())


def test_docker_available_is_false_when_cli_broken(monkeypatch):
    monkeypatch.setattr(m.subprocess,'run',lambda *a,**k:(_ for _ in ()).throw(FileNotFoundError()))
    assert m.docker_available() is False
