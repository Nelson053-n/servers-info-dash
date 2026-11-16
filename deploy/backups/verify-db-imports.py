#!/usr/bin/python3
"""Verify that every nightly archive really restores its databases — automatically.

Runs on vm-claude after the nightly backup. For each source it:

1. reads the current receipt from VM310 (snapshot id + archive SHA + database list);
2. skips the source when a proof for exactly this snapshot and SHA already exists;
3. otherwise extracts only the DB dumps from that snapshot on VM310 (private payload,
   full-archive SHA re-checked there) and pulls the payload over the QGA channel;
4. imports every dump into a throwaway container (``--network none``, no application
   code) on the source host — or locally with pinned images for Bob, whose SSH route
   is not available from this machine;
5. validates the proof with the same strict check the publisher uses and records it on
   VM310, then republishes the backup card.

Nothing here writes to a production database: the import targets a fresh random
container and both container and volume are removed afterwards.
"""
import argparse
import base64
import datetime as dt
import importlib.util
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time

REPO = Path('/home/nel/info/deploy/backups')
STATE = Path('/home/nel/.local/state/info-db-verify')
RU3 = '/home/nel/recovery-20261104/ru3-access/config'
SSH_OPTIONS = ['-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=yes', '-o', 'ConnectTimeout=10',
               '-o', 'ServerAliveInterval=15', '-o', 'ServerAliveCountMax=3']

# bob живёт в другой подсети: входящего SSH с этой машины нет, поэтому дампы Bob
# импортируются здесь же на закреплённых образах тех же мажорных версий.
CONFIG = {
    'lv3': {'mode': 'remote', 'ssh': ['ssh', 'amn-lv3'], 'scp': ['scp'], 'target': 'amn-lv3',
            'sudo': False, 'config': '/etc/projects-backup/export.json'},
    'ru3': {'mode': 'remote', 'ssh': ['ssh', '-F', RU3, 'ru3-recovery'],
            'scp': ['scp', '-F', RU3], 'target': 'ru3-recovery', 'sudo': True,
            'config': '/etc/projects-backup/export.json'},
    'vm300-code': {'mode': 'local', 'config': '/home/nel/.local/share/project-backup/config.json'},
    'bob': {'mode': 'local-images', 'xz': True, 'timeout_sec': 5400,
            'images': {'otpusk-stand-db-1': 'postgres:16.15', 'csdtest-test-db-1': 'mysql:8.0'},
            'clients': {'csdtest-test-db-1': 'mysql'}},
}
SOURCES = ('lv3', 'ru3', 'vm300-code', 'bob')


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


pull = load('private_pull', REPO / 'pull-audit-from-giga.py')


def say(kind, **values):
    print(json.dumps({'event': kind, 'at': dt.datetime.now(dt.timezone.utc).isoformat(), **values},
                     ensure_ascii=False), flush=True)


def run(args, *, cwd=None, private_log=None, timeout=1800):
    result = subprocess.run(args, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
    if result.returncode:
        if private_log is not None:
            private_log.write_bytes(result.stderr + b'\n' + result.stdout)
            private_log.chmod(0o600)
        raise RuntimeError('operation_failed:' + Path(args[0]).name + ':exit=' + str(result.returncode))
    return result.stdout.decode().strip()


def remote(source, command, private_log=None):
    route = CONFIG[source]['ssh']
    return run(route[:-1] + SSH_OPTIONS + [route[-1], command], private_log=private_log)


def guest_json(code):
    return json.loads(pull.guest(code))


def receipt_and_proof(source):
    """Current receipt and the proof already on file — read on VM310, nothing written."""
    code = '''import json,importlib.util,datetime as dt
from pathlib import Path
source=SOURCE;base=Path('/var/lib/info-backup/projects')
receipt=json.loads((base/'receipts'/(source+'.json')).read_text())
out={'receipt':{'snapshot_id':receipt.get('snapshot_id'),'archive_sha256':receipt.get('archive_sha256'),'verified_at':receipt.get('verified_at'),'databases':len([x for x in receipt['manifest']['databases'] if x.get('dump')])}}
proof_path=base/'database-restore-proofs'/(source+'.json')
if proof_path.exists():
    proof=json.loads(proof_path.read_text())
    out['proof']={'snapshot_id':proof.get('snapshot_id'),'archive_sha256':proof.get('archive_sha256'),'verified_at':proof.get('verified_at'),'checks':len(proof.get('checks') or [])}
    try:
        spec=importlib.util.spec_from_file_location('p','/opt/info-backup/publish-project-status.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
        m.database_restore_evidence(proof,receipt,source,dt.datetime.now(dt.timezone.utc))
        out['proof_current']=True
    except Exception:
        out['proof_current']=False
print(json.dumps(out))
'''.replace('SOURCE', repr(source))
    return guest_json(code)


def staging_payload(source):
    return '/srv/restic/projects-staging/' + source + '-db-restore-audit'


def payload_state(source):
    code = '''import json,os,glob
from pathlib import Path
found=sorted(glob.glob(PAYLOAD_PREFIX+'*.tar.*'))
p=Path(found[0]) if found else Path(PAYLOAD_PREFIX+'none.tar.gz')
out={'exists':bool(found)}
if p.exists():
    out.update(size=p.stat().st_size,uid=p.stat().st_uid,mode=oct(p.stat().st_mode & 0o777))
print(json.dumps(out))
'''.replace('PAYLOAD_PREFIX', repr(staging_payload(source)))
    return guest_json(code)


def drop_payload(source):
    code = '''import json,os,pwd,glob
from pathlib import Path
u=pwd.getpwnam('info-backup');removed=[]
for name in glob.glob(PAYLOAD_PREFIX+'*.tar.*'):
    p=Path(name)
    assert p.is_file() and not p.is_symlink() and p.stat().st_uid==u.pw_uid
    p.unlink();removed.append(p.name)
print(json.dumps({'payload_removed':removed}))
'''.replace('PAYLOAD_PREFIX', repr(staging_payload(source)))
    return guest_json(code)


def start_extraction(source):
    unit = 'info-db-verify-audit-' + source
    if payload_state(source)['exists']:
        # Пейлоад от прежнего запуска того же источника: свежесть всё равно
        # перепроверяется по snapshot_id и SHA после передачи.
        say('reuse_existing_payload', source=source)
        return
    argv = [
        'systemd-run', '--unit', unit,
        '--property=User=info-backup', '--property=Group=info-backup',
        '--property=UMask=0077', '--property=Nice=15', '--property=IOSchedulingClass=idle',
        '--property=TimeoutStartSec=5400',
        '--property=BindPaths=/srv/restic/projects-staging:/var/lib/info-backup/projects/staging',
        '/usr/bin/python3', '/opt/info-backup/audit-restic-databases.py', source,
    ]
    if CONFIG[source].get('xz'):
        argv.append('--xz')
    code = (
        "import json,subprocess\n"
        "subprocess.run(['systemctl','reset-failed',UNIT],capture_output=True,text=True)\n"
        "args=ARGV\n"
        "r=subprocess.run(args,capture_output=True,text=True)\n"
        "if r.returncode:raise RuntimeError('audit_unit_start_failed:'+r.stderr[-200:])\n"
        "print(json.dumps({'started':UNIT}))\n"
    ).replace('UNIT', repr(unit)).replace('ARGV', repr(argv))
    guest_json(code)
    deadline = time.monotonic() + 5500
    while time.monotonic() < deadline:
        code = (
            "import json,subprocess\n"
            "p=subprocess.run(['systemctl','show',UNIT,'-p','ActiveState','-p','Result','-p','ExecMainStatus'],capture_output=True,text=True)\n"
            "d=dict(line.split('=',1) for line in p.stdout.splitlines() if '=' in line)\n"
            "print(json.dumps(d))\n"
        ).replace('UNIT', repr(unit))
        state = guest_json(code)
        if state.get('ActiveState') == 'failed':
            raise RuntimeError('archive_audit_failed:' + source)
        if state.get('ActiveState') == 'inactive':
            if state.get('Result') != 'success' or state.get('ExecMainStatus') != '0':
                raise RuntimeError('archive_audit_incomplete:' + source)
            pull.guest("import subprocess;subprocess.run(['systemctl','reset-failed'," + repr(unit) + "],check=False);print('reset')")
            return
        time.sleep(10)
    raise RuntimeError('archive_audit_deadline:' + source)


def record_proof(source, proof):
    blob = base64.b64encode(json.dumps(proof).encode()).decode()
    code = '''import base64,json,datetime as dt,importlib.util,os,pwd
from pathlib import Path
source=SOURCE;proof=json.loads(base64.b64decode(BLOB));base=Path('/var/lib/info-backup/projects')
receipt=json.loads((base/'receipts'/(source+'.json')).read_text())
spec=importlib.util.spec_from_file_location('p','/opt/info-backup/publish-project-status.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
m.database_restore_evidence(proof,receipt,source,dt.datetime.now(dt.timezone.utc))
folder=base/'database-restore-proofs';folder.mkdir(mode=0o700,exist_ok=True)
u=pwd.getpwnam('info-backup');os.chmod(folder,0o700);os.chown(folder,u.pw_uid,u.pw_gid)
p=folder/(source+'.json');temporary=p.with_suffix('.tmp');temporary.write_text(json.dumps(proof));os.chmod(temporary,0o600);os.chown(temporary,u.pw_uid,u.pw_gid);os.replace(temporary,p)
print(json.dumps({'proof_recorded':source,'verified_at':proof['verified_at']}))
'''.replace('SOURCE', repr(source)).replace('BLOB', repr(blob))
    return guest_json(code)


def import_on_source(source, payload, root):
    cfg = CONFIG[source]
    files = [payload, REPO / 'db-restore-check.py', REPO / 'check-archive-databases.py']
    remote_root = remote(source, 'umask 077; mktemp -d /tmp/info-db-verify.XXXXXXXX')
    assert re.fullmatch(r'/tmp/info-db-verify\.[A-Za-z0-9]+', remote_root)
    sudo = 'sudo ' if cfg['sudo'] else ''
    try:
        run(cfg['scp'] + ['-q'] + SSH_OPTIONS + list(map(str, files)) + [cfg['target'] + ':' + remote_root + '/'],
            private_log=root / (source + '-scp.private.log'))
        command = sudo + 'python3 ' + ' '.join(shlex.quote(x) for x in [
            remote_root + '/check-archive-databases.py', remote_root + '/' + payload.name,
            cfg['config'], remote_root + '/proof.json'])
        remote(source, command, private_log=root / (source + '-import.private.log'))
        return json.loads(remote(source, sudo + 'python3 -c ' + shlex.quote(
            'from pathlib import Path;print(Path(' + repr(remote_root + '/proof.json') + ').read_text())')))
    finally:
        assert remote(source, 'realpath -- ' + shlex.quote(remote_root)) == remote_root
        remote(source, sudo + 'rm -rf -- ' + shlex.quote(remote_root))


def import_locally(payload, root, config_blob):
    directory = root / 'local-import'
    directory.mkdir(mode=0o700)
    try:
        for name in ('db-restore-check.py', 'check-archive-databases.py'):
            shutil.copy2(REPO / name, directory / name)
        shutil.copy2(payload, directory / payload.name)
        config_path = directory / 'config.json'
        config_path.write_text(json.dumps(config_blob))
        output = directory / 'proof.json'
        run(['python3', str(directory / 'check-archive-databases.py'), str(directory / payload.name),
             str(config_path), str(output)], private_log=root / 'local-import.private.log', timeout=7200)
        return json.loads(output.read_text())
    finally:
        shutil.rmtree(directory, ignore_errors=True)


def verify_source(source, root):
    receipt = receipt_and_proof(source)
    if receipt.get('proof_current'):
        say('skipped_already_verified', source=source,
            verified_at=receipt['proof'].get('verified_at'), databases=receipt['proof'].get('checks'))
        return {'source': source, 'status': 'already_verified', 'verified_at': receipt['proof'].get('verified_at')}
    age = dt.datetime.now(dt.timezone.utc) - dt.datetime.fromisoformat(
        receipt['receipt']['verified_at'].replace('Z', '+00:00'))
    if age > dt.timedelta(hours=FRESH_HOURS):
        say('skipped_stale_receipt', source=source, age_hours=round(age.total_seconds() / 3600, 1))
        return {'source': source, 'status': 'stale_receipt'}

    say('audit_start', source=source, snapshot=receipt['receipt']['snapshot_id'][:12],
        databases=receipt['receipt']['databases'])
    start_extraction(source)
    say('archive_sha_verified', source=source)
    transfer = run(['python3', str(REPO / 'pull-audit-from-giga.py'), source, '--into', str(root)],
                   private_log=root / (source + '-transfer.private.log'), timeout=7200)
    payload_name = json.loads(transfer.splitlines()[-1])['payload_name']
    payload = root / payload_name
    with tarfile.open(payload, 'r:*') as archive:
        metadata = json.load(archive.extractfile('audit.json'))
    assert metadata['source'] == source and metadata['archive_sha_verified'] is True

    cfg = CONFIG[source]
    if cfg['mode'] == 'remote':
        proof = import_on_source(source, payload, root)
    elif cfg['mode'] == 'local':
        # Рабочая VM импортирует собственные дампы по своему же конфигу контейнеров.
        local_config = json.loads(Path(cfg['config']).read_text())
        local_config['source'] = source
        local_config.setdefault('timeout_sec', cfg.get('timeout_sec', 900))
        proof = import_locally(payload, root, local_config)
    else:
        proof = import_locally(payload, root, {'source': source, 'mysql': [], 'timeout_sec': cfg.get('timeout_sec', 600),
                                               'images': cfg['images'], 'clients': cfg['clients']})
    assert proof['snapshot_id'] == metadata['snapshot_id'] == receipt['receipt']['snapshot_id']
    assert proof['archive_sha256'] == metadata['archive_sha256'] == receipt['receipt']['archive_sha256']
    record_proof(source, proof)
    (root / (source + '-proof.json')).write_text(json.dumps(proof, indent=2))
    payload.unlink()
    drop_payload(source)
    say('database_import_passed', source=source, databases=len(proof['checks']), verified_at=proof['verified_at'])
    return {'source': source, 'status': 'verified', 'verified_at': proof['verified_at'],
            'databases': len(proof['checks'])}


def publish():
    pull.guest("import subprocess;subprocess.run(['systemctl','start','projects-backup-status.service'],check=True);print('published')")
    try:
        run(['ssh'] + SSH_OPTIONS + ['amn-ru2', 'systemctl start info-backup-card.service'], timeout=120)
    except Exception as error:  # noqa: BLE001 — карточка обновится следующим циклом
        say('card_refresh_failed', reason=type(error).__name__)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--sources', default=','.join(SOURCES))
    parser.add_argument('--max-age-hours', type=float, default=30.0)
    parser.add_argument('--no-publish', action='store_true')
    args = parser.parse_args()
    global FRESH_HOURS
    FRESH_HOURS = args.max_age_hours
    os.umask(0o077)
    STATE.mkdir(parents=True, exist_ok=True, mode=0o700)
    root = Path(tempfile.mkdtemp(prefix='db-verify-', dir=STATE))
    results, failed = [], []
    for source in [s.strip() for s in args.sources.split(',') if s.strip()]:
        try:
            results.append(verify_source(source, root))
        except Exception as error:  # noqa: BLE001 — один источник не должен ломать остальные
            # Пейлоад на VM310 не удаляем: повторный запуск переиспользует его,
            # не тратя ещё полчаса на извлечение из архива.
            say('verification_failed', source=source, error_type=type(error).__name__,
                reason=str(error)[:300], private_root=str(root))
            results.append({'source': source, 'status': 'failed', 'reason': str(error)[:300]})
            failed.append(source)
    if not args.no_publish and not failed:
        publish()
    summary = {'finished_at': dt.datetime.now(dt.timezone.utc).isoformat(), 'sources': results,
               'failed': failed}
    (STATE / 'last-run.json').write_text(json.dumps(summary, indent=2, ensure_ascii=False))
    say('finished', failed=failed, sources=[(r['source'], r['status']) for r in results])
    if failed:
        return 1
    shutil.rmtree(root, ignore_errors=True)
    return 0


if __name__ == '__main__':
    sys.exit(main())
