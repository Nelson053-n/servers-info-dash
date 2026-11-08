import json,sys,subprocess,tempfile,os,datetime,importlib.util
from pathlib import Path
spec=importlib.util.spec_from_file_location('restore',Path(__file__).with_name('db-restore-check.py'));r=importlib.util.module_from_spec(spec);spec.loader.exec_module(r)
os.umask(0o077)
config=json.load(open(sys.argv[1])); proofs=[]
def out(args):return subprocess.check_output(args,stderr=subprocess.DEVNULL,timeout=60).decode().strip()
def dump(args,path):
 with path.open('wb') as f:subprocess.run(args,stdout=f,stderr=subprocess.DEVNULL,check=True,timeout=600)
 assert path.stat().st_size>0
with tempfile.TemporaryDirectory(prefix='info-db-proof-') as temp:
 root=Path(temp)
 for e in config.get('mysql',[]):
  c=e['container'];client=e['client'];setup=('export MYSQL_PWD="$(cat /run/secrets/db_root_password)"; ' if e.get('secret_file') else 'export MYSQL_PWD="$MYSQL_ROOT_PASSWORD"; ')
  names=out(['docker','exec',c,'sh','-c',setup+'exec '+client+' -uroot -N -e "SHOW DATABASES"']).splitlines()
  image=out(['docker','inspect','-f','{{.Image}}',c])
  for db in names:
   if db in ['mysql','information_schema','performance_schema','sys']:continue
   p=root/'mysql.sql'
   dump(['docker','exec',c,'sh','-c',setup+'exec '+e['dumper']+' -uroot --single-transaction --routines --events --databases "$1"','sh',db],p)
   proof=r.restore_dump(p,'mysql',image,client);proof.update(container=c,database=db,bytes=p.stat().st_size);proofs.append(proof)
 for c in config.get('postgres',[]):
  running=out(['docker','inspect','-f','{{.State.Running}}',c])=='true'
  if not running:
   state=json.loads(out(['docker','inspect',c]))[0]
   if c in config.get('nonpersistent_test_containers',[]) and '/var/lib/postgresql/data' in (state.get('HostConfig',{}).get('Tmpfs') or {}):continue
   raise RuntimeError('postgres_stopped:'+c)
  image=out(['docker','inspect','-f','{{.Image}}',c])
  names=out(['docker','exec',c,'sh','-c','exec psql -X -U "$POSTGRES_USER" -d postgres -At -c "SELECT datname FROM pg_database WHERE NOT datistemplate"']).splitlines()
  for db in names:
   p=root/'postgres.dump';dump(['docker','exec',c,'sh','-c','exec pg_dump -U "$POSTGRES_USER" -Fc -- "$1"','sh',db],p)
   proof=r.restore_dump(p,'postgres',image);proof.update(container=c,database=db,bytes=p.stat().st_size);proofs.append(proof)
 native=config.get('native_postgres')
 if native:
  client=['docker','run','--rm','--network','none','--user',str(native['uid']),'--mount','type=bind,src='+native['socket']+',dst='+native['socket']+',readonly',native['image']]
  auth=['-h',native['socket'],'-U','postgres']
  names=out(client+['psql','-X']+auth+['-d','postgres','-At','-c','SELECT datname FROM pg_database WHERE NOT datistemplate']).splitlines()
  for db in names:
   p=root/'native.dump';dump(client+['pg_dump']+auth+['-Fc','--',db],p)
   proof=r.restore_dump(p,'postgres',native['image']);proof.update(container='native',database=db,bytes=p.stat().st_size);proofs.append(proof)
result={'source':config['source'],'verified_at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'checks':proofs}
Path(sys.argv[2]).write_text(json.dumps(result,indent=2))
print(json.dumps(result,ensure_ascii=False))
