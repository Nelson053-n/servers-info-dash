#!/usr/bin/python3
"""Fixed read-only filesystem view; command arguments never select paths."""
import os,sys,json,subprocess
from pathlib import Path
if os.environ.get('SSH_ORIGINAL_COMMAND')!='export-projects-v1' or len(sys.argv)!=1:raise SystemExit(64)
os.umask(0o077)
base=Path('/home/nel/.local/share/project-backup');config=json.loads((base/'config.json').read_text());cache=Path('/home/nel/.cache/project-backup-export');cache.mkdir(mode=0o700,exist_ok=True)
args=['docker','run','--rm','--network','none','--read-only','--user','0','--memory','512m','--cpus','0.5','--security-opt','no-new-privileges','--entrypoint','python3','--env','DOCKER_HOST=unix:///var/run/docker.sock']
for path in config['roots']+[str(base)]:args+=['--mount','type=bind,src='+path+',dst='+path+',readonly']
args+=['--mount','type=bind,src='+str(cache)+',dst='+str(cache),'--mount','type=bind,src=/var/run/docker.sock,dst=/var/run/docker.sock,readonly','--mount','type=bind,src=/usr/bin/docker,dst=/usr/local/bin/docker,readonly']
code=r"""import os,json,importlib.util,sys
from pathlib import Path
os.umask(0o077)
base=Path('/home/nel/.local/share/project-backup');spec=importlib.util.spec_from_file_location('exporter',base/'export-projects.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);m.EXPORT_ROOT=Path('/home/nel/.cache/project-backup-export')
try:
 m.export(json.loads((base/'config.json').read_text()));(m.EXPORT_ROOT/'last-error.txt').unlink(missing_ok=True)
except Exception as e:
 (m.EXPORT_ROOT/'last-error.txt').write_text(type(e).__name__+': '+str(e)+'\n');print('project export failed',file=sys.stderr);raise SystemExit(65)
"""
args+=['python@sha256:4840d514c583a4d3d8cad3940e68dee6f0f6f3635c12fcd0a3d74c21a5b93a54','-c',code]
raise SystemExit(subprocess.run(args).returncode)
