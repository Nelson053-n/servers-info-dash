import base64
import hashlib
import importlib.util
import json
from pathlib import Path
import pytest

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('db_audit_transfer',ROOT/'deploy/backups/pull-audit-from-giga.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)

@pytest.mark.parametrize('corrupt',[False,True])
def test_audit_transfer_checks_full_payload_sha(tmp_path,monkeypatch,capsys,corrupt):
    tmp_path.chmod(0o700);payload=b'private SQL audit payload'
    def guest(code):
        if "'sha256'" in code:return json.dumps({'size':len(payload),'sha256':hashlib.sha256(payload).hexdigest()})
        data=b'X'+payload[1:] if corrupt else payload
        return base64.b64encode(data).decode()
    monkeypatch.setattr(m,'guest',guest)
    monkeypatch.setattr(m.os,'getuid',lambda:tmp_path.stat().st_uid)
    monkeypatch.setattr(m,'__name__','transfer_test')
    import sys
    monkeypatch.setattr(sys,'argv',['transfer','lv3','--into',str(tmp_path)])
    if corrupt:
        with pytest.raises(AssertionError,match='checksum mismatch'):m.main()
    else:
        m.main()
        assert (tmp_path/'lv3-db-restore-audit.tar.gz').read_bytes()==payload
        output=capsys.readouterr().out;assert 'transfer_sha_verified' in output and 'private SQL' not in output
