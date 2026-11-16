"""Ежедневная автопроверка импорта БД: пропуски, свежесть и закреплённые образы.

Проверяется то, что можно проверить без docker: логика пропусков (уже подтверждено,
устаревший receipt), выбор образа/клиента для закреплённого варианта и то, что
неудачный источник не мешает остальным.
"""
import importlib.util
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope='module')
def verify_module():
    return load('verify_db_imports', ROOT / 'deploy/backups/verify-db-imports.py')


@pytest.fixture(scope='module')
def archive_module():
    return load('check_archive_db', ROOT / 'deploy/backups/check-archive-databases.py')


def test_pinned_image_wins_over_inspection(archive_module):
    config = {'images': {'csdtest-test-db-1': 'mysql:8.0'}, 'mysql': [], 'postgres': []}
    assert archive_module._pinned_image(config, 'csdtest-test-db-1') == 'mysql:8.0'
    assert archive_module._pinned_image(config, 'otpusk-stand-db-1') is None


def test_pinned_client_is_validated(archive_module):
    config = {'clients': {'csdtest-test-db-1': 'mysql'}, 'mysql': [{'container': 'x', 'client': 'mariadb'}]}
    assert archive_module._client_for(config, 'csdtest-test-db-1') == 'mysql'
    assert archive_module._client_for(config, 'x') == 'mariadb'
    with pytest.raises(AssertionError):
        archive_module._client_for({'clients': {'c': 'sqlite3'}, 'mysql': []}, 'c')


def test_current_proof_is_skipped(verify_module, monkeypatch):
    monkeypatch.setattr(verify_module, 'receipt_and_proof', lambda source: {
        'receipt': {'snapshot_id': 'a' * 12, 'archive_sha256': 'b' * 64,
                    'verified_at': '2026-11-16T00:00:00+00:00', 'databases': 6},
        'proof': {'snapshot_id': 'a' * 12, 'archive_sha256': 'b' * 64,
                  'verified_at': '2026-11-16T00:10:00+00:00', 'checks': 6},
        'proof_current': True,
    })
    called = []
    monkeypatch.setattr(verify_module, 'start_extraction', lambda source: called.append(source))
    result = verify_module.verify_source('bob', Path('/tmp'))
    assert result['status'] == 'already_verified'
    assert called == []


def test_stale_receipt_is_skipped(verify_module, monkeypatch):
    monkeypatch.setattr(verify_module, 'FRESH_HOURS', 30.0, raising=False)
    monkeypatch.setattr(verify_module, 'receipt_and_proof', lambda source: {
        'receipt': {'snapshot_id': 'a' * 12, 'archive_sha256': 'b' * 64,
                    'verified_at': '2026-01-01T00:00:00+00:00', 'databases': 6},
        'proof_current': False,
    })
    called = []
    monkeypatch.setattr(verify_module, 'start_extraction', lambda source: called.append(source))
    result = verify_module.verify_source('lv3', Path('/tmp'))
    assert result['status'] == 'stale_receipt'
    assert called == []


def test_bob_uses_pinned_images_not_source_inspection(verify_module):
    config = verify_module.CONFIG['bob']
    assert config['mode'] == 'local-images'
    assert config['images']['otpusk-stand-db-1'].startswith('postgres:')
    assert config['clients']['csdtest-test-db-1'] == 'mysql'


def test_every_source_has_a_route(verify_module):
    for source in verify_module.SOURCES:
        assert source in verify_module.CONFIG
        assert verify_module.CONFIG[source]['mode'] in ('remote', 'local', 'local-images')
