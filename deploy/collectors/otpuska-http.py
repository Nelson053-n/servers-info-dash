#!/usr/bin/env python3
"""Info snapshot from Bob's existing HTTP tunnel; no business writes."""
import argparse
import datetime as dt
import http.cookies
import json
import os
from pathlib import Path
import urllib.error
import urllib.request


class AccessError(Exception):
    def __init__(self, status):
        self.status = status


class Client:
    def __init__(self, credentials, session):
        self.credentials = credentials
        self.session_path = session
        self.cache = json.loads(session.read_text()) if session.exists() else {}
        self.statuses = {}
        self.tried_login = False

    def save(self):
        self.session_path.write_text(json.dumps(self.cache))
        self.session_path.chmod(0o600)

    def request(self, path, *, body=None, public=False):
        headers = {'Host': 'kad.csdtest.ru', 'Origin': 'https://kad.csdtest.ru',
                   'X-Forwarded-Proto': 'https', 'User-Agent': 'Info-collector-readonly'}
        if not public and self.cache.get('cookie'):
            headers['Cookie'] = self.cache['cookie']
        if body is not None:
            headers['Content-Type'] = 'application/json'
        request = urllib.request.Request('http://127.0.0.1:18080' + path, headers=headers,
                                         data=None if body is None else json.dumps(body).encode())
        try:
            with urllib.request.urlopen(request, timeout=15) as response:
                self.statuses[path] = response.status
                if not public:
                    jar = http.cookies.SimpleCookie()
                    jar.load(self.cache.get('cookie', ''))
                    for value in response.headers.get_all('Set-Cookie', []):
                        jar.load(value)
                    self.cache['cookie'] = '; '.join(k + '=' + v.value for k, v in jar.items())
                return response.read()
        except urllib.error.HTTPError as exc:
            self.statuses[path] = exc.code
            raise AccessError(exc.code) from None
        except (OSError, TimeoutError):
            self.statuses[path] = None
            raise AccessError(None) from None

    def login(self):
        stamp = self.credentials.stat().st_mtime_ns
        if self.tried_login or self.cache.get('blocked_credentials_mtime') == stamp:
            raise AccessError(401)
        self.tried_login = True
        credentials = json.loads(self.credentials.read_text())
        try:
            self.request('/api/v1/auth/login', body=credentials, public=False)
        except AccessError as exc:
            if exc.status in (401, 403):
                self.cache['blocked_credentials_mtime'] = stamp
            raise
        self.cache.pop('blocked_credentials_mtime', None)

    def get(self, path, *, text=False):
        try:
            body = self.request(path)
        except AccessError as exc:
            if exc.status != 401:
                return None
            try:
                self.login()
                body = self.request(path)
            except AccessError:
                return None
        try:
            return body.decode('utf-8') if text else json.loads(body)
        except (ValueError, UnicodeError):
            return None


def collect(credentials, session):
    client = Client(credentials, session)
    try:
        client.request('/healthz', public=True)
    except AccessError:
        pass
    me = client.get('/api/v1/me')
    campaign = employees = delivery = progress = ops = None
    if me is not None:
        campaign = client.get('/api/v1/campaigns/current')
        employees = client.get('/api/v1/employees?limit=1')
        delivery = client.get('/api/v1/notifications/delivery')
        if campaign and isinstance(campaign.get('year'), int):
            progress = client.get('/api/v1/reports/campaign_progress?format=json'
                                  '&section=departments&limit=100&year=' + str(campaign['year']))
        ops = client.get('/api/v1/ops/metrics', text=True)
    client.save()
    return build(client.statuses, me is not None, campaign, employees, delivery, progress, ops)


def build(statuses, authenticated, campaign, employees, delivery, progress, ops=None):
    kpis, tables, alerts = [], [], []
    health = statuses.get('/healthz')
    live = health == 200 and authenticated
    kpis.append({'id': 'stand', 'label': 'Сервис', 'value': 'работает' if live else 'нет проверки',
                 'state': 'ok' if live else 'warn', 'hint': 'HTTP frontend и авторизованный запрос backend /me'})
    labels = {'collecting': 'сбор пожеланий', 'approval': 'согласование', 'hr_check': 'проверка кадрами',
              'approved': 'утверждён', 'execution': 'исполнение', 'closed': 'закрыт', 'draft': 'черновик'}
    if campaign:
        kpis.append({'id': 'campaign', 'label': 'Кампания ' + str(campaign['year']),
                     'value': labels.get(campaign['status'], campaign['status']),
                     'hint': f"сбор до {campaign.get('collect_until')}, согласование до {campaign.get('approve_until')}"})
    if employees is not None and isinstance(employees.get('total'), int):
        kpis.append({'id': 'employees', 'label': 'Работников в реестре', 'value': employees['total'],
                     'hint': 'Область HR-учётной записи; активные и неактивные'})
    if progress:
        summary = {item['label']: item['value'] for item in progress.get('summary', [])}
        if 'Итого работников' in summary:
            kpis.append({'id': 'participants', 'label': 'Участников кампании',
                         'value': int(summary['Итого работников'])})
        for item in progress.get('summary', []):
            if item['label'].startswith('Не участвуют'):
                kpis.append({'id': 'excluded', 'label': 'Не участвуют в кампании', 'value': int(item['value'])})
        columns = [{'key': c['key'], 'label': c['title'], 'num': c.get('kind') != 'text'}
                   for c in progress.get('columns', [])]
        rows = progress.get('rows', [])
        tables.append({'id': 'campaign_progress', 'title': 'Ход кампании по подразделениям',
                       'columns': columns, 'rows': rows})
        if progress.get('next_cursor'):
            alerts.append({'severity': 'warn', 'text': 'Таблица кампании: показаны первые 100 подразделений'})
        elif rows and all('in_approval' in row for row in rows):
            kpis.append({'id': 'employees_in_approval', 'label': 'Работников на согласовании',
                         'value': sum(row['in_approval'] for row in rows),
                         'hint': 'Работники из отчёта кампании; это не число задач согласования'})
    if delivery is not None:
        kpis.append({'id': 'email_enabled', 'label': 'Email-уведомления',
                     'value': 'включены' if delivery['email_enabled'] else 'выключены'})
        tables.append({'id': 'delivery', 'title': 'Уведомления: фактические счётчики',
                       'columns': [{'key': 'channel', 'label': 'Канал'}] +
                                  [{'key': k, 'label': label, 'num': True} for k, label in
                                   [('pending', 'Ожидают'), ('sent', 'Отправлены'), ('failed', 'Ошибки'),
                                    ('read', 'Прочитаны'), ('cancelled', 'Отменены')]],
                       'rows': [{k: row.get(k) for k in ('channel', 'pending', 'sent', 'failed', 'read', 'cancelled')}
                                for row in delivery.get('channels', [])]})
        if any(row.get('failed', 0) for row in delivery.get('channels', [])
               if row.get('channel') != 'email' or delivery['email_enabled']):
            alerts.append({'severity': 'warn', 'text': 'Есть ошибки доставки уведомлений'})
    if not authenticated:
        alerts.append({'severity': 'warn', 'text': 'Доступ к бизнес-агрегатам не подтверждён'})
    missing = []
    for available, name in [(campaign, 'кампания'), (employees, 'число работников'),
                            (progress, 'ход кампании'), (delivery, 'счётчики уведомлений')]:
        if available is None:
            missing.append(name)
    if missing:
        alerts.append({'severity': 'warn', 'text': 'Не получены: ' + ', '.join(missing)})
    alerts.append({'severity': 'warn', 'text': 'Для проверки бэкапов, CI runner, диска и контейнеров '
                   'нужен SSH-доступ к Bob. Текущий сборщик использует HTTP-туннель приложения через RU3.'})
    ops_labels = {
        'otpusk_approval_overdue_tasks': 'Просроченных задач согласования',
        'otpusk_inapp_pending': 'Уведомлений портала в очереди',
        'otpusk_db_connections': 'Соединений с базой',
        'otpusk_db_connections_active': 'Активных соединений с базой',
    }
    ops_rows = []
    for line in (ops or '').splitlines():
        parts = line.split()
        if len(parts) == 2 and parts[0] in ops_labels and parts[1].isdigit():
            ops_rows.append({'metric': ops_labels[parts[0]], 'value': int(parts[1])})
    if ops_rows:
        tables.append({'id': 'ops', 'title': 'Служебные показатели приложения',
                       'columns': [{'key': 'metric', 'label': 'Показатель'},
                                   {'key': 'value', 'label': 'Значение', 'num': True}],
                       'rows': ops_rows})
    else:
        status = statuses.get('/api/v1/ops/metrics')
        reason = ('у учётной записи сборщика нет права ops.view (HTTP 403)'
                  if status == 403 else 'не получен корректный ответ от /api/v1/ops/metrics')
        alerts.append({'severity': 'warn', 'text': 'Служебные показатели приложения недоступны: '
                       + reason + '. Нужен доступ сборщика к OPS.'})
    tables.append({'id': 'http_checks', 'title': 'Проверки источников',
                   'columns': [{'key': 'endpoint', 'label': 'Endpoint'}, {'key': 'http', 'label': 'HTTP'}],
                   'rows': [{'endpoint': path.split('?')[0], 'http': code if code is not None else 'нет ответа'}
                            for path, code in statuses.items()]})
    unverified = ['backups', 'ci_runner', 'disk', 'containers',
                  'global_approval_tasks', 'historical_sql_charts']
    if not ops_rows:
        unverified.append('ops_metrics')
    return {'generated_at': dt.datetime.now(dt.timezone.utc).isoformat(), 'kpis': kpis,
            'tables': tables, 'charts': [], 'alerts': alerts,
            '_source': {'kind': 'existing Bob HTTP API through RU3 localhost:18080',
                        'scope': 'HR API; aggregate counts only, no personal employee fields',
                        'unverified': unverified}}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--credentials', type=Path, default=Path('/opt/info-collectors/otpuska.credentials.json'))
    parser.add_argument('--session', type=Path, default=Path('/opt/info-collectors/otpuska.session.json'))
    parser.add_argument('--output', type=Path, default=Path('/var/lib/infodash/projects/otpuska.json'))
    args = parser.parse_args()
    os.umask(0o077)
    document = collect(args.credentials, args.session)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    temporary = args.output.with_suffix('.json.tmp')
    temporary.write_text(json.dumps(document, ensure_ascii=False, indent=2))
    temporary.chmod(0o644)
    temporary.replace(args.output)
    print('otpuska snapshot written; source HTTP API; kpis=' + str(len(document['kpis'])))


if __name__ == '__main__':
    main()
