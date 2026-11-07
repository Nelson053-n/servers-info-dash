import asyncio
import json

from app import main

app = main.app
original_collect = main.collector.collect_all
last_rows = []
bridge_failed = False
hidden_nodes = {'Финляндия 2', 'Швеция', 'Нидерланды'}
original_fetch_analytics = main.projects_tab.fetch_analytics


def fetch_visible_analytics(source):
    document = original_fetch_analytics(source)
    if source.url and 'panel.oneyearsolution.com' in source.url:
        for table in document.get('tables', []):
            if table.get('id') == 'servers':
                table['rows'] = [row for row in table.get('rows', []) if row.get('name') not in hidden_nodes]
                for kpi in document.get('kpis', []):
                    if kpi.get('id') == 'nodes' and isinstance(kpi.get('value'), str):
                        active = kpi['value'].split('/')[0].strip()
                        kpi['value'] = f"{active} / {len(table['rows'])}"
        alerts = []
        for alert in document.get('alerts', []):
            text = alert.get('text', '')
            if text.startswith(('ТСПУ блокирует (cheburcheck): ', 'VPN с РФ заблокирован (флаг): ', 'Ноды офлайн: ')):
                prefix, names = text.split(': ', 1)
                visible = [name for name in names.split(', ') if name not in hidden_nodes]
                if not visible:
                    continue
                alert = {**alert, 'text': prefix + ': ' + ', '.join(visible)}
            alerts.append(alert)
        document['alerts'] = alerts
    return document


main.projects_tab.fetch_analytics = fetch_visible_analytics
original_probe_via_server = main.projects_tab.probe_via_server


async def probe_via_recovery_server(url, server_name, servers_path=main.projects_tab.SERVERS_PATH):
    if server_name != 'ru3-otpuska-tunnel':
        return await original_probe_via_server(url, server_name, servers_path)
    return await asyncio.to_thread(main.projects_tab.probe_http, 'http://127.0.0.1:18080/healthz')


main.projects_tab.probe_via_server = probe_via_recovery_server


async def rustdesk_port(port):
    try:
        _, writer = await asyncio.wait_for(asyncio.open_connection('217.26.27.80', port), 3)
        writer.close()
        await writer.wait_closed()
        return port, True
    except (OSError, asyncio.TimeoutError):
        return port, False


def number(value, divisor=1):
    return None if value is None else round(float(value) / divisor, 3)


import time as _time

# Раньше один сбой SSH до панели навсегда (до перезапуска контейнера) ставил bridge_failed=True —
# и все ноды из панели показывались «не на связи», хотя панель снова отвечала.
# Теперь — повтор с нарастающей паузой: 1, 2, 5, 10, 15 мин; успех сбрасывает счётчик.
# Защита от долбёжки сломанной авторизации сохраняется: при постоянной ошибке — одна попытка в 15 мин.
_BACKOFF_MIN = [1, 2, 5, 10, 15]
bridge_failures = 0
bridge_retry_at = 0.0
bridge_last_error = None


async def collect_with_panel():
    global last_rows, bridge_failed, bridge_failures, bridge_retry_at, bridge_last_error
    data = await original_collect()
    source_error = None
    bridge_failed = bridge_failures > 0 and _time.monotonic() < bridge_retry_at
    if not bridge_failed:
        try:
            process = await asyncio.create_subprocess_exec(
                'ssh', '-F', '/run/secrets/ssh_config', '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=yes',
                '-o', 'IdentitiesOnly=yes', '-o', 'ConnectionAttempts=1',
                '-o', 'ConnectTimeout=8', 'amn-lv3',
                'info-panel-metrics',
                stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            try:
                stdout, _ = await asyncio.wait_for(
                    process.communicate(), 25,
                )
            except BaseException:
                if process.returncode is None:
                    process.kill()
                    await process.wait()
                raise
            if process.returncode:
                raise RuntimeError('panel SSH query failed')
            rows = json.loads(stdout)['servers']
            assert isinstance(rows, list) and rows
            last_rows = rows
            bridge_failures, bridge_last_error = 0, None
        except Exception as exc:
            bridge_failures += 1
            bridge_last_error = type(exc).__name__
            pause = _BACKOFF_MIN[min(bridge_failures, len(_BACKOFF_MIN)) - 1]
            bridge_retry_at = _time.monotonic() + pause * 60
            source_error = f'панель недоступна ({bridge_last_error}), повтор через {pause} мин'
    if bridge_failed:
        left = max(0, round((bridge_retry_at - _time.monotonic()) / 60))
        source_error = f'панель недоступна ({bridge_last_error}), повтор через {left} мин'
    # В панели одна машина может числиться несколькими нодами (разные протоколы на одном IP).
    # Для парка серверов это одна машина: иначе её сбой считается дважды в «на связи» и в замечаниях.
    by_host = {}
    for row in last_rows:
        if row['name'] in hidden_nodes:
            continue
        if row.get('host') and row['host'] in by_host:
            by_host[row['host']].setdefault('aliases', []).append(row['name'])
            continue
        fresh = row['age_sec'] is not None and 0 <= int(row['age_sec']) <= 180
        available = not source_error and fresh and row['cpu_percent'] is not None
        disk_total = number(row['disk_total_gb']) if available else None
        disk_used = number(row['disk_used_gb']) if available else None
        entry = {
            'name': row['name'], 'host': row['host'], 'country': row['country_code'],
            'status': 'up' if available else 'down',
            'error': None if available else (source_error or f"Панель: {row['panel_status']}; нет свежих метрик"),
            'cpu_percent': number(row['cpu_percent']) if available else None,
            'ram_used_gb': number(row['ram_used_mb'], 1024) if available else None,
            'ram_total_gb': number(row['ram_total_mb'], 1024) if available else None,
            'disk_total_gb': disk_total,
            'disk_free_gb': None if disk_total is None or disk_used is None else max(0, disk_total - disk_used),
            'rx_mbps': number(row['network_rx_mbps']) if available else None,
            'tx_mbps': number(row['network_tx_mbps']) if available else None,
            'ping_ms': None, 'uptime_days': None, 'is_local': False,
            'interface': 'panel-db', 'metrics_source': 'amn-lv3/server_metrics',
            'source_collected_at': row['collected_at'], 'source_age_sec': row['age_sec'],
            'panel_status': row['panel_status'],
        }
        data['servers'].append(entry)
        if row.get('host'):
            by_host[row['host']] = entry
    data['panel_bridge_error'] = source_error
    ports = dict(await asyncio.gather(*(rustdesk_port(port) for port in (22, 21115, 21116, 21117))))
    open_ports = [str(p) for p, ok in ports.items() if ok]
    data['servers'].append({
        'name': 'RustDesk (217.26.27.80)', 'host': '217.26.27.80', 'country': None,
        'status': 'up' if ports[21117] else 'down',
        'error': None if ports[21117] else (
            'Relay-порт 21117 закрыт; открыты: ' + (', '.join(open_ports) if open_ports else 'ни один из 22/21115/21116')
            + '. Метрик нет: только TCP-наблюдение'),
        'tcp_ports': ports, 'metrics_source': 'tcp-probe',
        'cpu_percent': None, 'ram_used_gb': None, 'ram_total_gb': None,
        'disk_free_gb': None, 'disk_total_gb': None, 'rx_mbps': None, 'tx_mbps': None,
        'ping_ms': None, 'uptime_days': None, 'is_local': False, 'interface': 'tcp',
    })
    return data


main.collector.collect_all = collect_with_panel
