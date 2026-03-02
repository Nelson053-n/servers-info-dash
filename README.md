# Server Info Dashboard

Одноэкранный дашборд для мониторинга нескольких Linux-серверов:
- доступность сервера,
- ping до каждого сервера,
- загрузка CPU,
- загрузка сетевого канала (RX/TX Mbps).

## Безопасность

Проект сделан без хранения логинов/паролей:
- используется только SSH-аутентификация по ключам;
- парольная SSH-аутентификация принудительно отключена в клиенте;
- включена строгая проверка `known_hosts` (защита от MITM);
- приватные ключи и рабочий конфиг не коммитятся в Git.

Рекомендуется:
1. Использовать отдельного пользователя `monitor` с минимумом прав на каждом сервере.
2. На серверах отключить `PasswordAuthentication` в `sshd_config`.
3. Хранить ключ с passphrase и использовать `ssh-agent`.

## Быстрый старт

1. Создать виртуальное окружение и установить зависимости:
   - Windows PowerShell:
     ```powershell
     py -m venv .venv
     .\.venv\Scripts\Activate.ps1
     pip install -r requirements.txt
     ```
   - Linux/macOS:
     ```bash
     python -m venv .venv
     source .venv/bin/activate
     pip install -r requirements.txt
     ```

2. Подготовить конфиг:
   ```bash
   cp config/servers.example.yaml config/servers.yaml
   ```
   На Windows можно использовать:
   ```powershell
   Copy-Item config\servers.example.yaml config\servers.yaml
   ```

3. Отредактировать `config/servers.yaml`:
   - `user` — ваш SSH-пользователь (например `monitor`),
   - `host` — адрес сервера,
   - `interface` — сетевой интерфейс (`eth0`, `ens18` и т.д.),
   - `known_hosts` и `client_keys` — пути к файлам на вашей машине.

4. Запустить дашборд:
   ```bash
   python -m uvicorn app.main:app --host 0.0.0.0 --port 8000
   ```

5. Открыть в браузере:
   - `http://localhost:8000`

## Как считаются метрики

- `Ping` — локальная проверка ICMP до `host`.
- `CPU (%)` — расчет по дельте `/proc/stat` между опросами.
- `RX/TX (Mbps)` — расчет по дельте байтов `/proc/net/dev` между опросами.

> Важно: первый цикл после старта показывает `CPU/RX/TX` как `—`, потому что нужны две точки измерения.
