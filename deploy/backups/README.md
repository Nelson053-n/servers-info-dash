# Резервирование проектов на Giga

Рабочая схема: VM310 `projects-backup` на Proxmox Giga `192.168.10.100`.
Публичный Info и BondAI работают на RU2; сборщики Info и часть приложений — на RU3.

## Источники

- RU2: `/opt/info-recovery`, `/opt/bonds-recovery`, получатель статусов, сводки и настройки сервисов. SQLite копируется через backup API; сохраняются образы запущенных приложений и их inspect-метаданные.
- RU3: Бананоген, Wakeparty, FluxRadar, GlobalAuto, Машины, KendoSolki, Trade4. Выгрузки PostgreSQL, MariaDB, Redis; файлы, загрузки, конфигурация и образы приложений.
- Латвия: OneYearSolution `/opt/amnpanel`, MySQL, сохранённые конфигурации нод и образ панели. Это не образ операционных систем всех VPN-нод.
- Kuma `89.110.120.66`: SQLite, каталог данных, настройки, экспортёр и образ.
- Рабочая VM: выбранные каталоги проектов, локальный Info, пользовательские systemd units, SQLite, native PostgreSQL и работающие локальные PostgreSQL/MySQL containers. Это дополнительный источник, не замена публичных баз. Остановленная тестовая `pg-int` на tmpfs не содержит сохранившегося PGDATA (проверено: PG_VERSION отсутствует); она отмечается в manifest как nonpersistent_test_database и не запускается ради пустой копии. Работающий временный кластер выгружается обычным способом, постоянные базы сохраняются.
- Bob / «График отпусков»: **отложен владельцем 6 ноября 2026** до появления рабочего SSH-маршрута. Локальный код не подтверждает копию его рабочей БД.

Список директорий задаётся в `/etc/projects-backup/export.json` на источнике. Глобальные истории ассистента и установки инструментов не включены. Зависимости `node_modules`/`.venv`, Rust `target`, кеши и `__pycache__` исключены; `.next` runtime сохраняется, его cache — нет. Истории приложения/CSV и каталоги сохранённых backups сохраняются. Каталог сохранённых конфигураций нод OneYearSolution предварительно копируется с зафиксированным набором файлов; новые поступления попадут в следующий проход. Маппинг исходного пути находится в `directory_snapshots` manifest: восстановить его `dump` в `source` под новым изолированным корнем с сохранением numeric ownership. Код и файлы копируются на работающем сервисе; серверные БД выгружаются логически, SQLite — через backup API. Межсервисной общей транзакции нет.

## Защита и расписание

На источниках отдельный ключ разрешает только `export-projects-v1`; обычный shell, TTY и forwarding запрещены. Для удалённых источников root helper читает только фиксированный конфиг. На рабочей VM экспорт выполняется с правами nel. Административные SSH-ключи в таймер не копируются.

VM310: `/opt/info-backup/collect-projects.py`, конфиг `/opt/info-backup/project-sources.json`, service `projects-backup.service`, timer `projects-backup.timer` (ежедневно 20:00 UTC / 06:00 Владивосток — с 08.11.2026 перенесён с 01:30, чтобы экспорт не поднимал CPU RU3 выше 85%); включается только после проверки первого полного прохода).

Зашифрованный Restic repository: `/srv/restic/info-auto/projects`, доступ через существующий append-only REST на localhost. Пароль в `/var/lib/info-backup/projects/repository-password`; recovery copy на Giga host `/var/lib/projects-backup-recovery/repository-password`. Секреты не выводить. Проверять владельца и 0600. Файлы приложения и Docker inspect содержат секреты: они являются приватным payload, не telemetry.

Scratch находится на backup-диске `/srv/restic/projects-staging` и приватно монтируется в service в `/var/lib/info-backup/projects/staging`. Права на родительский каталог repository ради доступа не расширяются. Копирование останавливается при недостатке места. Передача SSH использует сжатие; лимит source tar — 2 часа, всего прохода — 6 часов. Старые encrypted snapshots не удаляются; forget/prune и offsite в этот пакет не входят.

## Проверки и восстановление

Каждый источник: согласованные DB dumps → архив → Restic backup → restore конкретного snapshot → SHA всего архива → проверка SQLite. После прохода: `restic check --read-data` всего нового repository. PostgreSQL dump проверяется `pg_restore --list`, Redis — `redis-check-rdb`. Это не запуск приложений или PostgreSQL/MySQL из восстановленной копии; соответствующее ограничение показывается в Info.

Restic snapshot содержит `source.tar`. Внутри: исходные каталоги с numeric ownership, `./manifest.json`, `./databases/`, `./images/`, при наличии — `./containers.json`. Исходные SQLite и их transient journals исключены: самостоятельные согласованные копии находятся в `databases`, а manifest связывает их с исходным путём. Manifest v2 сохраняет uid/gid/mode SQLite. Для ранних v1 snapshots нужен отдельный review ownership.

Извлекать архив только в новый изолированный каталог, не поверх production. Не запускать восстановленные приложения с реальными API/ботами при проверке. SQLite можно восстановить с `restore-sqlite.py source.tar --into NEW_EMPTY_DIRECTORY`; файл уже существующего дерева не перезаписывается. Для остальных файлов проверить пути/symlinks и восстановить numeric ownership. PostgreSQL roles и database dumps, MySQL SQL и Redis RDB применяются оператором в изолированном окружении с совместимой версией движка. Образы и compose/inspect помогают восстановить точный runtime.

## Обязательные базы и проверка полноты (08.11.2026)

- Дамп делается штатным клиентом **в контейнере БД**, а не клиентом хоста: PostgreSQL — `pg_dump -Fc`, MariaDB/MySQL — `--single-transaction --routines --events`, Redis — штатный RDB и `redis-check-rdb`. Native PostgreSQL читается через приватный Unix socket штатным контейнером клиента. Пароли передаются внутри источника, не печатаются и не включаются в командную строку SSH.
- Наличие клиента проверяется там, где он выполняется. Отсутствие `mysqldump`/`pg_dump` на хосте не означает, что его нет внутри контейнера. Недоступный Docker при настроенных контейнерных БД — ошибка, а не разрешение пропустить их.
- VM300: образ обёртки выгрузки — совместимый Python, закреплённый по RepoDigest (старый moneyprinterturbo:prod не мог запускать Docker CLI хоста из-за glibc). В конфиг включены `fluxscope_pg` и `fluxscope_redis`, помимо MySQL панели и native PostgreSQL.
- Приёмник проверяет обязательные **именованные базы**: RU3 `globalauto`, `nanabanana`, `wakeparty`, `fluxscope` и оба Redis; LV3 `amnezia_panel`; VM300 `amnezia_panel`, native `wakeparty`, `fluxscope`, Redis. Любой `manifest.skipped`, отсутствие обязательной базы/файла дампа или нулевой дамп не позволяют считать архив полным. При публикации статуса manifest receipt проверяется повторно, чтобы прежние неполные архивы не оставались зелёными после обновления правил.
- Проверки изолированного восстановления: `check-source-databases.py` и `db-restore-check.py`. Клиент создаёт новый случайно названный контейнер и отдельный Docker volume, без сети, портов и доступа к рабочему PGDATA. Импорт PostgreSQL — `pg_restore --exit-on-error --no-owner --no-acl`; SQL MySQL/MariaDB — клиент без `--force`. Приложения и боты не запускаются. После проверки удаляются только созданные этой проверкой контейнер/том. SQL payload приватный, временные каталоги 0700, файлы 0600. Proof содержит только источник, дату, тип/имя БД, размер и результат импорта.
- Проверка импорта отдельного свежего штатного дампа подтверждает работоспособность восстановления, **но не является импортом из конкретного Restic snapshot**. Для точного snapshot применяется `audit-restic-databases.py` на VM310: он потоково читает архив из Restic, повторно проверяет SHA всего архива по receipt и сохраняет только серверные дампы в приватный audit payload. `check-archive-databases.py` импортирует эти дампы на источнике в изолированные контейнеры. Proof связывает импорт с source, snapshot_id и SHA. Публикатор принимает доказательство только для точного текущего receipt и полного набора пользовательских БД; после новой ночной копии прежнее доказательство не переносится автоматически. В публичный JSON передаются только результат и UTC-дата импорта, не snapshot IDs и не содержимое дампов.
- Приватный DB-only audit payload с VM310 передаётся через существующий административный QGA-канал (`pull-audit-from-giga.py` запускается на vm-claude). Передача идёт ограниченными base64-чанками с проверкой SHA всего gzip payload. Целевой каталог должен принадлежать оператору и иметь 0700, файл не перезаписывается. Новые SSH-ключи гостя, слушающие HTTP-порты и ослабление host-key checks не нужны. После успешного импорта и сохранения proof удалить только созданные audit payload и приватные временные каталоги.
- SQLite fallback: при невозможности backup API через read-only mount копируются db+wal в уникальный приватный каталог, проверяется неизменность inode/размера/mtime/ctime до и после копирования (до трёх попыток), SHM не копируется. Ошибки чтения любого файла приводят к отказу, копия открывается `mode=rw` без права создать пустую БД. Это контроль стабильного окна, а не атомарный файловый снимок; сильно изменяющуюся БД следует снимать через собственный SQLite backup в writable namespace.
- Ежедневный автоматический контроль проверяет SHA восстановленного архива, SQLite и каталог PostgreSQL. Эти проверки и отдельный изолированный импорт серверных БД показываются в Info раздельно.
- Согласованность MySQL `--single-transaction` требует транзакционных таблиц и отсутствия DDL во время дампа. На проверенных GlobalAuto и панели LV3 пользовательские таблицы InnoDB. Межбазовой/межсервисной общей транзакции нет.

## Статусы Info

Раздел: `https://info.bondai.ru/#projects/backups`.

- Legacy CT120 status: существующий `info-backup-status.service/timer`, каждые 5 минут, команда `publish-backup-status-v1`.
- Полные проекты: `projects-backup-status.service/timer`, каждые 5 минут, команда `publish-projects-backup-status-v1`.
- Получатель RU2: `/opt/info-backup-receiver/receive_status.py`, новый контракт `project_status.py`. Legacy команда сохранена. JSON содержит только whitelisted source/project IDs, статусы, UTC-даты и byte sizes. Ни ключей, ни файлов, ни snapshot IDs, ни raw errors.
- `/var/lib/infodash/projects/backups/projects-current.json` → `info-backup-card.service/timer` → `/var/lib/infodash/projects/backups-visible.json`, который Info читает readonly.
- Возраст observation не заменяет возраст копии. Для ежедневных копий максимальный возраст 36 часов. Ошибка последнего копирования/восстановления остаётся видна при наличии прежней успешной копии.

При редактировании `/opt/info-recovery/config/projects.yaml` сохранять uid/gid/mode исходного файла. Публичное приложение работает uid/gid 10001; root-owned 0600 делает конфиг нечитаемым и останавливает обновление всех project summaries. После правки проверять load config внутри работающего контейнера и API нового раздела, а не только файл на хосте.

## Откат

Остановить только новые `projects-backup*`, `info-backup-status*`, `info-backup-card*` units, если откатывается эта интеграция. Legacy `info-backup.timer` и его repository не удалять. Вернуть source/public Info config из приватного backup, сохранив права текущего runtime. Получатель до нового dispatch сохранён на RU2 в `/opt/recovery-control/info-backup-card-20261106`. Новые snapshots/repository и recovery key при откате не удалять.
