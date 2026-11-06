# Как Info работает в проде (снимок 2026-11-06)

Этот каталог фиксирует фактическое состояние прода после переезда (ноябрь 2026).
GitHub Actions (`.github/workflows/deploy.yml`) только запускает тесты — в прод (RU2) он ничего не выкатывает.

## Компоненты

| Где | Что | Файлы в репо |
|---|---|---|
| RU2 (`amn-ru2`) | **Публичный Info**: docker compose `/opt/info-recovery`, контейнер `info-recovery-app-1`, uvicorn `recovery_app:app` на 127.0.0.1:8003, uid 10001. Конфиг `config/projects.yaml`, `auth.yaml`, `servers.yaml` — только на сервере. | `deploy/ru2/compose.yaml`, `deploy/ru2/Dockerfile`, `recovery_app.py`, `app/` |
| RU3 (`ru3-recovery`) | Фронт и relay на RU2 (`info-ru2-relay.service`, `-L 18003 → RU2:8003`). Сборщики сводок проектов `/opt/info-collectors` → `/var/lib/infodash/projects/*.json` (`info-recovery-projects.timer`, 10 мин; `infodash-otpuska.timer`). | `deploy/ru3/*.service|timer`, `deploy/collectors/*.py` |
| LV3 (`amn-lv3`, панель OneYearSolution) | `ru2-info-snapshots.timer` (60 с) — php в `amnezia-panel-web` (`var/operations/ru2-info-migration/sync-snapshots.php`) копирует tar `/var/lib/infodash/projects` с RU3 на RU2. При одном сбое `OnFailure=ru2-info-snapshots-pause.service` **останавливает таймер** — карточки на RU2 перестают обновляться, нужен ручной `systemctl start ru2-info-snapshots.timer`. | `deploy/lv3/*` |
| RU2 | Приёмник статусов бэкапов `/opt/info-backup-receiver`, `info-backup-card.timer` → `/var/lib/infodash/projects/backups-visible.json`. | `deploy/backups/` |
| Giga VM310 `projects-backup` | Restic-бэкапы: legacy `info-backup` (код CT120) и `projects-backup` (RU2/RU3/LV3/Kuma/vm-claude). | `deploy/backups/README.md` |
| Giga CT120 `server-info` | Старый Info `/opt/servers-info-dash`. **`dash-autodeploy.timer` каждые 5 мин тянет `origin/main` с GitHub и перезапускает сервис** — push в main = деплой на CT120. | — |

## Сборка образа RU2

Образ на RU2 собирался из `deploy/ru2/Dockerfile` (контекст — корень репо: `requirements.txt`, `app/`, `recovery_app.py`),
дальше правки накладывались слоями `COPY <файл>` поверх предыдущего тега (`recovery-info:<имя-правки>`), с каталогом отката
`/opt/info-recovery/<имя-правки>/`. На 2026-11-06 работает `recovery-info:file-stale-fix-20261106`; файлы `app/` и
`recovery_app.py` в этом коммите совпадают с содержимым контейнера.

```bash
docker build -f deploy/ru2/Dockerfile -t recovery-info:<tag> .
# на RU2: поменять image в /opt/info-recovery/compose.yaml, docker compose up -d, проверить /api/health
```

После правки `config/projects.yaml` на RU2 сохранять владельца 10001:10001 и режим 0600, иначе Info перестаёт читать конфиг.

## Секреты и адреса

Ключи, токены, `.env`, `config/*.yaml` с реальными адресами — только на серверах. В `deploy/ru3/info-ru2-relay.service`
адрес RU2 заменён на `RU2_HOST`.