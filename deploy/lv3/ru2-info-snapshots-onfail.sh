#!/bin/sh
# Раньше таймер останавливался после ОДНОГО сбоя — разовый сетевой таймаут замораживал сводки Info на часы.
# Теперь: считаем сбои подряд; таймер останавливается только после 5 (защита от долбёжки при сломанном доступе).
F=/var/lib/ru2-info-snapshots/failures
n=$(( $(cat $F 2>/dev/null || echo 0) + 1 )); echo $n > $F
if [ $n -ge 5 ]; then
  echo "ru2-info-snapshots: $n failures in a row — pausing timer until operator review"
  systemctl stop ru2-info-snapshots.timer
else
  echo "ru2-info-snapshots: failure $n of 5 in a row — timer keeps running"
fi
