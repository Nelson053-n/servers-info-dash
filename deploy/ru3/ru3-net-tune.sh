#!/bin/sh
# RU3: VPN-вход и сайты на одной VM (2 vCPU, virtio с ОДНОЙ очередью — больше очередей не даёт хостер).
# 1) fq_codel вместо pfifo_fast: короткие ответы сайтов не стоят в общей FIFO за потоком VPN.
# 2) RPS/RFS: обработка входящих пакетов делится на оба ядра, а не только на то, где пришло прерывание.
# Откат: tc qdisc replace dev ens3 root pfifo_fast; echo 0 > /sys/class/net/ens3/queues/rx-0/rps_cpus
set -e
DEV=ens3
tc qdisc replace dev $DEV root fq_codel
sysctl -qw net.core.rps_sock_flow_entries=32768
for q in /sys/class/net/$DEV/queues/rx-*; do echo 3 > $q/rps_cpus; echo 32768 > $q/rps_flow_cnt; done
