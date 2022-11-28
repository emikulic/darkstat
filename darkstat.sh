#!/bin/bash

DATA_DIR="/tmp/data"
if ! test -d "$DATA_DIR"; then
  mkdir "$DATA_DIR"
  chown nobody.nogroup "$DATA_DIR"
fi

# "main" interface:
i="eth0"
./darkstat -i eth0 \
  --syslog \
  --chroot "$DATA_DIR" \
  --export darkstat-"$(hostname)-$i".db \
  --import darkstat-"$(hostname)-$i".db \
  --daylog darkstat-"$(hostname)-$i".db.daylog \
  --user nobody \
  -p 16670
# default: 667

# docker interfaces:
port=16670
for i in $(ip a | grep -v dynamic | grep -E "172" | sort | awk '{print $7}'); do
  port=$((port+1))
  ./darkstat -i "$i" \
    --syslog \
    --chroot "$DATA_DIR" \
    --export darkstat-"$(hostname)-$i".db \
    --import darkstat-"$(hostname)-$i".db \
    --daylog darkstat-"$(hostname)-$i".db.daylog \
    --user nobody \
    -p "$port"
done

