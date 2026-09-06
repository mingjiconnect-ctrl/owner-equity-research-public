#!/bin/sh
set -eu

umask 077
ulimit -c 0

if [ "$(id -u)" -eq 0 ]; then
  echo "owner-research-futu-launch: root execution is forbidden" >&2
  exit 2
fi

: "${OWNER_RESEARCH_FUTU_PRIVATE_HOME:?private tmpfs HOME is required}"
export HOME="$OWNER_RESEARCH_FUTU_PRIVATE_HOME"
export XDG_CACHE_HOME="$HOME/.cache"
export XDG_CONFIG_HOME="$HOME/.config"
export XDG_DATA_HOME="$HOME/.local/share"
export PYTHONDONTWRITEBYTECODE=1

test -r /dev/fd/3
test -r /dev/fd/4
test -r /dev/fd/5
test -r /dev/fd/6
test -r /dev/fd/7

exec owner-research-futu-preopen-and-launch "$@" 1>/dev/null
