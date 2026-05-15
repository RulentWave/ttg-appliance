#!/bin/sh
set -e

PATCHER=/opt/NinjaRMMAgent/programfiles/ninjarmm-linagent-patcher

# Background loop replacing ninjarmm-patcher.timer (5 min interval)
(
	while true; do
		sleep 300
		if [ -x "$PATCHER" ]; then
			DAEMON_RUN=1 "$PATCHER" >/dev/null 2>&1 || true
		fi
	done
) &

exec env DAEMON_RUN=1 LC_ALL=C \
	/opt/NinjaRMMAgent/programfiles/ninjarmm-linagent
