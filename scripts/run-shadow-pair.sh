#!/bin/bash
# Run both individual gateway daemons within the pair service's private state directory.
set -euo pipefail
umask 077

state=${STATE_DIRECTORY:?Shadow Mode requires a private StateDirectory}
credentials=${CREDENTIALS_DIRECTORY:?Shadow Mode requires systemd credentials}
if [[ $state != /* || $credentials != /* || $state == *:* || ! -d $state || ! -d $credentials ]]; then
    echo "Shadow Mode requires one absolute state directory and one credential directory" >&2
    exit 1
fi

for role in primary standby; do
    if [[ -L $state/$role || -L $state/$role/gateway.conf || -L $state/$role/firewall.json || -L $state/$role/firewall.lock ]]; then
        echo "Shadow Mode state and journal paths must not be symlinks" >&2
        exit 1
    fi
    for name in site.conf vyos-ca.pem vyos-api-key shadow-ssh-key shadow-ssh-known-hosts shadow-receipt-ssh-key \
        restart-ssh-key restart-ssh-known-hosts; do
        if [[ ! -r $credentials/${role}_$name ]]; then
            echo "Missing Shadow Mode credential ${role}_$name" >&2
            exit 1
        fi
    done
    mkdir -p -m 0700 -- "$state/$role"
done

roles=(standby primary)
run_worker() {
    local role=$1
    shift
    UNIFI_GW_CONFIG="$state/$role/gateway.conf" \
    UNIFI_GW_UNHANDLED_LOG="$state/$role/unhandled_commands.json" \
    UNIFI_GW_SITE_CONFIG="$credentials/${role}_site.conf" \
    UNIFI_GW_SHADOW_CREDENTIAL_PREFIX="${role}_" \
        exec /usr/bin/unifi-gateway "$@"
}

/usr/bin/unifi-gateway check-shadow-pair-enrollment

pids=()
# Leave time for systemd's final cgroup cleanup before TimeoutStopSec.
shutdown_grace_seconds=60
shutdown() {
    trap '' TERM INT
    local pid index deadline=$((SECONDS + shutdown_grace_seconds))
    for pid in "${pids[@]}"; do
        kill -TERM "$pid" 2>/dev/null || true
    done
    for index in "${!pids[@]}"; do
        pid=${pids[index]}
        while kill -0 "$pid" 2>/dev/null && (( SECONDS < deadline )); do
            sleep 0.1
        done
        if kill -0 "$pid" 2>/dev/null; then
            echo "Shadow Mode ${roles[index]} worker did not stop within ${shutdown_grace_seconds}s. Sending SIGKILL." >&2
            kill -KILL "$pid" 2>/dev/null || true
        else
            wait "$pid" || true
        fi
    done
}
trap 'shutdown; exit 0' TERM INT

for role in "${roles[@]}"; do
    run_worker "$role" run &
    pids+=("$!")
done

while :; do
    for index in "${!pids[@]}"; do
        pid=${pids[index]}
        if ! kill -0 "$pid" 2>/dev/null; then
            result=0
            wait "$pid" || result=$?
            echo "Shadow Mode ${roles[index]} worker exited unexpectedly with status $result" >&2
            shutdown
            if [[ $result == 0 ]]; then
                exit 1
            fi
            exit "$result"
        fi
    done
    sleep 1
done
