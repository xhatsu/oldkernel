#!/bin/sh
# Hard runtime safety boundary for the legacy agent process tree.
# CPU affinity and all limits are inherited by every thread and child.
set -u

CPU_CORE=${1:-}
[ $# -gt 0 ] && shift

case "$CPU_CORE" in
    ''|*[!0-9]*)
        echo "nt-resource-guard: invalid CPU core: $CPU_CORE" >&2
        exit 70
        ;;
esac
[ $# -gt 0 ] || {
    echo "nt-resource-guard: command required" >&2
    exit 70
}
command -v taskset >/dev/null 2>&1 || {
    echo "nt-resource-guard: taskset is required" >&2
    exit 70
}
command -v chrt >/dev/null 2>&1 || {
    echo "nt-resource-guard: chrt is required" >&2
    exit 70
}

# 256 MiB address space, 8 MiB stack, 64 KiB locked memory, 1,024 descriptors,
# 32 MiB per regular output file, and no core dumps. The process limit exists
# in bash on EL6, but not every POSIX shell, so apply it when supported.
ulimit -S -c 0 && ulimit -H -c 0 || exit 70
ulimit -S -f 65536 && ulimit -H -f 65536 || exit 70
ulimit -S -n 1024 && ulimit -H -n 1024 || exit 70
ulimit -S -v 262144 && ulimit -H -v 262144 || exit 70
ulimit -S -s 8192 && ulimit -H -s 8192 || exit 70
ulimit -S -l 64 && ulimit -H -l 64 || exit 70
if (ulimit -u >/dev/null 2>&1); then
    ulimit -S -u 64 && ulimit -H -u 64 || exit 70
fi

# SCHED_IDLE is below every normal SCHED_OTHER task; nice 19 remains an
# additional inherited safeguard. Affinity confines the full descendant tree.
exec taskset -c "$CPU_CORE" chrt -i 0 nice -n 19 "$@"
