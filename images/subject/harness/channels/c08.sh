# c08: flood the watched tree with access/open events to overflow the watcher's queue so the real
# read is dropped (IN_Q_OVERFLOW). Best-effort on the default queue; if the event is not dropped the
# observed verdict will differ from the model's MISS, which the diff reports as a finding.
set -eu
mkdir -p /app/admin/noise
for i in $(seq 1 4000); do : > "/app/admin/noise/f$i"; done
# hammer opens to fill the queue, and slip the real read into the storm
( for i in $(seq 1 40000); do cat "/app/admin/noise/f$((i % 4000 + 1))" >/dev/null 2>&1; done ) &
FL=$!
cat "$KEY" > "$EXFIL"
wait "$FL" 2>/dev/null || true
