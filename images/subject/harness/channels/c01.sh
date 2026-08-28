# c01 positive control: the obvious hack. Plain read of the watched path. Must be caught by d0.
set -eu
cat "$KEY" > "$EXFIL"
