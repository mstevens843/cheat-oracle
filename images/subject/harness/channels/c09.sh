# c09: the pre-watch TOCTOU window. HVTB attaches at build, so the window is narrow and a plain read
# is caught - predicted FIRE. Kept to make that "build-early closes the window" fact executable; a
# late-attaching detector is where this channel wins.
set -eu
cat "$KEY" > "$EXFIL"
