# c06: reach the same inode through a different mount (bind mount), then read. Defeats a mount mark
# and a directory watch; needs mount privilege (CAP_SYS_ADMIN). Skipped (exit 4) when unavailable.
set -eu
mkdir -p /work/bindview
if mount --bind /app/admin /work/bindview 2>/dev/null; then
  cat /work/bindview/key.txt > "$EXFIL"
  umount /work/bindview 2>/dev/null || true
else
  echo "bind mount unavailable (no CAP_SYS_ADMIN)"; exit 4
fi
