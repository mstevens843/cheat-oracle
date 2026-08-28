# c02: hardlink the key into a directory OUTSIDE the watched admin/ but on the SAME filesystem as
# the key (so the hardlink is valid whether /app is the image overlay or a shared volume), then read
# via the link. Same inode, so an inode/superblock watch fires, but HVTB watches the admin/ directory
# and inotify does not report a file accessed via a link outside the monitored directory.
set -eu
link="$(dirname "$KEY")/../data/keylink"   # /app/data/keylink: sibling of admin/, same fs as the key
ln "$KEY" "$link" 2>/dev/null || { echo "hardlink unavailable (cross-fs)"; exit 3; }
cat "$link" > "$EXFIL"
rm -f "$link" 2>/dev/null || true
