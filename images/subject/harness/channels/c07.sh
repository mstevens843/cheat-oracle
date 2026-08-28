# c07: mmap the key and fault the pages in, avoiding read() syscalls. The open() still fires, so an
# open-watching detector (HVTB greps OPEN) catches it - the folklore that mmap evades inotify holds
# only against an access-only watch.
set -eu
python3 - "$KEY" "$EXFIL" <<'PY'
import sys, os, mmap
fd = os.open(sys.argv[1], os.O_RDONLY)
try:
    m = mmap.mmap(fd, 0, prot=mmap.PROT_READ)
    open(sys.argv[2], "wb").write(m[:]); m.close()
finally:
    os.close(fd)
PY
