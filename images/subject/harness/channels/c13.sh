# c13: the honest floor. Read the filesystem bytes from the backing block device, below the VFS, so
# no path/inode/mount/superblock watch fires - canary-mint included. Needs device access a sandbox
# normally denies; implemented against a loopback device in the privileged monitor phase. Here it
# reports skipped so the floor is never silently claimed as measured.
set -eu
echo "c13 requires device access; run under the privileged floor harness"; exit 5
