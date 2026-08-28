# The c13 honest-floor image: enough to build a loop-backed ext4 filesystem and mark its superblock
# with fanotify, so a raw block-device read below the VFS can be shown to evade the mark. Runs
# --privileged (loop device + mount). See images/floor/floor_probe.py.
FROM debian:stable-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
      util-linux e2fsprogs mount python3 \
    && rm -rf /var/lib/apt/lists/*
COPY floor_probe.py /opt/floor_probe.py
ENTRYPOINT ["python3", "/opt/floor_probe.py"]
