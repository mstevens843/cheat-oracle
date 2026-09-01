# canary-mint monitor image. A privileged sidecar carrying only what it needs: python, the
# cheat_oracle package (for the ledger and canonical hashing), and monitor.py. No git, no shell
# tools the subject would need - it observes, it does not act.
FROM python:3.12.13-slim-bookworm@sha256:4766d8b510c428e595d74b9cc5bbb2fae8e26316fffb4adc89908d79aacd58a2
COPY src /opt/src
COPY images/monitor/monitor.py /opt/monitor.py
ENV PYTHONUNBUFFERED=1
ENTRYPOINT ["python3", "/opt/monitor.py"]
