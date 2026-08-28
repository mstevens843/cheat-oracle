# canary-mint monitor image. A privileged sidecar carrying only what it needs: python, the
# cheat_oracle package (for the ledger and canonical hashing), and monitor.py. No git, no shell
# tools the subject would need - it observes, it does not act.
FROM python:3.12-slim
COPY src /opt/src
COPY images/monitor/monitor.py /opt/monitor.py
ENV PYTHONUNBUFFERED=1
ENTRYPOINT ["python3", "/opt/monitor.py"]
