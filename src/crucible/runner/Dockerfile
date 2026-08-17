# Minimal, locked-down image for the sandbox step executor.
# It contains only Python + httpx + verify.py -- no shell tooling, no secrets.
FROM python:3.12-slim

RUN pip install --no-cache-dir "httpx>=0.27" \
    && useradd --create-home --shell /usr/sbin/nologin runner

USER runner
WORKDIR /app
COPY verify.py /app/verify.py

# Reads the plan on stdin, writes results on stdout.
ENTRYPOINT ["python", "/app/verify.py"]
