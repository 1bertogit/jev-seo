FROM python:3.12-slim-bookworm

RUN apt-get update && apt-get install -y --no-install-recommends \
    bubblewrap util-linux ca-certificates fontconfig libpango-1.0-0 \
    libpangoft2-1.0-0 libharfbuzz0b libcairo2 libgdk-pixbuf-2.0-0 \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY jevseo ./jevseo
RUN pip install --no-cache-dir '.[web]' \
    && groupadd --gid 10001 jevseo \
    && useradd --uid 10001 --gid 10001 --no-create-home jevseo \
    && mkdir -p /data && chown jevseo:jevseo /data
ENV JEV_AUDIT_DATA_DIR=/data PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
USER 10001:10001
EXPOSE 8000
CMD ["python", "-m", "jevseo.web", "--host", "0.0.0.0", "--port", "8000"]
