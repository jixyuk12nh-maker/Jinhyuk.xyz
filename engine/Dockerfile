FROM python:3.11-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 ENGINE_ROOT=/opt/luraph-repo/Deobfuscator/deobf
RUN apt-get update && apt-get install -y --no-install-recommends git ca-certificates build-essential cmake ninja-build clang && rm -rf /var/lib/apt/lists/*
WORKDIR /opt
# Review and pin a commit before production. This repository claims support for v14.7/14.8/14.9/v15.
RUN git clone --depth 1 https://github.com/larpcorrupt/luraph-v15-v14.x-deobfuscator.git /opt/luraph-repo
# The repository may ship Windows Luau binaries. Build/install Linux-compatible tools per upstream docs if needed.
RUN test -f /opt/luraph-repo/Deobfuscator/deobf/cli.py && test -f /opt/luraph-repo/Deobfuscator/deobf/deob.py
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY main.py .
RUN useradd --create-home --uid 10001 appuser && chown -R appuser:appuser /app
USER appuser
EXPOSE 8080
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8080", "--workers", "1"]
