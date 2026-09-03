FROM python:3.13.15-slim-bookworm@sha256:00faa2debb87529f9f0764e9491d8ba400a3678976616c3bd7cb193745ac20d1

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    DATA_DIR=/data \
    PORT=8000

WORKDIR /app

# The project pins exact dependency versions in pyproject.toml; installing the package
# itself keeps one source of truth for them.
COPY pyproject.toml LICENSE ./
COPY src ./src
RUN python -m pip install --no-cache-dir --upgrade 'pip>=26.1' && python -m pip install --no-cache-dir .

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD ["python", "-c", "import os,urllib.request; urllib.request.urlopen('http://127.0.0.1:'+os.getenv('PORT','8000')+'/healthz',timeout=4).read()"]

CMD ["python", "-m", "steepd"]
