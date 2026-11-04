# CAWASMA backend image (api + worker).
# Build context is ./backend. Includes WeasyPrint's native dependencies
# (cairo/pango/gdk-pixbuf) so PDF report generation works out of the box.
# Pinned by tag and digest, like every other input of the build: a clean machine
# builds what CI tested (constraints.txt pins every Python package).
FROM python:3.12.16-slim-trixie@sha256:b18b261e1b4974b4f321451ad5251ded85abb22c2b8b262da527dda1d031ab30

# INSTALL_ML=false skips torch/sentence-transformers/spaCy (~1 GB, slow build);
# the endpoint classifier then runs keyword-only. INSTALL_DEV adds test/lint tools.
ARG INSTALL_ML=true
ARG INSTALL_DEV=false

# HF_HOME: model cache outside /root so the non-root runtime user can read it.
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    HF_HOME=/opt/hf-cache \
    HF_HUB_OFFLINE=1 \
    TRANSFORMERS_OFFLINE=1 \
    PYTHONPATH=/app

# System libraries:
#  - build-essential/libpq-dev: psycopg2 build
#  - libcairo2, libpango*, libgdk-pixbuf*, libffi: WeasyPrint rendering
#  - fonts-dejavu-core: baseline fonts for PDF output
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libpq-dev \
    libcairo2 \
    libpango-1.0-0 \
    libpangocairo-1.0-0 \
    libgdk-pixbuf-2.0-0 \
    libffi-dev \
    shared-mime-info \
    fonts-dejavu-core \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
RUN mkdir -p /opt/hf-cache

# Install dependencies from pyproject.toml before copying the source, against a
# placeholder package, so code edits don't invalidate this layer.
COPY pyproject.toml constraints.txt ./
RUN mkdir app && touch app/__init__.py \
    && pip install pip==26.2.1 \
    && if [ "$INSTALL_DEV" = "true" ]; then pip install -c constraints.txt ".[dev]"; \
       else pip install -c constraints.txt .; fi \
    && pip uninstall -y cawasma-backend && rm -rf app build *.egg-info

# NLP stack (CPU-only torch, sentence-transformers, spaCy). The models are
# downloaded at build time (the one step allowed online); at run time
# HF_HUB_OFFLINE=1 so loading never waits on huggingface.co (eval network: ~190 s).
COPY requirements-ml.txt .
RUN if [ "$INSTALL_ML" = "true" ]; then \
        pip install -c constraints.txt -r requirements-ml.txt \
        && HF_HUB_OFFLINE=0 TRANSFORMERS_OFFLINE=0 python -c "from sentence_transformers import SentenceTransformer; SentenceTransformer('all-MiniLM-L6-v2')"; \
    fi

COPY . .

# /certs: mount point for the demo CA (docker-compose.demo.yml), writable by the
# runtime user so a fresh named volume inherits that ownership.
RUN useradd --create-home --uid 1000 cawasma \
    && mkdir -p /certs && chown cawasma /certs \
    && chown -R cawasma /app /opt/hf-cache
USER cawasma

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
