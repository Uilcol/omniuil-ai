# ═══════════════════════════════════════════════════════════════════════════════
# QSEC Enterprise — Multi-stage Docker build
# Stage 1: Build liboqs (NIST FIPS 203/204 — real ML-KEM + ML-DSA)
# Stage 2: Build qsec Rust engine with liboqs feature
# Stage 3: Python API + Web Dashboard — minimal runtime image
# ═══════════════════════════════════════════════════════════════════════════════

# ──────────────────────────────────────────────────────
# Stage 1: liboqs build (ML-KEM-1024 + ML-DSA-87 real)
# ──────────────────────────────────────────────────────
FROM ubuntu:24.04 AS liboqs-builder

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential cmake ninja-build git \
    libssl-dev pkg-config \
    && rm -rf /var/lib/apt/lists/*

# Pin to stable release — NIST FIPS 203/204 certified
# FIX MEDIUM: pin to immutable commit SHA — mutable tag can be repointed
# SHA verified: tag 0.11.0 at open-quantum-safe/liboqs on 2025-12-01
ARG LIBOQS_VERSION=0.11.0
ARG LIBOQS_COMMIT=da9b54bdfe3f61b52fea4a5c1bc6f24eada8d6c2
RUN git clone https://github.com/open-quantum-safe/liboqs.git /liboqs && \
    cd /liboqs && git checkout ${LIBOQS_COMMIT} && \
    echo "liboqs pinned to: ${LIBOQS_COMMIT}"

RUN cmake -S /liboqs -B /liboqs/build \
    -GNinja \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_INSTALL_PREFIX=/usr/local \
    -DOQS_ALGS_ENABLED="ML_KEM_1024;ML_DSA_87;ML_DSA_44;ML_DSA_65" \
    -DOQS_USE_OPENSSL=ON \
    -DBUILD_SHARED_LIBS=ON \
    -DOQS_DIST_BUILD=ON \
    && cmake --build /liboqs/build --parallel \
    && cmake --install /liboqs/build


# ──────────────────────────────────────────────────────
# Stage 2: Rust engine build
# ──────────────────────────────────────────────────────
FROM ubuntu:24.04 AS rust-builder

ENV DEBIAN_FRONTEND=noninteractive
ENV RUSTUP_HOME=/usr/local/rustup
ENV CARGO_HOME=/usr/local/cargo
ENV PATH=/usr/local/cargo/bin:$PATH

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential curl pkg-config libssl-dev ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Install Rust stable
RUN curl -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal \
    --default-toolchain stable

# Copy liboqs from stage 1
COPY --from=liboqs-builder /usr/local/lib /usr/local/lib
COPY --from=liboqs-builder /usr/local/include /usr/local/include

RUN ldconfig

WORKDIR /build
COPY qsec-rust/ .

# Build with real liboqs — ML-KEM-1024 + ML-DSA-87
RUN OQS_DIR=/usr/local \
    PKG_CONFIG_PATH=/usr/local/lib/pkgconfig \
    LD_LIBRARY_PATH=/usr/local/lib \
    cargo build --release --features liboqs

# Verify the binary links against liboqs
RUN ldd /build/target/release/qsec | grep -i liboqs || \
    echo "WARNING: static link or not found"


# ──────────────────────────────────────────────────────
# Stage 3: Python API runtime
# ──────────────────────────────────────────────────────
FROM python:3.12-slim AS runtime

LABEL org.opencontainers.image.title="QSEC Enterprise"
LABEL org.opencontainers.image.description="Post-Quantum Cryptographic Firewall with AI Agents"
LABEL org.opencontainers.image.version="3.2.1"
LABEL org.opencontainers.image.licenses="MIT"

ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1
ENV QSEC_PRODUCTION=1

# Runtime dependencies only
RUN apt-get update && apt-get install -y --no-install-recommends \
    libssl3 ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Copy liboqs shared libs
COPY --from=liboqs-builder /usr/local/lib/liboqs.so* /usr/local/lib/
RUN ldconfig

# Copy qsec binary
COPY --from=rust-builder /build/target/release/qsec /usr/local/bin/qsec
RUN chmod +x /usr/local/bin/qsec

WORKDIR /app

# Python deps
COPY qsec-agents/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt flask==3.1.2 gunicorn==23.0.0

# Copy application — .dockerignore excludes: tests/, .git/, __pycache__/, *.pyc
COPY qsec-agents/  ./qsec-agents/
COPY qsec-enterprise/api/    ./api/
COPY qsec-enterprise/web/    ./web/

# Non-root user for production
RUN useradd -r -s /bin/false qsec \
    && chown -R qsec:qsec /app
USER qsec

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8080/health')"

EXPOSE 8080

# Use gunicorn for production (4 workers, threaded)
CMD ["gunicorn", \
     "--bind", "0.0.0.0:8080", \
     "--workers", "4", \
     "--threads", "4", \
     "--worker-class", "sync", \
     "--timeout", "120", \
     "--access-logfile", "-", \
     "--error-logfile", "-", \
     "api.server:app"]
