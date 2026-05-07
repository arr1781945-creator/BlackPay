# ─── BlackPay Django Application Dockerfile ───────────────────────────────────
# Multi-stage: crypto builder → slim Django runtime

# Stage 1: Build C++ crypto module
FROM ubuntu:24.04 AS crypto_builder

ARG DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y \
    build-essential cmake ninja-build git \
    libssl-dev python3-dev python3-pip \
    && rm -rf /var/lib/apt/lists/*

RUN pip3 install pybind11 --break-system-packages

WORKDIR /deps
RUN git clone --depth 1 --branch 0.15.0 https://github.com/open-quantum-safe/liboqs.git
WORKDIR /deps/liboqs/build
RUN cmake .. -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=OFF \
    -DOQS_BUILD_ONLY_LIB=ON -GNinja && ninja -j$(nproc) && ninja install

COPY crypto_engine/ /src/crypto_engine/
WORKDIR /src/crypto_engine/build
RUN cmake .. -DCMAKE_BUILD_TYPE=Release \
    -Dpybind11_DIR=$(python3 -c "import pybind11; print(pybind11.get_cmake_dir())") \
    -GNinja && ninja -j$(nproc)

# Stage 2: Django runtime
FROM python:3.12-slim-bookworm

ARG DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y \
    libpq-dev libssl3 curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy crypto module
COPY --from=crypto_builder /src/crypto_engine/build/blackpay_crypto*.so /usr/local/lib/python3.12/

# Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Application code
COPY . .

# Collect static files
RUN python manage.py collectstatic --noinput || true

# Non-root user for security
RUN useradd -m -u 1000 blackpay && chown -R blackpay:blackpay /app
USER blackpay

EXPOSE 8000

CMD ["gunicorn", "blackpay.wsgi:application", \
     "--bind", "0.0.0.0:8000", \
     "--workers", "4", \
     "--worker-class", "gthread", \
     "--threads", "2", \
     "--timeout", "120", \
     "--access-logfile", "-", \
     "--error-logfile", "-"]
