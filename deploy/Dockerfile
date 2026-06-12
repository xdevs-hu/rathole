# --- Stage 1: Build & Wheel Generation ---
# Using the native target platform to build wheels natively
FROM python:3.12-slim AS builder

WORKDIR /build
COPY . .

# We build wheels natively using buildx's QEMU emulation
RUN pip install --no-cache-dir wheel && \
    pip wheel --no-cache-dir --wheel-dir /build/wheels ".[all]"

# --- Stage 2: Clean Final Runtime ---
FROM python:3.12-slim

LABEL maintainer="Ratspeak <ratspeak.org>"
LABEL description="Rathole Security Suite for Reticulum"

WORKDIR /app

# Copy only the pre-compiled packages from Stage 1
COPY --from=builder /build/wheels /wheels

# Install the matching architecture wheels cleanly
RUN pip install --no-cache-dir /wheels/* && \
    rm -rf /wheels && \
    useradd -r -m -d /home/rathole -s /bin/false rathole && \
    mkdir -p /var/lib/rathole /var/run /home/rathole/.reticulum /etc/rathole && \
    chown -R rathole:rathole /var/lib/rathole /var/run /home/rathole /etc/rathole

USER rathole
EXPOSE 9777

ENTRYPOINT ["rathole"]
CMD ["--config", "/etc/rathole/rathole.toml", "--headless"]
