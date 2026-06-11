FROM python:3.12-slim

LABEL maintainer="Ratspeak <ratspeak.org>"
LABEL description="Rathole Security Suite for Reticulum"

WORKDIR /app

COPY . .

RUN pip install --no-cache-dir -e ".[all]" && \
    useradd -r -m -d /home/rathole -s /bin/false rathole && \
    mkdir -p /var/lib/rathole /var/run /home/rathole/.reticulum && \
    chown -R rathole:rathole /var/lib/rathole /var/run /home/rathole

USER rathole

EXPOSE 9777

ENTRYPOINT ["rathole"]
CMD ["--config", "/etc/rathole/rathole.toml", "--headless"]
