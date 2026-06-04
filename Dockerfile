FROM ubuntu:24.04 AS build

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    ca-certificates \
    libnghttp2-dev \
    libngtcp2-dev \
    libngtcp2-crypto-ossl-dev \
    libssl-dev \
    make \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY . .
RUN make clean && make

FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    libnghttp2-dev \
    libngtcp2-dev \
    libngtcp2-crypto-ossl-dev \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system rpsiod \
    && useradd --system --gid rpsiod --no-create-home --home-dir /var/lib/rpsiod --shell /usr/sbin/nologin rpsiod \
    && install -d -m 0755 /etc/rpsiod /usr/share/rpsiod/config /usr/share/rpsiod/www /usr/share/rpsiod/errors \
    && install -d -m 0750 /var/log/rpsiod /var/cache/rpsiod /run/rpsiod \
    && install -d -m 0700 /var/lib/rpsiod/ssl \
    && install -d -m 0755 /var/www/rpsiod-example /var/www/rpsiod-errors

COPY --from=build /src/build/rpsiod /usr/local/sbin/rpsiod
COPY config/server.yml /usr/share/rpsiod/config/server.yml
COPY config/sites.yml /usr/share/rpsiod/config/sites.yml
COPY docker/entrypoint.sh /usr/local/bin/rpsiod-docker-entrypoint
COPY docker/www/ /usr/share/rpsiod/www/
COPY www/rpsiod-errors/ /usr/share/rpsiod/errors/

RUN chmod 0755 /usr/local/sbin/rpsiod /usr/local/bin/rpsiod-docker-entrypoint

EXPOSE 80 443 9191

ENTRYPOINT ["/usr/local/bin/rpsiod-docker-entrypoint"]
CMD ["rpsiod", "serve", "--server", "/etc/rpsiod/server.yml", "--sites", "/etc/rpsiod/sites.yml"]
