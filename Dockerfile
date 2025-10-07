# Build stage - contains all build dependencies
FROM debian:bookworm-slim AS builder
ARG version
ARG DEBIAN_FRONTEND=noninteractive

# Install build dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    make cmake git curl build-essential m4 \
    libreadline-dev bison flex zlib1g-dev \
    libicu-dev pkg-config ca-certificates \
    perl cpanminus && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Build PostgreSQL
RUN curl -s -L https://ftp.postgresql.org/pub/source/v${version}/postgresql-${version}.tar.gz | tar zxf - && \
    cd postgresql-${version} && \
    ./configure --prefix=/usr/local/pgsql CFLAGS="-O3" && \
    make -j$(nproc) && \
    make install && \
    cd .. && rm -rf postgresql-${version}

# Build libsodium
RUN curl -s -L https://github.com/jedisct1/libsodium/releases/download/1.0.20-RELEASE/libsodium-1.0.20.tar.gz | tar zxf - && \
    cd libsodium-1.0.20 && \
    ./configure --prefix=/usr/local && \
    make -j$(nproc) && \
    make install && \
    cd .. && rm -rf libsodium-1.0.20

# Build pgTAP (for testing)
RUN curl -s -L https://github.com/theory/pgtap/archive/v1.2.0.tar.gz | tar zxf - && \
    cd pgtap-1.2.0 && \
    PATH=/usr/local/pgsql/bin:$PATH make && \
    PATH=/usr/local/pgsql/bin:$PATH make install && \
    cd .. && rm -rf pgtap-1.2.0

# Build pgddl
RUN git clone --depth 1 https://github.com/lacanoid/pgddl.git && \
    cd pgddl && \
    PATH=/usr/local/pgsql/bin:$PATH make && \
    PATH=/usr/local/pgsql/bin:$PATH make install && \
    cd .. && rm -rf pgddl

# Build pgsodium
COPY . /build/pgsodium
RUN cd pgsodium && \
    PATH=/usr/local/pgsql/bin:$PATH make -j$(nproc) && \
    PATH=/usr/local/pgsql/bin:$PATH make install

# Install Perl test dependencies
RUN cpanm --notest TAP::Parser::SourceHandler::pgTAP

# Runtime stage - minimal dependencies
FROM debian:bookworm-slim
ARG DEBIAN_FRONTEND=noninteractive

# Install only runtime dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    libreadline8 zlib1g libicu72 ca-certificates \
    perl sudo locales && \
    rm -rf /var/lib/apt/lists/* && \
    echo "en_US.UTF-8 UTF-8" > /etc/locale.gen && \
    locale-gen

ENV LANG=en_US.UTF-8 \
    LC_ALL=en_US.UTF-8 \
    PATH=/usr/local/pgsql/bin:/usr/local/bin:$PATH \
    PGDATA=/home/postgres/data

# Copy PostgreSQL and extensions from builder
COPY --from=builder /usr/local/pgsql /usr/local/pgsql
COPY --from=builder /usr/local/lib/libsodium* /usr/local/lib/
COPY --from=builder /usr/local/include/sodium* /usr/local/include/
COPY --from=builder /usr/local/share/perl /usr/local/share/perl
COPY --from=builder /usr/local/lib/x86_64-linux-gnu/perl /usr/local/lib/x86_64-linux-gnu/perl
COPY --from=builder /usr/local/bin/pg_prove /usr/local/bin/

# Create postgres user
RUN groupadd -r postgres && \
    useradd --no-log-init -r -m -s /bin/bash -g postgres -G sudo postgres && \
    echo "postgres ALL=(root) NOPASSWD:ALL" > /etc/sudoers.d/postgres && \
    chmod 0440 /etc/sudoers.d/postgres

# Setup getkey script
RUN mkdir -p /usr/local/pgsql/share/extension && \
    cp /usr/local/pgsql/share/extension/pgsodium_getkey_urandom.sh \
       /usr/local/pgsql/share/extension/pgsodium_getkey 2>/dev/null || true
COPY --from=builder /build/pgsodium/getkey_scripts/pgsodium_getkey_urandom.sh \
     /usr/local/pgsql/share/extension/pgsodium_getkey
RUN sed -i 's/exit//g' /usr/local/pgsql/share/extension/pgsodium_getkey && \
    chmod +x /usr/local/pgsql/share/extension/pgsodium_getkey && \
    cp /usr/local/pgsql/share/extension/pgsodium_getkey /getkey

# Update library cache
RUN ldconfig

# Initialize database as postgres user
USER postgres
WORKDIR /home/postgres
RUN mkdir -p "$PGDATA" && \
    initdb -D "$PGDATA"

EXPOSE 5432
CMD ["postgres", "-D", "/home/postgres/data"]
