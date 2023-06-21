FROM ubuntu:latest
ARG version
ARG DEBIAN_FRONTEND=noninteractive

# install base dependences
RUN apt-get -qq update && \
    apt-get -qq install -y make cmake git curl build-essential m4 sudo gdbserver \
    gdb libreadline-dev bison flex zlib1g-dev tmux zile zip vim gawk wget > /dev/null

# add postgres user and make data dir
RUN groupadd -r postgres && useradd --no-log-init -r -m -s /bin/bash -g postgres -G sudo postgres
ENV PGDATA /home/postgres/data
RUN /bin/rm -Rf "$PGDATA" && mkdir "$PGDATA"
WORKDIR "/home/postgres"

# get postgres source and compile with debug and no optimization
RUN git clone --branch REL_${version}_STABLE https://github.com/postgres/postgres.git --depth=1 && \
    cd postgres && echo "Installing pgsql..." && ( ./configure \
    --prefix=/usr/ \
    --enable-debug \
    --enable-depend --enable-cassert --enable-profiling \
    CFLAGS="-ggdb -Og -g3 -fno-omit-frame-pointer" \
    && make -j 4 && make install ) > /dev/null
#    CFLAGS="-O3"

RUN chown postgres:postgres /home/postgres

RUN curl -s -L https://github.com/theory/pgtap/archive/v1.2.0.tar.gz | tar zxf - && cd pgtap-1.2.0 && (make && make install) > /dev/null
RUN curl -s -L https://download.libsodium.org/libsodium/releases/libsodium-1.0.18.tar.gz | tar zxf - && cd libsodium-1.0.18 && (./configure && make check && make -j 4 install) > /dev/null
RUN cpan App::cpanminus > /dev/null
RUN cpan TAP::Parser::SourceHandler::pgTAP > /dev/null
RUN cpan App::prove > /dev/null

RUN git clone --depth 1 https://github.com/lacanoid/pgddl.git && \
    (cd pgddl && make && make install && cd ..) > /dev/null

RUN mkdir "/home/postgres/pgsodium"
WORKDIR "/home/postgres/pgsodium"
COPY . .
RUN echo "Installing pgsodium..." && (make -j 4 && make install) > /dev/null
RUN ldconfig
RUN cd `pg_config --sharedir`/extension/
RUN cp getkey_scripts/pgsodium_getkey_urandom.sh `pg_config --sharedir`/extension/pgsodium_getkey
RUN sed -i 's/exit//g' `pg_config --sharedir`/extension/pgsodium_getkey
RUN chmod +x `pg_config --sharedir`/extension/pgsodium_getkey
RUN cp `pg_config --sharedir`/extension/pgsodium_getkey /getkey

# chown just pggraphblas
RUN chown -R postgres:postgres /home/postgres/pgsodium
RUN chown -R postgres:postgres /home/postgres/data

# make postgres a sudoer
RUN echo "postgres ALL=(root) NOPASSWD:ALL" > /etc/sudoers.d/user && \
    chmod 0440 /etc/sudoers.d/user

# start the database
USER postgres
RUN initdb -D "$PGDATA" > /dev/null
EXPOSE 5432
CMD ["/usr/bin/postgres"]
