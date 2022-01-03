ARG version
FROM postgres:${version}
ARG version
    
RUN apt-get update && apt-get install -y make git postgresql-server-dev-${version} curl build-essential libreadline-dev zile
RUN curl -s -L https://github.com/theory/pgtap/archive/v1.1.0.tar.gz | tar zxvf - && cd pgtap-1.1.0 && make && make install
RUN curl -s -L https://download.libsodium.org/libsodium/releases/libsodium-1.0.18.tar.gz | tar zxvf - && cd libsodium-1.0.18 && ./configure && make check && make install
RUN mkdir "/pgsodium"
WORKDIR "/pgsodium"
COPY . .
RUN make -j 4 && make install
RUN ldconfig
RUN cd `pg_config --sharedir`/extension/
RUN cp getkey_scripts/pgsodium_getkey_urandom.sh `pg_config --sharedir`/extension/pgsodium_getkey
RUN sed -i 's/exit//g' `pg_config --sharedir`/extension/pgsodium_getkey
RUN chmod +x `pg_config --sharedir`/extension/pgsodium_getkey
RUN cp `pg_config --sharedir`/extension/pgsodium_getkey /getkey
