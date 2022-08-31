ARG version
FROM postgres:${version}
ARG version

RUN apt-get update && apt-get install -y make git postgresql-server-dev-${version} curl build-essential libreadline-dev pgxnclient python3-pip
RUN curl -s -L https://download.libsodium.org/libsodium/releases/libsodium-1.0.18.tar.gz | tar zxvf - && cd libsodium-1.0.18 && ./configure && make check && make install

RUN pip3 install ipython-sql sqlalchemy psycopg2 pgspecial ipykernel jupyterlab

RUN mkdir "/pgsodium"
WORKDIR "/pgsodium"
COPY . .
RUN make && make install
RUN ldconfig
RUN cd `pg_config --sharedir`/extension/
RUN cp getkey_scripts/pgsodium_getkey_urandom.sh `pg_config --sharedir`/extension/pgsodium_getkey
RUN sed -i 's/exit//g' `pg_config --sharedir`/extension/pgsodium_getkey
RUN chmod +x `pg_config --sharedir`/extension/pgsodium_getkey
RUN chown -R postgres:postgres /pgsodium
