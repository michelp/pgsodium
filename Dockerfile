FROM postgres:11
RUN apt-get update && apt-get install -y make git postgresql-server-dev-11 postgresql-11-pgtap curl build-essential
RUN curl -s -L https://github.com/jedisct1/libsodium/releases/download/1.0.16/libsodium-1.0.16.tar.gz | tar zxvf - && cd libsodium-1.0.16 && ./configure && make check && make install
RUN mkdir "/pgsodium"
WORKDIR "/pgsodium"
COPY . .
RUN make && make install
RUN ldconfig


