ARG version
FROM postgres:${version}
ARG version
    
RUN apt-get update && apt-get install -y make git postgresql-server-dev-${version} postgresql-${version}-pgtap curl build-essential
RUN curl -s -L https://download.libsodium.org/libsodium/releases/libsodium-1.0.18.tar.gz | tar zxvf - && cd libsodium-1.0.18 && ./configure && make check && make install
RUN mkdir "/pgsodium"
WORKDIR "/pgsodium"
COPY . .
RUN make && make install
RUN ldconfig


