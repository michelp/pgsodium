#!/bin/bash

set -e

for version in 9 10 11 12
do
    DB_HOST="pgsodium-test-db-$version"
    DB_NAME="postgres"
    SU="postgres"
    EXEC="docker exec $DB_HOST"
    TAG="pgsodium/test-$version"

    echo building test image $DB_HOST
    docker build . -t $TAG --build-arg "version=$version"

    echo running test container
    docker run -e POSTGRES_HOST_AUTH_METHOD=trust -d --name "$DB_HOST" $TAG

    echo waiting for database to accept connections
    until
        $EXEC \
            psql -o /dev/null -t -q -U "$SU" \
            -c 'select pg_sleep(1)' \
            2>/dev/null;
    do sleep 1;
    done

    echo running tests
    $EXEC pg_prove -U "$SU" /pgsodium/test.sql

    echo destroying test container and image
    docker rm --force "$DB_HOST"
done

