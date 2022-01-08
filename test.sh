#!/bin/bash

set -e

versions=${1:-14 13 12 11 10}

for version in $versions
do
	for config in '-c shared_preload_libraries=pgsodium' '' '-c shared_preload_libraries=pgsodium -c pgsodium.getkey_script=/getkey'
	do
		DB_HOST="pgsodium-test-db-$version"
		DB_NAME="postgres"
		SU="postgres"
		EXEC="docker exec -it $DB_HOST"
		TAG="pgsodium/test-$version"

		echo building test image $DB_HOST
		docker build . -t $TAG --build-arg "version=$version"

		echo running test container
		docker run --rm -e POSTGRES_HOST_AUTH_METHOD=trust -d --name "$DB_HOST" $TAG $config

		echo waiting for database to accept connections
		sleep 1;
		until
			$EXEC pg_isready -t 3 -U "$SU";
		do
            docker logs "$DB_HOST";
            sleep 3;
		done
        docker logs "$DB_HOST"
		echo running tests
		$EXEC psql -U "$SU" -f /pgsodium/test/test.sql

		echo destroying test container and image
		docker rm --force "$DB_HOST"
	done
done
