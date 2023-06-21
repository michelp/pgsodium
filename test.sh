#!/bin/bash

set -e

versions=${1:-13 14 15}

for version in $versions
do
	TAG="pgsodium/test-$version"
	DB_HOST="pgsodium-test-db-$version"

	echo building test image $DB_HOST
	docker build . -t $TAG --build-arg "version=$version"

	for config in '-c shared_preload_libraries=pgsodium' '-c shared_preload_libraries=pgsodium -c pgsodium.getkey_script=/getkey' ''
	do
		DB_NAME="postgres"
		SU="postgres"
		EXEC="docker exec -i $DB_HOST"

		echo running test container
		docker run --rm -e POSTGRES_HOST_AUTH_METHOD=trust -d \
               -v `pwd`/test:/home/postgres/pgsodium/test:Z \
               -v `pwd`/example:/home/postgres/pgsodium/example:Z \
               --name "$DB_HOST" $TAG postgres $config

		echo waiting for database to accept connections
		sleep 3;
		echo running tests

		# test using inscremental script
		$EXEC createdb inc
		$EXEC psql -d inc -c 'CREATE EXTENSION pgsodium VERSION "3.1.0"'
		$EXEC pg_prove -d inc -U "$SU" /home/postgres/pgsodium/test/test.sql

		# test using full script
		$EXEC createdb full
		$EXEC pg_prove -d full -U "$SU" /home/postgres/pgsodium/test/test.sql

		echo destroying test container and image
		docker rm --force "$DB_HOST"
	done
done
