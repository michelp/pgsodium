version=$1
shift

DB_HOST="pgsodium-test-db-$version"
DB_NAME="postgres"
SU="postgres"
EXEC="docker exec $DB_HOST"
TAG="pgsodium/test-$version"
CONFIG="-c shared_preload_libraries=pgsodium -c pgsodium.getkey_script=/getkey"

echo building test image $DB_HOST
docker build . -t $TAG --build-arg "version=$version"

echo running test container
docker run \
	   -v `pwd`/example:/pgsodium/example \
	   -e POSTGRES_HOST_AUTH_METHOD=trust \
	   -d --name "$DB_HOST" $TAG $CONFIG

echo waiting for database to accept connections
until
    $EXEC \
        psql -o /dev/null -t -q -U "$SU" \
        -c 'select pg_sleep(1)' \
        2>/dev/null;
do sleep 1;
done

docker exec -it $DB_HOST psql -U "$SU" $@
