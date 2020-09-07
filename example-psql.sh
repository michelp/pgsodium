version=${1:-13}
shift

DB_HOST="pgsodium-example-db-$version"
DB_NAME="postgres"
SU="postgres"
EXEC="docker exec $DB_HOST"
TAG="pgsodium/test-$version"

echo building test image $DB_HOST
docker build -f example/Dockerfile . -t $TAG --build-arg "version=$version"

echo running test container
docker run -v `pwd`/example:/pgsodium/example -e POSTGRES_HOST_AUTH_METHOD=trust -d --name "$DB_HOST" $TAG -c 'shared_preload_libraries=pgsodium,anon' 

echo waiting for database to accept connections
until
    $EXEC \
        psql -o /dev/null -t -q -U "$SU" \
        -c 'select pg_sleep(1)' \
        2>/dev/null;
do sleep 1;
done

docker exec -it $DB_HOST psql -U "$SU" $@
