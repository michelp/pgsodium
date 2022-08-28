version=$1
shift

DB_HOST="pgsodium-notebook-db-$version"
DB_NAME="postgres"
SU="postgres"
EXEC="docker exec $DB_HOST"
TAG="pgsodium/test-$version"

echo building test image $DB_HOST
docker build -f example/Dockerfile . -t $TAG --build-arg "version=$version"

echo running test container
docker run -d -p 8888:8888 --net=host -v `pwd`:/pgsodium -e POSTGRES_HOST_AUTH_METHOD=trust --name "$DB_HOST" $TAG -c 'shared_preload_libraries=pgsodium,anon' 

echo waiting for database to accept connections
until
    $EXEC \
        psql -o /dev/null -t -q -U "$SU" \
        -c 'select pg_sleep(1)' \
        2>/dev/null;
do sleep 1;
done

docker exec -u root -e NB_UID=$(id -u) -e NB_GID=$(id -g) -it $DB_HOST jupyter notebook --allow-root
