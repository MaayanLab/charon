# get rid of old stuff
docker rmi -f $(docker images | grep "^<none>" | awk "{print $3}")
docker rm $(docker ps -q -f status=exited)

docker kill charon
docker rm charon


docker build -f Dockerfile -t maayanlab/charon .

docker push maayanlab/charon
