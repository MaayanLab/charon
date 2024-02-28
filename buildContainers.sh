# get rid of old stuff
docker rmi -f $(docker images | grep "^<none>" | awk "{print $3}")
docker rm $(docker ps -q -f status=exited)

docker kill charon
docker rm charon


docker build --platform="linux/amd64" -f Dockerfile -t maayanlab/charon:2.7 .

#docker run -p 5000:5000 -it maayanlab/charon:2.1
docker push maayanlab/charon:2.7
