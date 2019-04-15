#!/bin/bash

DOCKER_REPO=${1:-wattson}

GO=`which go`
REALPATH=`which realpath`
if [ "x$GO" == "x" ]; then
    echo "go missing, please install go 1.5 or newer"
    exit 1
fi

if [ "x$REALPATH" == "x" ]; then
    echo "realpath missing, please install it"
    exit 1
fi

PATH_TO_SCRIPT=`realpath ${0}`
PATH_TO_FOLDER=`dirname "$PATH_TO_SCRIPT"`
PATH_TO_REPO=`cd "${PATH_TO_FOLDER}/.." && pwd -P`

DOCKERFILE="$PATH_TO_FOLDER/Dockerfile"
WATTSON="$PATH_TO_REPO/wattson"

cd $PATH_TO_REPO
echo " "
echo " building wattson ..."

VERSION=`go version`
GOPATH=`cd "${PATH_TO_FOLDER}/.." && pwd -P`

echo "    cleaning ..."
pwd
rm wattson
rm wattson_container_*.tgz
echo " "
echo "running the build with '$VERSION', please include in issue reports"
echo " "
export "GOPATH=${GOPATH}"
echo "fetiching:"
echo -n "  kingpin ... "
go get gopkg.in/alecthomas/kingpin.v2
echo "done"
echo -n "  sling ... "
go get github.com/dghubble/sling
echo "done"
echo -n "  liboidcagent ... "
go get github.com/indigo-dc/liboidcagent-go/liboidcagent
echo "done"
echo -n "building wattson ... "
CGO_ENABLED=0 GOOS=linux go build -a -v -o $WATTSON ${GOPATH}/wattson.go
echo "done"

echo "building docker ... "
mkdir -p /tmp/wattson_docker/
cp $DOCKERFILE /tmp/wattson_docker/
cp $WATTSON /tmp/wattson_docker/
cp /etc/ssl/certs/ca-certificates.crt /tmp/wattson_docker/
cd /tmp/wattson_docker/
WATTSON_VERSION=`./wattson --version 2>&1`
WATTSON_TAG="$DOCKER_REPO:$WATTSON_VERSION"
WATTSON_DOCKER="$PATH_TO_REPO/wattson_container_${WATTSON_VERSION}.tar"
docker image rm -f "$WATTSON_TAG"
docker build -t "$WATTSON_TAG" .
cd $PATH_TO_REPO
rm -rf /tmp/wattson_docker/
docker save --output "$WATTSON_DOCKER" "$WATTSON_TAG"
echo "done"

echo " "
echo " "
echo " checking image "
docker image rm -f "$WATTSON_TAG"
docker images -a
docker load --input "$WATTSON_DOCKER"
docker run  --rm "$WATTSON_TAG" --version
docker images -a
echo " done "
