#!/bin/bash


CURRENT_DIR=`pwd`
cd `dirname $0`
cd ..
SOURCE_DIR=`pwd`
source ./utils/prepare_system.sh

# expecting to be in $GOPATH/src/github.com/indigo-dc/ttsc
mkdir -p $GOPATH/src/github.com/indigo-dc/ttsc
cd $GOPATH/src/github.com/indigo-dc/ttsc
pwd
cp -v $SOURCE_DIR/* .
glide install
rm -fr pkg-build/*
mkdir -p pkg-build/amd64
GOOS=linux GOARCH=amd64 go build -o build/amd64/ttsc ttsc.go

VERSION="0.0.1"

case $DISTRIBUTION in
    ubuntu)
        go-bin-deb generate -a amd64 --version ${VERSION} -w pkg-build/amd64/ -o ttsc-amd64.deb
        ;;
    debian)
        go-bin-deb generate -a amd64 --version ${VERSION} -w pkg-build/amd64/ -o ttsc-amd64.deb
        ;;
    centos)
        echo "not yet supported"
        ;;
esac
echo " "
echo " "
echo " *** DONE ***"
