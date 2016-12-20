#!/bin/bash
DISTRIBUTION_NAME=`cat /etc/os-release | grep PRETTY_NAME`
CURRENT_DIR=`pwd`
cd `dirname $0`
UTILS_DIR=`pwd`

DISTRIBUTION="unknown"
case "$DISTRIBUTION_NAME" in
    *Debian*)
        DISTRIBUTION="debian"
        ;;
    *Ubuntu*)
        DISTRIBUTION="debian"
        ;;
    *CentOS*)
        DISTRIBUTION="centos"
        ;;
esac
export DISTRIBUTION="$DISTRIBUTION"
echo "preparing the system ..."
echo "distribution: $DISTRIBUTION"
echo "utils dir: $UTILS_DIR"
echo "current dir: $CURRENT_DIR"
if [ "$DISTRIBUTION" = "unknown" ]; then
    echo "ERROR: unknown distribution"
    exit 1
fi

echo " "
echo " "
echo "*** INSTALLING PACKAGES ***"
cd $UTILS_DIR
case "$DISTRIBUTION" in
    debian)
        ./debian_install_packages.sh
        ;;
    ubuntu)
        ./ubuntu_install_packages.sh
        ;;
    centos)
        ./centos_install_packages.sh
        ;;
esac

echo " "
echo " "
echo "*** creating go environment ***"
export GOPATH="/tmp/go-ttsc"
export PATH="$GOPATH/bin:$PATH"
echo "GOPATH: $GOPATH"
echo "PATH: $PATH"

rm -rf $GOPATH
mkdir -p $GOPATH
cd $GOPATH
mkdir bin
mkdir pkg
mkdir -p src/github.com/indigo-dc/ttsc
mkdir -p src/github.com/mh-cbon
cd src/github.com/mh-cbon
case "$DISTRIBUTION" in
    debian)
        git clone https://github.com/mh-cbon/go-bin-deb.git
        cd go-bin-deb
        git checkout 0.0.16
        ;;
    ubuntu)
        git clone https://github.com/mh-cbon/go-bin-deb.git
        cd go-bin-deb
        git checkout 0.0.16
        ;;
    centos)
        git clone https://github.com/mh-cbon/go-bin-rpm.git
        cd go-bin-rpm
        git checkout 0.0.15
        ;;
esac
glide install
go install
cd ..
git clone https://github.com/mh-cbon/changelog.git
cd changelog
git checkout 0.0.24
glide install
go install

echo " "
echo " "
echo "*** SYSTEM SETUP DONE ***"
echo " "
