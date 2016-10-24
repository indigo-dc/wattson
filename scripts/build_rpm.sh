#!/bin/bash

my_dir="$(dirname "$0")"
source $my_dir/package_config.sh

mkdir -p $RPM_DIR/SOURCES
cp ttsc $RPM_DIR/SOURCES

#  adjust the config files
mkdir -p $RPM_DIR/SPECS
cat $RPM_DIR/../conf/ttsc.spec | ./scripts/mo > $RPM_DIR/SPECS/ttsc.spec

rpmbuild --define "_topdir ${RPM_DIR}" -ba $RPM_DIR/SPECS/ttsc.spec

mv $RPM_DIR/RPMS/x86_64/ttsc-*.rpm packaging/
