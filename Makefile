
compile:
	./scripts/build.sh

install: compile
	install -m 755 ttsc /usr/bin/ttsc

deb: compile
	./scripts/build_deb.sh

rpm: compile
	./scripts/build_rpm.sh
