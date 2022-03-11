.PHONY: db copy_scan stage_init stage_scan scanner_image

# Keep this as the first
all:
	go build -ldflags='-s -w'
	cd task; make; cd ..
	cd monitor; make; cd ..

REPO_URL = 10.1.127.3:5000
REPO_REL_URL = 10.1.127.12:5000
STAGE_DIR = stage

copy_scan:
	mkdir -p ${STAGE_DIR}/usr/local/bin/
	mkdir -p ${STAGE_DIR}/etc/neuvector/db
	#
	cp scanner/monitor/monitor ${STAGE_DIR}/usr/local/bin/
	cp scanner/scanner ${STAGE_DIR}/usr/local/bin/
	cp scanner/task/scannerTask ${STAGE_DIR}/usr/local/bin/
	cp scanner/data/cvedb.regular ${STAGE_DIR}/etc/neuvector/db/cvedb

stage_init:
	rm -rf ${STAGE_DIR}; mkdir -p ${STAGE_DIR}

stage_scan: stage_init copy_scan

scanner_image: stage_scan
	docker pull $(REPO_REL_URL)/neuvector/scanner_base:latest
	docker build -t neuvector/scanner -f scanner/build/Dockerfile.scanner .

ubi_scanner:
	rm -rf ${STAGE_DIR}; mkdir -p ${STAGE_DIR}
	mkdir -p ${STAGE_DIR}/licenses/
	mkdir -p ${STAGE_DIR}/usr/local/bin/
	mkdir -p ${STAGE_DIR}/etc/neuvector/certs/
	mkdir -p ${STAGE_DIR}/etc/neuvector/certs/internal/
	mkdir -p ${STAGE_DIR}/etc/neuvector/db/
	docker run -itd --name cache --entrypoint true ${REPO_URL}/neuvector/scanner:latest
	docker cp cache:/licenses/. ${STAGE_DIR}/licenses/
	docker cp cache:/etc/neuvector/certs/internal/. ${STAGE_DIR}/etc/neuvector/certs/internal/
	docker cp cache:/usr/local/bin/. ${STAGE_DIR}/usr/local/bin/
	docker cp cache:/etc/neuvector/db/cvedb ${STAGE_DIR}/etc/neuvector/db/cvedb
	docker stop cache; docker rm cache
	rm -f ${S_DATA_FILE} || true
	cd stage; tar -czvf ../${S_DATA_FILE} *; cd ..
	docker build --build-arg DATA_FILE=${S_DATA_FILE} -t neuvector/scanner.ubi -f scanner/build/Dockerfile.scanner.ubi .

binary:
	@echo "Making $@ ..."
	@docker pull $(REPO_REL_URL)/neuvector/build
	@docker run --rm -ia STDOUT --name build -e VULN_VER=$(VULN_VER) --net=none -v $(CURDIR):/go/src/github.com/neuvector/scanner -w /go/src/github.com/neuvector/scanner --entrypoint ./make_bin.sh $(REPO_REL_URL)/neuvector/build
