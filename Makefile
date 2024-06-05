.PHONY: db copy_scan stage_init stage_scan scanner_image

BASE_IMAGE_TAG = latest
BUILD_IMAGE_TAG = v2

# Keep this as the first
all:
	go build -ldflags='-s -w' -buildvcs=false
	cd task; make; cd ..
	cd monitor; make; cd ..

STAGE_DIR = stage

copy_scan:
	mkdir -p ${STAGE_DIR}/usr/local/bin/
	mkdir -p ${STAGE_DIR}/etc/neuvector/db
	#
	cp scanner/monitor/monitor ${STAGE_DIR}/usr/local/bin/
	cp scanner/scanner ${STAGE_DIR}/usr/local/bin/
	cp scanner/task/scannerTask ${STAGE_DIR}/usr/local/bin/
	cp sigstore-interface/sigstore-interface ${STAGE_DIR}/usr/local/bin/sigstore-interface
	cp scanner/data/cvedb.regular ${STAGE_DIR}/etc/neuvector/db/cvedb

stage_init:
	rm -rf ${STAGE_DIR}; mkdir -p ${STAGE_DIR}

stage_scan: stage_init copy_scan

scanner_image: stage_scan
	docker pull neuvector/scanner_base:${BASE_IMAGE_TAG}
	docker build --build-arg BASE_IMAGE_TAG=${BASE_IMAGE_TAG} -t neuvector/scanner -f scanner/build/Dockerfile.scanner .

binary:
	@echo "Making $@ ..."
	@docker pull neuvector/build_fleet:${BUILD_IMAGE_TAG}
	@docker run --rm -ia STDOUT --name build -e VULN_VER=$(VULN_VER) --net=none -v $(CURDIR):/go/src/github.com/neuvector/scanner -w /go/src/github.com/neuvector/scanner --entrypoint ./make_bin.sh neuvector/build_fleet:${BUILD_IMAGE_TAG}
