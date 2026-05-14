.PHONY: all copy_scan build

BASE_IMAGE_TAG = latest
BUILD_IMAGE_TAG = v2

STAGE_DIR = stage

RUNNER := docker
IMAGE_BUILDER := $(RUNNER) buildx
MACHINE := neuvector
BUILDX_ARGS ?= --sbom=true --attest type=provenance,mode=max
DEFAULT_PLATFORMS := linux/amd64,linux/arm64,linux/x390s,linux/riscv64
STAGE_DIR=stage

# For scanner, the version is also vulndb version.
COMMIT = $(shell git rev-parse --short HEAD)
ifeq ($(VERSION),)
	# Define VERSION, which is used for image tags or to bake it into the
	# compiled binary to enable the printing of the application version, 
	# via the --version flag.
	CHANGES = $(shell git status --porcelain --untracked-files=no)
	ifneq ($(CHANGES),)
		DIRTY = -dirty
	endif

	GIT_TAG = $(shell git tag -l --contains HEAD | head -n 1)

	COMMIT = $(shell git rev-parse --short HEAD)
	VERSION = $(COMMIT)$(DIRTY)

	# Override VERSION with the Git tag if the current HEAD has a tag pointing to
	# it AND the worktree isn't dirty.
	ifneq ($(GIT_TAG),)
		ifeq ($(DIRTY),)
			VERSION = $(GIT_TAG)
		endif
	endif
	VULNDBVER=LATEST
else
	VULNDBVER=$(VERSION:1)
endif

ifeq ($(TAG),)
	TAG = $(VERSION)
	ifneq ($(DIRTY),)
		TAG = dev
	endif
endif

TARGET_PLATFORMS ?= linux/amd64,linux/arm64
REPO ?= neuvector
IMAGE = $(REPO)/scanner:$(TAG)
BUILD_ACTION = --load

ARCH := $(shell uname -p)

# Keep this as the first
all: test build copy_scan gen_license

build:
	go build -ldflags='-s -w' -buildvcs=false -o scanner ./cmd/scanner
	go build -ldflags='-s -w' -buildvcs=false -o sigstore-interface ./cmd/sigstore-interface
	make -C task/
	make -C monitor/

test:
	# Only run unit-test on amd64 for now
	if [ "$(ARCH)" = "x86_64" ]; then go test ./...;fi

STAGE_DIR = stage

gen_license:
	mkdir -p ${STAGE_DIR}/licenses
	cd vendor && ../genlic.sh > ../${STAGE_DIR}/licenses/neuvector-license.txt

copy_scan:
	mkdir -p ${STAGE_DIR}/usr/local/bin/
	mkdir -p ${STAGE_DIR}/etc/neuvector/db
	#
	cp monitor/monitor ${STAGE_DIR}/usr/local/bin/
	cp task/scannerTask ${STAGE_DIR}/usr/local/bin/
	cp scanner ${STAGE_DIR}/usr/local/bin/
	cp sigstore-interface ${STAGE_DIR}/usr/local/bin/sigstore-interface
	cp data/cvedb.regular ${STAGE_DIR}/etc/neuvector/db/cvedb

buildx-machine:
	docker buildx ls
	@docker buildx ls | grep $(MACHINE) || \
	docker buildx create --name=$(MACHINE) --platform=$(DEFAULT_PLATFORMS)

test-image:
	# Instead of loading image, target all platforms, effectivelly testing
	# the build for the target architectures.
	$(MAKE) build-image BUILD_ACTION="--platform=$(TARGET_PLATFORMS)"

build-image: buildx-machine ## build (and load) the container image targeting the current platform.
	$(IMAGE_BUILDER) build -f package/Dockerfile \
		--builder $(MACHINE) $(IMAGE_ARGS) \
		--build-arg VERSION=$(VERSION) --build-arg COMMIT=$(COMMIT) -t "$(IMAGE)" $(BUILD_ACTION) .
	@echo "Built $(IMAGE)"


push-image: buildx-machine
	$(IMAGE_BUILDER) build -f package/Dockerfile \
		--builder $(MACHINE) $(IMAGE_ARGS) $(IID_FILE_FLAG) $(BUILDX_ARGS) \
		--build-arg VERSION=$(VERSION) --build-arg COMMIT=$(COMMIT) --build-arg VULNDBVER=$(VULNDBVER) --platform=$(TARGET_PLATFORMS) -t "$(REPO)/$(IMAGE_PREFIX)scanner:$(TAG)" --push .
	@echo "Pushed $(REPO)/$(IMAGE_PREFIX)scanner:$(TAG)"
