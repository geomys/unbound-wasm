include versions.mk

.PHONY: module module-local module-check clean

# The container is pinned to linux/amd64 to match the pinned wasi-sdk
# artifact; on other hosts it runs under emulation, and the wasm output is
# identical.
module:
	docker build --platform linux/amd64 -f Dockerfile.build \
	  --build-arg WASI_SDK_TAG=$(WASI_SDK_TAG) \
	  --build-arg WASI_SDK_VERSION=$(WASI_SDK_VERSION) \
	  --build-arg WASI_SDK_SHA256=$(WASI_SDK_SHA256) \
	  -t unbound-wasm-build:$(WASI_SDK_VERSION) .
	docker run --rm --platform linux/amd64 --user "$$(id -u):$$(id -g)" -e HOME=/tmp -v "$(CURDIR):/src" unbound-wasm-build:$(WASI_SDK_VERSION)
	./build/update-embedded.sh

module-local:
	@test -n "$(WASI_SDK)" || (echo 'set WASI_SDK=/path/to/wasi-sdk' >&2; exit 2)
	WASI_SDK="$(WASI_SDK)" ./build/build-module.sh
	./build/update-embedded.sh

module-check:
	go test -run TestEmbeddedModule

clean:
	rm -rf build/work build/downloads
