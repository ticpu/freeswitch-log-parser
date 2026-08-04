BINARY := fslog
DOCKER := $(shell which podman || which docker)
DEB_ARCH ?= amd64
# Old base image on purpose: the released binary's glibc floor is whatever this
# suite ships, and that floor is what makes it portable to production servers.
DEBIAN_SUITE ?= bullseye

CARGO_VERSION := $(shell grep '^version' Cargo.toml | head -1 | cut -d'"' -f2)
GIT_SHORT := $(shell git rev-parse --short HEAD)
GIT_TAG := $(shell git tag --points-at HEAD --list 'v*' | head -1)
GIT_DIRTY := $(shell git status --porcelain --untracked-files=no | head -1)
# Only a clean checkout of a v* tag claims the plain Cargo.toml version; anything
# else carries its commit so a dev .deb can never be mistaken for the released one.
DEB_VERSION := $(if $(GIT_DIRTY),$(CARGO_VERSION)+$(GIT_SHORT).dirty,$(if $(GIT_TAG),$(CARGO_VERSION),$(CARGO_VERSION)+$(GIT_SHORT)))

DEB_AMD64 := $(BINARY)_$(DEB_VERSION)_amd64.deb
DEB_ARM64 := $(BINARY)_$(DEB_VERSION)_arm64.deb
DEB := $(BINARY)_$(DEB_VERSION)_$(DEB_ARCH).deb

# Staging lives under target/: on bcachefs that is a subvolume, so build
# artifacts stay out of the repo's snapshots.
DIST := target/dist/$(DEB_ARCH)
IMG := fslog-build:$(DEB_ARCH)-$(DEBIAN_SUITE)
PKG := target/package.tmp
CTX := target/context.tmp

.PHONY: all binary deb deb-all clean

all: deb

binary: $(DIST)/fslog

deb: $(DEB)

deb-all:
	$(MAKE) deb DEB_ARCH=amd64
	$(MAKE) deb DEB_ARCH=arm64

# Built in the container, extracted through a throwaway container: the image is
# kept (stable tag) so a rebuild reuses its layer and registry caches. The build
# context is staged rather than the repo root, which carries target/ and the log
# fixtures. Cargo.lock only exists on a release tag; without it cargo resolves.
$(DIST)/fslog: packaging/Containerfile Cargo.toml $(shell find src -name '*.rs')
	rm -rf "$(CTX)"
	mkdir -p "$(CTX)"
	cp -a Cargo.toml src "$(CTX)/"
	if [ -f Cargo.lock ]; then cp -a Cargo.lock "$(CTX)/"; fi
	$(DOCKER) build --platform linux/$(DEB_ARCH) --build-arg SUITE=$(DEBIAN_SUITE) \
		--tag "$(IMG)" -f packaging/Containerfile "$(CTX)"
	rm -rf "$(CTX)"
	rm -rf "$(DIST)"
	mkdir -p target/dist
	cid=$$($(DOCKER) create "$(IMG)") && \
	$(DOCKER) cp "$$cid:/app/out" "$(DIST)"; \
	rc=$$?; $(DOCKER) rm "$$cid" > /dev/null; exit $$rc

# A version bump otherwise leaves the previous version's .deb behind for a
# release job to pick up alongside the current one.
define purge_stale_debs
	@for f in $(BINARY)_*.deb; do \
		[ -e "$$f" ] || continue; \
		case "$$f" in \
			$(DEB_AMD64)|$(DEB_ARM64)) ;; \
			*) rm -f "$$f"; echo "removed stale $$f"; ;; \
		esac; \
	done
endef

$(DEB): $(DIST)/fslog packaging/control LICENSE
	$(call purge_stale_debs)
	rm -rf "$(PKG)"
	install -D -m 755 -T "$(DIST)/fslog" "$(PKG)/usr/bin/$(BINARY)"
	install -D -m 644 -T "$(DIST)/completions/bash" "$(PKG)/usr/share/bash-completion/completions/$(BINARY)"
	install -D -m 644 -T "$(DIST)/completions/zsh" "$(PKG)/usr/share/zsh/vendor-completions/_$(BINARY)"
	install -D -m 644 -T "$(DIST)/completions/fish" "$(PKG)/usr/share/fish/vendor_completions.d/$(BINARY).fish"
	install -D -m 644 -T LICENSE "$(PKG)/usr/share/doc/$(BINARY)/copyright"
	install -D -m 644 -T packaging/control "$(PKG)/DEBIAN/control"
	sed -i -e "s/^Version:.*/Version: $(DEB_VERSION)/" \
		-e "s/^Architecture:.*/Architecture: $(DEB_ARCH)/" \
		-e "s/^Depends:.*/Depends: libc6 (>= $$(cat $(DIST)/glibc-floor)), libgcc-s1, liblzma5/" \
		"$(PKG)/DEBIAN/control"
	@if grep -rq "$$PWD" "$(PKG)"; then echo "ERROR: package contains build path ($$PWD)" >&2; exit 1; fi
	dpkg-deb --build --root-owner-group "$(PKG)" "$@"
	rm -rf "$(PKG)"

clean:
	rm -rf "$(PKG)" "$(CTX)" target/dist $(BINARY)_*.deb
