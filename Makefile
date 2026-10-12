# AmiScan: one static Linux binary. Needs Go and a C compiler (for the
# built-in 68000, Musashi); the people who use it need neither.

VERSION := $(shell sed -n 's/^const version = "\(.*\)"/\1/p' cmd/amiscan/main.go)

amiscan: $(shell find cmd internal -name '*.go' -o -name '*.c' -o -name '*.h')
	CGO_ENABLED=1 go build -trimpath -tags osusergo,netgo \
		-ldflags '-s -w -linkmode external -extldflags "-static"' -o $@ ./cmd/amiscan

test:
	go vet ./...
	go test ./...

release: amiscan
	mkdir -p dist/amiscan-$(VERSION)
	cp amiscan README.md NOTICES.md dist/amiscan-$(VERSION)/
	tar -C dist -czf dist/amiscan-$(VERSION)-linux-x86_64.tar.gz amiscan-$(VERSION)

clean:
	rm -rf amiscan dist

.PHONY: test release clean
