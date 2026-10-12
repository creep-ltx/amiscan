# AmiScan: one static Linux binary. Needs Go and a C compiler (for the
# built-in 68000, Musashi); the people who use it need neither.

VERSION := $(shell sed -n 's/^const version = "\(.*\)"/\1/p' cmd/amiscan/main.go)

amiscan: $(shell find cmd internal -name '*.go' -o -name '*.c' -o -name '*.h')
	CGO_ENABLED=1 go build -trimpath -tags osusergo,netgo \
		-ldflags '-s -w -linkmode external -extldflags "-static"' -o $@ ./cmd/amiscan

# Windows, built here with MinGW (pacman: mingw-w64-gcc); try it with Wine.
amiscan.exe: $(shell find cmd internal -name '*.go' -o -name '*.c' -o -name '*.h')
	CGO_ENABLED=1 GOOS=windows GOARCH=amd64 CC=x86_64-w64-mingw32-gcc go build -trimpath \
		-ldflags '-s -w -extldflags "-static"' -o $@ ./cmd/amiscan

test:
	go vet ./...
	go test ./...

release: amiscan amiscan.exe
	mkdir -p dist/amiscan-$(VERSION)-linux dist/amiscan-$(VERSION)-windows
	cp amiscan README.md NOTICES.md dist/amiscan-$(VERSION)-linux/
	cp amiscan.exe README.md NOTICES.md dist/amiscan-$(VERSION)-windows/
	tar -C dist -czf dist/amiscan-$(VERSION)-linux-x86_64.tar.gz amiscan-$(VERSION)-linux
	cd dist && zip -qr amiscan-$(VERSION)-windows-x86_64.zip amiscan-$(VERSION)-windows

clean:
	rm -rf amiscan amiscan.exe dist

.PHONY: test release clean
