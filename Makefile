# AmiScan - Amiga virus scanner
#
#   make                 build ./amiscan (static on Linux)
#   make install         install program, manual page and documentation
#   make uninstall       remove them again
#   make test            vet and tests (set AMISCAN_LIBS to test with the real parts)
#   make check           test, plus the manual page checked with groff
#   make amiscan.exe     Windows build with MinGW (pacman: mingw-w64-gcc)
#   make release         Linux and Windows archives in dist/
#
# Building needs Go and a C compiler (for the built-in 68000, Musashi);
# the people who use AmiScan need neither.
#
# Where "make install" puts things (packagers: DESTDIR=/tmp/pkg):
PREFIX  ?= /usr/local
BINDIR  ?= $(PREFIX)/bin
MANDIR  ?= $(PREFIX)/share/man
DOCDIR  ?= $(PREFIX)/share/doc/amiscan
DESTDIR ?=

VERSION := $(shell sed -n 's/^const version = "\(.*\)"/\1/p' cmd/amiscan/main.go)
SOURCES := $(shell find cmd internal -name '*.go' -o -name '*.c' -o -name '*.h') go.mod go.sum
DOCS    := README.md NOTICES.md LICENSE docs/*.md
GO      ?= go
INSTALL ?= install

# Static on Linux (one file that runs on any distribution); macOS does not
# allow fully static programs, so there it links the system library only.
ifeq ($(shell uname -s),Darwin)
LDFLAGS := -s -w
else
LDFLAGS := -s -w -linkmode external -extldflags "-static"
endif

all: amiscan

amiscan: $(SOURCES)
	CGO_ENABLED=1 $(GO) build -trimpath -tags osusergo,netgo -ldflags '$(LDFLAGS)' -o $@ ./cmd/amiscan

amiscan.exe: $(SOURCES)
	CGO_ENABLED=1 GOOS=windows GOARCH=amd64 CC=x86_64-w64-mingw32-gcc \
		$(GO) build -trimpath -ldflags '-s -w -extldflags "-static"' -o $@ ./cmd/amiscan

install: amiscan
	$(INSTALL) -d $(DESTDIR)$(BINDIR) $(DESTDIR)$(MANDIR)/man1 $(DESTDIR)$(DOCDIR)
	$(INSTALL) -m 755 amiscan $(DESTDIR)$(BINDIR)/amiscan
	$(INSTALL) -m 644 man/amiscan.1 $(DESTDIR)$(MANDIR)/man1/amiscan.1
	$(INSTALL) -m 644 $(wildcard $(DOCS)) $(DESTDIR)$(DOCDIR)/
	@echo
	@echo "Installed. Now run \"amiscan -update\" (as yourself, not root) to fetch the"
	@echo "virus database and unpackers into your own parts folder."

uninstall:
	rm -f $(DESTDIR)$(BINDIR)/amiscan $(DESTDIR)$(MANDIR)/man1/amiscan.1
	rm -rf $(DESTDIR)$(DOCDIR)
	@echo "The parts folder (amiscan -version shows where) is left alone."

test:
	$(GO) vet ./...
	$(GO) test ./...

check: test
	groff -man -ww -z man/amiscan.1

release: amiscan amiscan.exe
	rm -rf dist
	mkdir -p dist/amiscan-$(VERSION)-linux-x86_64/man dist/amiscan-$(VERSION)-windows-x86_64
	cp amiscan $(wildcard $(DOCS)) dist/amiscan-$(VERSION)-linux-x86_64/
	cp man/amiscan.1 dist/amiscan-$(VERSION)-linux-x86_64/man/
	cp amiscan.exe $(wildcard $(DOCS)) dist/amiscan-$(VERSION)-windows-x86_64/
	cd dist && tar -czf amiscan-$(VERSION)-linux-x86_64.tar.gz amiscan-$(VERSION)-linux-x86_64
	cd dist && zip -qr amiscan-$(VERSION)-windows-x86_64.zip amiscan-$(VERSION)-windows-x86_64
	cd dist && sha256sum *.tar.gz *.zip > SHA256SUMS
	@ls -l dist

clean:
	rm -rf amiscan amiscan.exe dist

.PHONY: all install uninstall test check release clean
