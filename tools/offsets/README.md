`offs.c` prints `internal/amiga/offsets.go` from the NDK headers. Build it with the Amiga
cross compiler and run it on any Amiga (or vamos):

    m68k-amigaos-gcc -O1 -noixemul -o offs offs.c && vamos ./offs > ../../internal/amiga/offsets.go && gofmt -w ../../internal/amiga/offsets.go

Developers only; nothing here is needed to build or run AmiScan.
