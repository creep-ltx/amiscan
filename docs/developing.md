# Developing AmiScan

## The code

    cmd/amiscan        the command: options, scanning, reports, -bbs, updating
    internal/amiga     the emulated Amiga: memory, exec/dos/utility, LoadSeg, libraries
    internal/m68k      Go wrapper round Musashi (vendored in musashi/)
    internal/xvs       xvs.library's API: CheckFile, CheckBootblock, lists, repair
    internal/xfd       xfdmaster.library: Decrunch (XPK through it too)
    internal/bootdb    the Amiga Bootblock Reader database and its matching
    internal/update    -update: sources, downloads, PGP 2 signatures, installing
    internal/diz       archive and disk image readers (from BBX), and walk.go
    man/amiscan.1      the manual page
    tools/             developer tools (struct offsets, .fd names)

[design.md](design.md) has the design notes: how guest code calls Go (traps), how
libraries are loaded while Amiga code runs (continuations), the memory map,
what each library needed, and the findings behind each decision.

## Building and testing

    make            # ./amiscan
    make test       # go vet, go test
    make check      # also lints the manual page with groff

Most tests need nothing. Those that run the real libraries skip unless you point
them at a parts folder, and the strongest ones need Amiga viruses:

| Variable | Enables |
|---|---|
| `AMISCAN_LIBS=~/.local/share/amiscan/libs` | the tests against xvs.library, xfdmaster, xpkmaster (every XPK packer is packed and unpacked) and the boot block database |
| `AMISCAN_SAMPLES=DIR` | known viruses must be found by name; `DIR` is the unpacked [Amiga Virus Collection Research](https://archive.org/details/amiga_virus_collection_research) from archive.org |
| `AMISCAN_XVS_ARCHIVE=DIR` | Georg Wittmann's signature on the unpacked `xvslibrary.lha` |
| `AMISCAN_XPK_SAMPLE=FILE` | an XPK file must unpack to the size its header gives |

Never commit virus samples or the third-party libraries (`.gitignore` refuses
`*.library`).

Developer switches: `-trace` logs every OS call the Amiga code makes;
`AMISCAN_CPUPROFILE=file` writes a Go CPU profile.

## When an Amiga library needs more of AmigaOS

Run it with `-trace`: calls AmiScan does not have show as `not emulated, returning
0`. Add the call to `internal/amiga` (exec.go, dos.go, utility.go) following the
ROM's behaviour; `fdNames` knows every function's name. A call that must run Amiga
code (a library's init, a hook) uses `guestCall` and `osReturn`.

## Releases

    make release

builds `dist/` with the Linux and Windows archives and `SHA256SUMS`. Tagging
`vX.Y` on GitHub builds the same plus the macOS programs and publishes a release.
