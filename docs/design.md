# AmiScan design

## Start here

- `make` builds the static binary; `make test` runs vet and tests. The xvs tests
  need `AMISCAN_LIBS=<folder with xvs.library>`; without it they skip.
- Status 0.1b1 (2026-10-12): scanning files, disks and archives works. xvs.library
  33.49 loads, self-tests, and **catches real viruses**: the archive.org collection
  `amiga_virus_collection_research` (1,392 files, 21 MB .7z) gives 1,502 viruses
  (665 link, 326 file, 258 data, 253 boot) in 1.6 s, and the verdict and name of
  every one of its 1,392 files is identical to xvs.library run in vamos (an
  independent emulator). Tests: `AMISCAN_LIBS=... AMISCAN_SAMPLES=<unpacked
  collection> make test`. Download the collection again when needed; never commit
  samples.
- `amiscan -update` (2026-10-12) installs and updates xvs.library (signature-checked),
  xfdmaster.library + LIBS:xfd/ (Aminet) and the Amiga Bootblock Reader database
  (GitHub raw: Resources/Brainfile.txt and bin/Debug/net472/searchbrain.xml, the
  newest copies in that repo as of 2026-10-12).
- xfd (2026-10-12): every checked file is offered to xfdmaster, up to 5 layers.
  Collection: 124 unpacked, +72 viruses. Decrunched StoneCracker 4.04 is byte-identical
  to the collector's unpacked original. CPU is now a 68020 (24-bit bus), AttnFlags
  010|020; all earlier verdicts unchanged.
- Boot block database (2026-10-12): `internal/bootdb` matches like ABR's
  IdentifyBootblock: CRC-32 of the 1024 bytes (CRC field is a comma list of hex
  without leading zeros), then searchbrain byte sequences (base64) anywhere, then
  exactly 7 offset,value pairs. xvs decides first; a database "v" match makes a virus
  only when xvs says not. Collection: +1 (Zevil, in UNKNOWN_TO_ANY.LHA); no false
  alarm on 63 clean boot blocks from the user's disks.
- Next: see "Later" below.

## How it works

    cmd/amiscan        the command: finds xvs.library, walks paths, reports
    internal/xvs       xvs.library's API: CheckFile, CheckBootblock, RepairFile, lists
    internal/amiga     the emulated Amiga: RAM, allocator, exec lists, LoadSeg,
                       InitResident/MakeLibrary/InitStruct, exec + dos calls
    internal/m68k      cgo wrapper round Musashi (vendored, unchanged except
                       M68K_ILLG_HAS_CALLBACK on in m68kconf.h)
    internal/diz       BBX's pure-Go unpackers (copied, see FROM-BBX.md) + walk.go

Guest code calls the Go OS through jump-table entries `ILLEGAL; dc.w trap; RTS`
(trap = library index << 10 | LVO/6). Musashi's illegal-instruction callback
hands the trap to Go. A guest call returns to a stop stub (trap $FFFF); every
exception vector points at its own stub (trap $F000 + vector), so a crash in the
library becomes an `ErrCrash` naming the vector and PC instead of taking the
program down. Every call has a cycle budget, so a loop cannot hang a scan.

Memory map (since 2026-10-12): a 68020 with full 32-bit addresses. "Chip" RAM
$000000-$BE0000 (vectors at 0, stubs at $400, heap from $1000, stacks at the top)
and 2 GB of fast RAM from $01000000. The host reserves it with mmap(MAP_NORESERVE)
so only touched pages cost memory; Free of a block of 1 MB or more madvises it
back (MADV_DONTNEED), and a cleared big Alloc does the same instead of writing
zeros. A panic in a Go OS call (bad guest pointer) is caught and becomes a
failed call, never a dead process. Measured: a 700 MB file checks in 0.4 s,
peak RSS 1.4 GB (the file plus its copy in guest RAM). Reads of $BFxxxx/$DFxxxx return 0
(xvs.library reads VHPOSR at $DFF006/7 for a random number). Anything else
outside RAM reads 0 and is counted.

What xvs.library needs, found by tracing it under vamos (see
`Knowledge/amiga/xvs-virus-scanning-on-linux.md`):

- `trackdisk.device` in the device list and `intuition.library` in the library
  list, or its init refuses to start. Both are fake (every call returns 0).
- `Lock`/`Examine` of `LIBS:xvs.library` (it checks its own file). dos.library
  here sees only LIBS:, read-only.
- Its own memory pools: `Allocate`/`Deallocate` on a MemHeader it builds, so
  those follow exec exactly.

Only one CPU per process (Musashi is global C state). BBX should run one
AmiScan per scan, or one long-lived scanner behind a lock.

## Damaged archives (2026-10-12)

On the user's 61,859-file BBS door collection 255 items were "not checked": 165
were a 112-byte BBS advert LhA claiming 20 MB from 7 bytes, the rest real damage
(the reference `lha t` and `unlzx` report the same errors on every one tested) or
text files merely named .lha. Now the lha/lzx readers return what decoded before
the damage, Walk passes it on with Item.Damaged and it is checked ("checked as far
as it unpacks", like LhA writing out a CRC-error file); extension-only matches are
silent (a real LZX starts "LZX\0"). Result: 5 not checked, 202 damaged-but-checked.
In the virus collection that turned up one more virus (Mpeople.exe, CRC mismatch).
Remaining "not checked" are packed files that are themselves broken (xfdDecrunch
under vamos agrees on EoC.exe) and one XPK file (needs xpkmaster.library).

## Updating (internal/update)

`amiscan -update` fetches each `update.Source` (an LhA archive URL, which members go
to the libs folder, which are PGP-signed and by whom, what it `Needs`). Steps: GET
with If-None-Match/If-Modified-Since; same SHA-256 as last time is "up to date";
unpack with the LhA reader; verify signatures; write to `libs/.update-*/`; run a
second amiscan on that folder (`-libs tmp -version`: one emulated Amiga per
process, so the check is a child process) which must load the library and pass
its self test; refuse an older version; move the old files to `libs/old/`, the
new into place, the archive to `libs/archives/`; state in `amiscan-update.json`.
`Needs` (free key files) are fetched only when their files are missing.

Georg's key is PGP 2 (v3, RSA 1024, MD5 signatures); gpg 2 no longer reads it, so
`pgp2.go` checks it itself. Key ID 650EC4D80A831D77, fingerprint
2B53 8234 CBD3 4C5B 5F71 B8C3 6538 2290, from vht-dk.dk/amiga/xvs/gh-pgp.txt and
identical to Georg.asc in the archive. If he ever signs with a new key, AmiScan
refuses the update until the new key is built in.

HTTPS uses the system's certificates, or Mozilla's built in
(`x/crypto/x509roots/fallback`) on a system without any.

## Licence of the parts

xvs.library may not be altered or passed on except as its whole archive, so it
is never in this repository (`.gitignore` refuses `*.library`) and the user
downloads it. Musashi is MIT-style. See NOTICES.md.

## Later

1. Many "clean" programs in the virus collection are its clean reference copies
   (`*_UN`, `*_ORG`, `*_CLEAN`).
2. ABR's XOR-decoding of encrypted boot blocks (DecodeBB) and its Lamer Exterminator
   5/9 second pass are not copied; xvs knows those viruses anyway.
3. xfd slaves that crash leak guest memory (no reset between files); fine for one
   scan, worth a heap check if BBX keeps one process alive for days.
4. **Repair**: `amiscan -repair` for link viruses via xvsRepairFile (bound in
   internal/xvs, not offered yet).
5. **BBX**: see docs/bbx.md.
