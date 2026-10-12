# AmiScan design

## Start here

- `make` builds the static binary; `make test` runs vet and tests. The xvs tests
  need `AMISCAN_LIBS=<folder with xvs.library>`; without it they skip.
- Status 0.1b1 (2026-10-12): scanning files, disks and archives works; xvs.library
  33.49 loads, self-tests, lists its 379/15/382/107 viruses, tells programs,
  data and boot block kinds apart. **Not yet seen to catch a real virus**: no
  infected sample found yet. That is the first thing to do.
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

Memory map: RAM $000000-$BE0000 (24-bit, 68000). Vectors at 0, stubs at $400,
heap $1000 up to the stacks at the top. Reads of $BFxxxx/$DFxxxx return 0
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

## Licence of the parts

xvs.library may not be altered or passed on except as its whole archive, so it
is never in this repository (`.gitignore` refuses `*.library`) and the user
downloads it. Musashi is MIT-style. See NOTICES.md.

## Later

1. **A real positive**: find infected samples (VHT, the user's old disks) and add
   a test that names the virus. Without that, a wrong flag in the boot or file
   check would go unnoticed.
2. **VirusZ_III.Bootblocks** (VHT, 1,981 harmless boot blocks by name): read its
   brain format and name known harmless boot blocks instead of "unknown".
3. **Crunched programs**: run xfdmaster.library (Aminet util/pack/xfdmaster.lha,
   plus its LIBS:xfd/ slaves) in the same machine to unpack before checking,
   as VirusZ does. Needs dos `ExNext`/`LoadSeg` for the slaves.
4. **Repair**: `amiscan -repair` for link viruses via xvsRepairFile (bound in
   internal/xvs, not offered yet).
5. **BBX**: see docs/bbx.md.
