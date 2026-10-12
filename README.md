# AmiScan

Checks Amiga files, disk images and archives for Amiga viruses, on Linux.

AmiScan is one program file. It runs the Amiga's own virus database,
**xvs.library** by Georg Wittmann (the one VirusZ III, VirusExecutor and
VirusChecker II use), in a built-in 68000 processor. Nothing else needs to be
installed.

## Setting up

1. Put `amiscan` anywhere on your path, e.g. `~/.local/bin/`.
2. Download **xvs.library** from the Virus Help Team:
   <https://www.vht-dk.dk/amiga/xvs/xvs.htm> (the `xvslibrary.lha` archive).
3. Take `xvs/libs/xvs.library` out of the archive and put it in
   `~/.local/share/amiscan/libs/`.

AmiScan looks for xvs.library in these folders, first one wins:

- the folder named with `-libs`
- `$AMISCAN_LIBS`
- `~/.local/share/amiscan/libs` (`$XDG_DATA_HOME/amiscan/libs`)
- `libs/` next to the `amiscan` program
- `/usr/local/share/amiscan/libs`, `/usr/share/amiscan/libs`

When a new xvs.library comes out, replace the file. That is the whole update.

## Using it

    amiscan Downloads/                 check a folder
    amiscan -v game.adf                list every file checked
    amiscan -list                      the viruses xvs.library knows
    amiscan -version                   which xvs.library is in use
    amiscan -json upload.lha           machine-readable, one line per file

It opens ADF, ADZ, DMS and HDF disk images, and LhA, LZX, Zip, 7z, RAR, ARJ,
ARC, ZOO, CAB, tar and gzip/bzip2/xz archives, also inside each other, and
checks every file in them and every floppy's boot block.

Exit status: **0** nothing found, **1** a virus found, **2** something could
not be checked (named in the output).

## Limits

- Files bigger than 4 MB are not checked (they do not fit in the emulated
  Amiga's memory). They are named in the output.
- Packed (crunched) programs are checked as they are; a virus inside a
  PowerPacker or Imploder file is not seen yet.

## Thanks

xvs.library is © Georg Wittmann, Alex van Niel and Jan Erik Olausen. It is
freeware, not part of AmiScan, and you download it yourself. The 68000 is
Musashi by Karl Stenerud. See [NOTICES.md](NOTICES.md).
