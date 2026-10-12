# AmiScan

Checks Amiga files, disk images and archives for Amiga viruses, on Linux.

AmiScan is one program file. It runs the Amiga's own virus database,
**xvs.library** by Georg Wittmann (the one VirusZ III, VirusExecutor and
VirusChecker II use), in a built-in 68000 processor. Nothing else needs to be
installed.

## Setting up

1. Put `amiscan` anywhere on your path, e.g. `~/.local/bin/`.
2. Run `amiscan -update`. It downloads into `~/.local/share/amiscan/libs/`:
   - **xvs.library**, the virus database, from the Virus Help Team
     (<https://www.vht-dk.dk/amiga/xvs/xvs.htm>);
   - **xfdmaster.library** and its 103 decrunchers from Aminet
     (<https://aminet.net/util/pack/xfdmaster.lha>), so that programs packed
     with PowerPacker, Imploder, StoneCracker, CrunchMania and the like are
     unpacked and their insides checked too;
   - the **boot block database** of Amiga Bootblock Reader (Jason and Jordan
     Smith, <https://github.com/jasonthesmith79/AmigaBootBlockReader>): 3,040
     boot blocks and 314 byte patterns, a second opinion on boot blocks
     (it knows some boot viruses xvs.library does not) and names for the
     harmless ones (intros, logos, utilities).

Run `amiscan -update` now and then (AmiScan reminds you after 30 days). It
only downloads when the Virus Help Team has published something new, and it
installs a new xvs.library only when:

- it carries Georg Wittmann's signature, checked against his key built into
  AmiScan (a changed or fake library is refused),
- it loads and passes its own self test,
- it is not older than the one you have.

Only the xvs.library download is signed; the others come over HTTPS from
Aminet and GitHub, are tried before they replace anything, and their code
only ever runs inside AmiScan's emulated Amiga. The previous files are kept
in `libs/old/`, the archives as published in `libs/archives/`. If a library ever needs a key file (xvs.library does not),
`-update` fetches that too when it is missing.

You can also install xvs.library by hand: take `xvs/libs/xvs.library` out of
`xvslibrary.lha` and put it in the libs folder. AmiScan looks in these
folders, first one wins:

- the folder named with `-libs`
- `$AMISCAN_LIBS`
- `~/.local/share/amiscan/libs` (`$XDG_DATA_HOME/amiscan/libs`)
- `libs/` next to the `amiscan` program
- `/usr/local/share/amiscan/libs`, `/usr/share/amiscan/libs`

## Using it

    amiscan Downloads/                 check a folder
    amiscan -v game.adf                list every file checked
    amiscan -list                      the viruses xvs.library knows
    amiscan -version                   which xvs.library is in use
    amiscan -update                    fetch the newest xvs.library
    amiscan -json upload.lha           machine-readable, one line per file

It opens ADF, ADZ, DMS and HDF disk images, and LhA, LZX, Zip, 7z, RAR, ARJ,
ARC, ZOO, CAB, tar and gzip/bzip2/xz archives, also inside each other, and
checks every file in them and every floppy's boot block.

Exit status: **0** nothing found, **1** a virus found, **2** something could
not be checked (named in the output).

## Limits

- Files bigger than 4 MB are not checked (they do not fit in the emulated
  Amiga's memory). They are named in the output.
- Without xfdmaster.library, packed programs are checked only as they are.
- A file packed with a password cannot be unpacked; the output says so.

## Thanks

xvs.library is © Georg Wittmann, Alex van Niel and Jan Erik Olausen;
xfdmaster.library © Georg Hörmann and Dirk Stöcker; the boot block database
© Jason and Jordan Smith. None of them is part of AmiScan: each is downloaded
by you from where its authors publish it.
All Amiga code runs inside AmiScan's emulated Amiga, which can only read its
own libs folder. The 68000 is
Musashi by Karl Stenerud. See [NOTICES.md](NOTICES.md).
