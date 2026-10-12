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
   - **xpkmaster.library** and its 16 packer libraries from Aminet
     (<https://aminet.net/util/pack/xpk_User.lha>), for files packed with XPK
     (NUKE, SQSH, IMPL, MASH, RAKE, SHRI and the rest);
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

    amiscan Downloads/                 check a folder; report at the end
    amiscan -bbs upload.lha            one line per file, for BBS software
    amiscan -json upload.lha           machine-readable, one object per finding
    amiscan -show virus Downloads/     list only the viruses
    amiscan -v game.adf                list the clean files too
    amiscan -q Downloads/              only the summary line
    amiscan -list                      the viruses xvs.library knows
    amiscan -version                   what is installed
    amiscan -update                    fetch the newest databases and unpackers

It opens ADF, ADZ, DMS and HDF disk images, and LhA, LZX, Zip, 7z, RAR, ARJ,
ARC, ZOO, CAB, tar and gzip/bzip2/xz archives, also inside each other, by
their contents (a text called `.lha` is a text). It unpacks packed programs
(PowerPacker, Imploder, StoneCracker, XPK, ...) and checks every file and
every floppy's boot block.

### The report

At the end AmiScan lists, grouped by the file on disk, with where inside
and why:

- **Viruses**: the virus name and kind.
- **Damaged**: broken archive members (CRC errors, data cut short) and
  packed programs whose packed data is broken. They were checked as far
  as they unpack, which is what LhA itself would write out.
- **Not checked**: what could not be checked at all, and why (a password,
  a missing unpacker, a size limit).

`-show` picks which of `virus`, `damaged`, `unchecked`, `clean` are listed
(default: the first three); `-v` is `-show all`, `-q` is `-show none`.

### For BBS software: -bbs

Like the file checkers Amiga BBSes used, one line per file:

    0 UPLOAD.LHA is clean
    1 UPLOAD.LHA is infected with Amixhack, BossNuke 1.5ß
    2 UPLOAD.LHA is corrupted: path/inside: lha: CRC mismatch (and 2 more)
    3 UPLOAD.LHA could not be checked: the file itself (packed contents): XPK Crypted needs a password to unpack

The first number is the code: **0** pass, **1** virus, **2** corrupted,
**3** could not check. A file with several problems gets the worst one,
in that order of badness: virus, corrupted, could not check.

### Exit status

The worst code over all files, the same four numbers. **3** also when
AmiScan itself cannot run (no xvs.library, a bad option).

## Limits

- Files up to 1.5 GB are checked whole (the emulated Amiga has 2 GB of fast
  RAM; your PC only spends memory on what a file needs, about twice its
  size while it is checked). Disk images up to 8 GB are opened and their
  files checked one by one.
- A file that is damaged inside its archive (CRC error, data cut short) is
  checked as far as it unpacks, which is what LhA itself would write out.
  The summary counts these; `-v` lists them.
- Without xfdmaster.library, packed programs are checked only as they are.
- A file packed with a password cannot be unpacked; the output says so.

## Thanks

xvs.library is © Georg Wittmann, Alex van Niel and Jan Erik Olausen;
xfdmaster.library © Georg Hörmann and Dirk Stöcker; XPK © Dirk Stöcker,
Christian von Roques, Urban Dominik Müller and others; the boot block database
© Jason and Jordan Smith. None of them is part of AmiScan: each is downloaded
by you from where its authors publish it.
All Amiga code runs inside AmiScan's emulated Amiga, which can only read its
own libs folder. The 68000 is
Musashi by Karl Stenerud. See [NOTICES.md](NOTICES.md).
