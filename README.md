# AmiScan

**An Amiga virus scanner for Linux and Windows.** It checks files, folders, Amiga
disk images and archives for boot, file, link and data viruses, and it was made
for checking uploads on Amiga-style BBSes the way Amiga file checkers did.

AmiScan doesn't imitate a virus checker. It runs the Amiga's own virus database,
**xvs.library**, the same one VirusZ III, VirusExecutor and VirusChecker II use,
unchanged, inside a 68020 processor and a small AmigaOS that are built into the
program. One file, nothing else to install.

```
$ amiscan ~/Amiga/BBS
AmiScan 0.1b1 with xvs 33.49 (11.04.2025)

Viruses (15):

  /home/me/Amiga/BBS/BBS Doors/AmiExpress/DEC-SCP.LHA
      AmixHack0.Exe (unpacked PowerPacker 4.0): Amixhack (file virus)
  /home/me/Amiga/BBS/BBS Doors/AmiExpress/SMK-STAT.LHA
      smk-stats/smk-statsv0.1: HappyNewYear 96 (link virus)
  ...

Damaged, checked as far as they unpack (49):

  /home/me/Amiga/BBS/BBS Doors/AmiExpress/AFL-UD12.LZX
      _ADD_TO_BBS/dOORS/uPdOWNiNFO/uPdOWNiNFO.000: lzx: CRC mismatch
  ...

Checked 105508 files (532 of them unpacked) and 8 boot blocks in 18.4s: 15 VIRUSES, 49 damaged.
```

## What it does

- **Opens everything:** ADF, ADZ, DMS and HDF disk images; LhA, LZX, Zip, 7z, RAR,
  ARJ, ARC, ZOO, CAB, tar, gzip, bzip2 and xz archives, also inside each other.
  Formats are recognised by their contents, not their names.
- **Unpacks packed programs** (PowerPacker, Imploder, StoneCracker, CrunchMania,
  XPK and about a hundred more) with the Amiga's own xfdmaster and xpkmaster
  libraries, and checks what is inside.
- **Checks every boot block** with xvs.library, with a second opinion from the
  Amiga Bootblock Reader database (3,040 boot blocks).
- **Says what it could not check, and why:** damaged archive members are checked
  as far as they unpack; passwords, size limits and missing parts are reported,
  never passed as clean.
- **Reports** on the terminal, or saved as text, Markdown, HTML or JSON.
- **BBS mode:** one line per upload with a code, as Amiga BBS file checkers did:
  `0` clean, `1` virus, `2` corrupted, `3` could not check.
- **Keeps itself current:** `amiscan -update` fetches the newest virus database and
  unpackers from where their authors publish them, checks the signature of
  xvs.library and tries every new part before it replaces the old one.

## Quick start

1. Download `amiscan` (Linux) or `amiscan.exe` (Windows) from the
   [releases](https://github.com/creep-ltx/amiscan/releases), or build it (below).
2. Fetch the virus database and unpackers:

       amiscan -update

3. Check something:

       amiscan ~/Downloads
       amiscan -o report.html ~/Amiga        # the report as a web page
       amiscan -bbs upload.lha               # one line, for BBS software

`amiscan -h` lists the options; `man amiscan` explains everything.

## Building and installing

You need Go 1.26 or newer and a C compiler.

    make
    sudo make install          # program, manual page, documentation
    amiscan -update            # as yourself: parts go to your own folder

`make amiscan.exe` cross-builds for Windows with MinGW. See
[docs/installing.md](docs/installing.md) for all of it, including macOS.

## Documentation

| | |
|---|---|
| [Installing](docs/installing.md) | binaries, building, `make install`, the parts folder, Windows and macOS |
| [Using AmiScan](docs/using.md) | checking, the report, output formats, limits, examples |
| [For BBS software](docs/bbs.md) | `-bbs` and `-json`, exit codes, AmiExpress-style checking, safe limits |
| [How it works](docs/how-it-works.md) | the emulated Amiga, the parts, safety, what is and is not checked |
| [Developing](docs/developing.md) | the code, tests, test samples, adding formats and parts |
| [Manual page](man/amiscan.1) | `man amiscan` |

## The parts

AmiScan contains none of these; `amiscan -update` downloads each one from where
its authors publish it:

| Part | What it does | From |
|---|---|---|
| xvs.library | the virus database (379 boot, 382 file, 107 link, 15 data viruses in 33.49) | [Virus Help Team](https://www.vht-dk.dk/amiga/xvs/xvs.htm), Georg Wittmann |
| xfdmaster.library | unpacks packed programs | [Aminet](https://aminet.net/package/util/pack/xfdmaster), Georg Hörmann, Dirk Stöcker |
| xpkmaster.library | unpacks XPK files | [Aminet](https://aminet.net/package/util/pack/xpk_User), Dirk Stöcker and others |
| boot block database | names boot blocks, knows more boot viruses | [Amiga Bootblock Reader](https://github.com/jasonthesmith79/AmigaBootBlockReader), Jason and Jordan Smith |

## Thanks

To Georg Wittmann and the Virus Help Team, who still keep xvs.library up to date
after 30 years; to Georg Hörmann and Dirk Stöcker for xfd and XPK; to Jason and
Jordan Smith for the Amiga Bootblock Reader; and to Karl Stenerud for Musashi,
the 68000 inside AmiScan. See [NOTICES.md](NOTICES.md).

## Licence

AmiScan is free software under the [MIT licence](LICENSE), © 2026 Tobias Karlsson.
The parts it downloads keep their own licences: they are freeware for
non-commercial use, and each user fetches them from their authors.
