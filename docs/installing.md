# Installing AmiScan

AmiScan is one program file. It needs nothing else installed: no Amiga
emulator, no Python, no libraries. What it does need, the virus database and
the unpackers, it downloads itself with `amiscan -update`.

## Ready-made programs

The [releases](https://github.com/creep-ltx/amiscan/releases) have:

- `amiscan-VERSION-linux-x86_64.tar.gz`: a static Linux program that runs on any
  distribution, with the manual page and documentation;
- `amiscan-VERSION-windows-x86_64.zip`: `amiscan.exe` for Windows 10 and 11;
- macOS programs for Apple Silicon and Intel Macs.

`SHA256SUMS` lists their checksums.

Put the program anywhere on your path (`~/.local/bin`, `/usr/local/bin`, a folder
in Windows' `PATH`), then:

    amiscan -update
    amiscan -version

## Building from source

You need **Go 1.26 or newer** and a **C compiler** (gcc or clang): the 68000
processor inside AmiScan, Musashi, is written in C.

    git clone https://github.com/creep-ltx/amiscan
    cd amiscan
    make            # builds ./amiscan
    make test       # optional

### make install

    sudo make install

installs

| What | Where |
|---|---|
| the program | `/usr/local/bin/amiscan` |
| the manual page | `/usr/local/share/man/man1/amiscan.1` |
| README, licence, documentation | `/usr/local/share/doc/amiscan/` |

`PREFIX=/usr` (or `BINDIR`, `MANDIR`, `DOCDIR`) changes the places; `DESTDIR` is
for packagers (`make install PREFIX=/usr DESTDIR=/tmp/pkg`). `sudo make uninstall`
removes them again.

Then run `amiscan -update` **as yourself**, not as root: the parts go into your
own parts folder.

### Windows

Build on Linux with MinGW (Arch, CachyOS: `pacman -S mingw-w64-gcc`; Debian,
Ubuntu: `apt install gcc-mingw-w64-x86-64`):

    make amiscan.exe

The result is one static `amiscan.exe`. Wine runs it too, for testing.

### macOS

On a Mac with Go and the Xcode command line tools (`xcode-select --install`):

    make

macOS does not allow fully static programs, so the Mac build uses the system's
own library and nothing else.

## The parts folder

`amiscan -update` puts the virus database and the unpackers in:

| System | Folder |
|---|---|
| Linux | `~/.local/share/amiscan/libs` (or `$XDG_DATA_HOME/amiscan/libs`) |
| Windows | `%AppData%\AmiScan\libs` |
| macOS | `~/Library/Application Support/AmiScan/libs` |

AmiScan uses the first of these that holds `xvs.library`: the folder named with
`-libs`; `$AMISCAN_LIBS`; the folder above; a `libs` folder next to the program
(handy on a USB stick); `/usr/local/share/amiscan/libs`; `/usr/share/amiscan/libs`.
For a system-wide installation, run `amiscan -update -libs /usr/local/share/amiscan/libs`
as root once, and again for updates.

After an update the folder holds:

| File | What it is |
|---|---|
| `xvs.library` | the virus database |
| `xfdmaster.library`, `xfd/` | the unpacker and its 103 decrunchers |
| `xpkmaster.library`, `compressors/` | XPK and its 16 packer libraries |
| `abr-brainfile.xml`, `abr-searchbrain.xml` | the boot block database |
| `archives/` | the archives as downloaded |
| `old/` | the previous version of each part |
| `amiscan-update.json` | what was fetched when |

You can also fill it by hand: take the files out of `xvslibrary.lha`,
`xfdmaster.lha` and `xpk_User.lha` (the `Libs` folders) and put them there.
Amiga file names with characters Windows forbids (`?`, `*`, `:`...) are stored
with those characters written as `%3F` and so on.
