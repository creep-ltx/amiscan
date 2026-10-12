# Using AmiScan

    amiscan [options] FILE|FOLDER ...

Options may come before or after the file names. `amiscan -h` lists them;
`man amiscan` describes them all.

## Checking

    amiscan game.adf
    amiscan ~/Downloads ~/Amiga
    amiscan "Mega Demo.dms"

Folders are checked with everything in them. Each file is opened if it is an
archive or disk image (recognised by its contents: a text called `History.lha` is
a text, an LhA archive called `readme.txt` is opened), and so is every archive
or disk image inside it, up to 8 levels deep. Each file found, and each packed
file once unpacked, goes to the virus database, and so does every floppy's boot
block. A 1,024-byte file starting with `DOS` (a boot block saved as a file) is
also checked as a boot block.

## The report

At the end AmiScan lists what it found, grouped by the file on disk, with where
inside it and why:

    Viruses (2):

      /home/me/Downloads/DEC-SCP.LHA
          AmixHack0.Exe (unpacked PowerPacker 4.0): Amixhack (file virus)
          AmixHack1.Exe (unpacked PowerPacker 4.0): Amixhack (file virus)

    Damaged, checked as far as they unpack (1):

      /home/me/Downloads/AFL-UD12.LZX
          _ADD_TO_BBS/dOORS/uPdOWNiNFO/uPdOWNiNFO.000: lzx: CRC mismatch

    Not checked (1):

      /home/me/Downloads/secret.xpk
          the file itself (packed contents): XPK Crypted needs a password to unpack

    Checked 214 files (12 of them unpacked) and 3 boot blocks in 0.3s: 2 VIRUSES, 1 damaged, 1 not checked.

- **Viruses**: the virus and its kind: a *boot virus* lives in a disk's boot block,
  a *file virus* is a program of its own (often a trojan pretending to be something
  useful), a *link virus* has attached itself to another program, a *data virus*
  hides in a data file.
- **Damaged**: an archive member that is broken (CRC error, data that ends early),
  or a packed program whose packed data is broken. AmiScan checks the part that
  unpacks, which is what LhA itself would write out, so a virus in a damaged file
  is still found. Archive entries that hold nothing (the fake entries BBS adverts
  are made of: a name, and a few bytes claiming megabytes of zeros) count as clean.
- **Not checked**: a password, a size limit, a missing part.

`-show` picks what the report lists: `virus`, `damaged`, `unchecked`, `clean`,
`all` or `none` (default the first three). `-v` lists the clean files too, `-q`
only the summary line.

## Saving the report

    amiscan -o report.html ~/Amiga
    amiscan -o report.md ~/Amiga
    amiscan -o report.txt ~/Amiga
    amiscan -o report.json ~/Amiga

The extension picks the format (or `-format`). A saved report also says when the
check ran, what was checked, and which versions of the database and unpackers
were used. The web page follows the system's light or dark mode. The terminal
gets the summary line and where the report went.

## Exit status

The worst result over all files: **0** nothing found, **1** a virus, **2**
something damaged, **3** something not checked, or AmiScan itself could not run
(no database, a bad option). Scripts can use it:

    amiscan -q upload.lha || echo "not clean"

## Limits

| Option | Default | Meaning |
|---|---|---|
| `-max SIZE` | 1536M | the biggest file checked or unpacked into; memory use is about twice this at most |
| `-max-total SIZE` | 8G | how much one file on disk may unpack to in all, and how big an archive or disk image may be (it is read whole) |

Sizes are written like `300M`, `1.5G`, `64K`. A bigger file is reported as not
checked; if it is not an archive or disk image, it is not even read. Archives
nested more than 8 deep, and packed files that would unpack to more than 64 times
their size, are not unpacked further: that is how unpacking bombs are stopped.

## Keeping up to date

    amiscan -update

fetches whatever changed since the last time. AmiScan reminds you when there has
been no update check for 30 days. `-version` shows what is installed.

## Other

    amiscan -list            every virus xvs.library knows, by kind
    amiscan -trace FILE      every call the Amiga code makes (for debugging)
