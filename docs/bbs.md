# AmiScan for BBS software

Amiga BBSes checked every upload with a file checker: is the archive whole, is
there a virus in it? AmiScan does that job for BBS software on Linux and Windows,
such as BBX. Run the program once per upload: it
takes milliseconds plus the unpacking, and a crash in a decoder cannot touch the
board.

## One line per upload: -bbs

    amiscan -bbs -max 300M -max-total 1G /path/to/UPLOAD.LHA

prints one line and exits with the same number:

    0 UPLOAD.LHA is clean
    1 UPLOAD.LHA is infected with Amixhack, BossNuke 1.5ß
    2 UPLOAD.LHA is corrupted: docs/readme.txt: lha: CRC mismatch (and 2 more)
    3 UPLOAD.LHA could not be checked: the file itself (packed contents): XPK Crypted needs a password to unpack

| Code | Meaning | What a board usually does |
|---|---|---|
| 0 | clean | accept |
| 1 | a virus | reject or quarantine, tell the sysop |
| 2 | corrupted: a broken archive or packed file | reject, as Amiga boards did with broken archives |
| 3 | could not be checked: a password, a missing part, too big | hold for the sysop |

A file with several problems gets the worst one: a virus, then corrupted, then
could not be checked. Code 3 is also used when AmiScan itself cannot run (no
database), so a broken installation never passes an upload.

## As AmiExpress did it

AmiExpress ignored a checker's exit code. It showed the checker's output to the
uploader and failed the upload if any line contained one of the sysop's
`ERROR.n` words. With AmiScan that works the same: show the `-bbs` line, and fail
on `infected` or `corrupted` (or `could not`).

## Everything: -json

    amiscan -json UPLOAD.LHA

prints one JSON object per file and boot block checked, then a summary:

    {"file":"UPLOAD.LHA","path":"UPLOAD.LHA/c/foo","kind":"file","result":"virus","virus":"Saddam","type":"link virus","found_by":"xvs"}
    {"file":"DISK.ADF","path":"DISK.ADF/(boot block)","kind":"boot","result":"clean","type":"Standard bootblock (1.3)"}
    {"file":"UPLOAD.LHA","path":"UPLOAD.LHA/doc.txt","kind":"file","result":"damaged","type":"data file","reason":"lha: CRC mismatch"}
    {"file":"X.XPK","path":"X.XPK (packed contents)","kind":"file","result":"unchecked","reason":"XPK Crypted needs a password to unpack"}
    {"summary":true,"files":12,"bootblocks":1,"unpacked":3,"viruses":0,"damaged":1,"unchecked":0,"seconds":0.01,"exit":2}

| Field | |
|---|---|
| `file` | the file on disk |
| `path` | the file on disk, then where inside it; `(unpacked PACKER)` after a name means its unpacked contents, `(packed contents)` a packed file that would not unpack, `(boot block)` a disk's boot block |
| `kind` | `file` or `boot` |
| `result` | `clean`, `virus`, `damaged` or `unchecked` |
| `virus`, `type` | the virus and its kind; for clean items what the file is |
| `reason` | why damaged or unchecked |
| `found_by` | `xvs` or `bootblock database` |

## Safe settings for uploads from strangers

- `-max 300M -max-total 1G` keeps one check under about 1.6 GB of memory.
- Run `amiscan -update` daily from cron (or a timer) as the board's user.
- Give the board its own parts folder with `-libs`, so an update by hand
  elsewhere does not change the board under it.
- One AmiScan process per upload is safe to run in parallel.
