# Using AmiScan from BBX

Run the binary per upload; it is quick (milliseconds plus unpacking) and a
crash in a decoder cannot touch the board.

## The simple way: -bbs

    amiscan -bbs -libs <board>/libs <uploaded file>

prints one line and exits with the same code:

    0 FILE is clean
    1 FILE is infected with VIRUS[, VIRUS...]
    2 FILE is corrupted: WHERE: WHY [(and N more)]
    3 FILE could not be checked: WHERE: WHY [(and N more)]

0 pass, 1 virus (reject or quarantine), 2 corrupted (reject, as AmiExpress
file checkers did with broken archives), 3 could not check (a password, a
missing unpacker, too big; the sysop decides). A file with several problems
gets the worst: virus, then corrupted, then could not check.

## As AmiExpress did it

AmiExpress ignores a checker's exit code: it shows the checker's output to the
uploader and fails the upload if any line contains one of the sysop's ERROR.n words
(Knowledge/bbs/amiexpress-filecheck.md). For the same behaviour, run
`amiscan -bbs`, show the line, and fail on "infected" or "corrupted" (the sysop's
choice); or use the exit status / leading code.

## Everything: -json

One object per finding:

    {"file":"x.lha","path":"x.lha/c/foo","kind":"file","result":"virus","virus":"Saddam","type":"link virus","found_by":"xvs"}
    {"file":"x.adf","path":"x.adf/(boot block)","kind":"boot","result":"clean","type":"Standard bootblock (1.3)"}
    {"file":"x.lha","path":"x.lha/doc.txt","kind":"file","result":"damaged","type":"data file","reason":"lha: CRC mismatch"}
    {"file":"x.xpk","path":"x.xpk (packed contents)","kind":"file","result":"unchecked","reason":"XPK Crypted needs a password to unpack"}

`result` is `clean`, `virus`, `damaged` or `unchecked`. A file unpacked by
xfdmaster appears again as `<path> (unpacked PowerPacker 4.0)`. The last line:

    {"summary":true,"files":12,"bootblocks":1,"unpacked":3,"viruses":0,"damaged":1,"unchecked":0,"seconds":0.01,"exit":2}

Only one emulated Amiga fits in a process, so importing `internal/xvs` into BBX
would need a lock round it; running the binary avoids that.
