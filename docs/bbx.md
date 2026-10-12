# Using AmiScan from BBX

Simplest, and safe if a decoder or the emulator ever crashes: run the binary.

    amiscan -json -libs <board>/libs <uploaded file>

Each line is one JSON object:

    {"path":"x.lha/c/foo","kind":"file","result":"virus","virus":"Saddam","type":"link virus"}
    {"path":"x.adf/(boot block)","kind":"boot","result":"clean","type":"Standard bootblock (1.3)"}
    {"path":"x.lha/big.mod","kind":"file","result":"skipped","detail":"bigger than 4 MB, too big for xvs.library"}

A virus line carries `"found_by":"xvs"` or `"found_by":"bootblock database"`.
A file unpacked by xfdmaster appears again as `<path> (unpacked PowerPacker 4.0)`;
one that will not unpack as `<path> (packed contents)` with result `skipped`.

and the last is a summary:

    {"summary":true,"files":12,"bootblocks":1,"unpacked":3,"viruses":0,"skipped":0,"errors":0,"seconds":0.01,"exit":0}

Exit status 0 clean, 1 virus (reject or quarantine the upload), 2 something not
checked (sysop decides). A scan of a typical upload takes a few milliseconds plus
unpacking.

Later, BBX can import `internal/xvs` directly (move it out of `internal/`), but
only one scanner can exist per process, so it needs a lock round it.
