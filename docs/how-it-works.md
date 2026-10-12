# How AmiScan works

## An Amiga inside

The Amiga's virus checkers are Amiga programs: their knowledge sits in
`xvs.library`, a 68000 shared library that a checker opens and hands each file
to. AmiScan does exactly that, on Linux and Windows:

- a **68020 processor** (Musashi, by Karl Stenerud) with 2 GB of fast RAM, of
  which the computer only spends what a file needs;
- a **small AmigaOS** written in Go: the parts of exec.library, dos.library and
  utility.library these libraries call (memory, lists, semaphores, opening
  libraries, loading programs, reading their own folder, tag lists), and stand-ins
  for the rest;
- the **real libraries**, loaded from the parts folder as AmigaOS would: xvs.library
  for viruses, xfdmaster.library and its 103 decrunchers for packed programs,
  xpkmaster.library and its packers for XPK files.

Nothing in them is changed or reimplemented. When the Virus Help Team adds a
virus to xvs.library, `amiscan -update` brings it in and AmiScan knows it.

To make sure the built-in Amiga gives the same answers as a real one, AmiScan was
compared with xvs.library running in vamos, a separate Amiga emulator: on a
collection of 1,392 Amiga viruses, every verdict and every virus name matched.

## From a file to a verdict

1. **Open:** if the file is an archive or disk image (by its contents), take
   every file out of it, and out of archives inside it. Disk images give their
   boot block too. This part is written in Go (shared with BBX) and never runs
   Amiga code.
2. **Check:** hand each file to xvs.library (`xvsCheckFile`), each boot block too
   (`xvsCheckBootblock`).
3. **Unpack:** offer each file to xfdmaster.library. If it knows the packer, the
   unpacked file is checked again, and unpacked again if it was packed twice.
4. **Second opinion on boot blocks:** the Amiga Bootblock Reader database, by
   CRC-32, byte sequences and its seven-point patterns, as that program does.
5. **Report**: the worst result decides a file's verdict.

## Safety

- The files being checked are **never run**. They are data handed to the virus
  database and the unpackers, as on an Amiga with a virus checker.
- The Amiga code can read its parts folder and **nothing else** on the computer;
  it cannot write anywhere.
- Every call into Amiga code has a **time limit**; a crash or a bad pointer in it
  becomes an error for that file, not a crashed AmiScan.
- Limits stop **unpacking bombs**: per file, per upload, nesting depth, and how
  much a packed file may grow.
- `xvs.library` updates are checked against **Georg Wittmann's signature**, built
  into AmiScan. The other parts come over HTTPS from Aminet and GitHub, and every
  new part must load and pass a test before it replaces the old one.

## What it cannot do

- Files packed **with a password** cannot be unpacked; they are reported.
- Packers that neither xfdmaster nor XPK knows: such files are checked as they are.
- Viruses **nobody has described** yet: AmiScan knows what xvs.library and the boot
  block database know. Send new viruses to the Virus Help Team.
- It does not **remove** viruses. (xvs.library can repair some link viruses; AmiScan
  may offer that one day.)
