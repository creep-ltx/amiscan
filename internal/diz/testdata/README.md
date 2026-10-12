# Test data

The archives and disk images here were made for testing: they hold the same few
generated files (`FILE_ID.DIZ`, `NUMBERS.TXT`, `RANDOM.BIN`, `README.TXT`), or are
small disk images built for the tests. `pc/golden.txt` lists the members of the
archives with their checksums, as an independent tool unpacked them.

The tests also use about thirty **real-world archives**: old BBS uploads, Aminet
programs, PC shareware and an AMOS Pro disk. They are **not published** with
AmiScan, because nobody has checked that each may be passed on. Without them the
tests that need them skip, saying "not published"; with them (for example in the
author's copy) every test runs. They are listed in `.gitignore`.
