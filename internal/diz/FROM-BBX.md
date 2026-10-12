This folder is a copy of `internal/diz` from BBX (github.com/creep-ltx/bbx), with the import
paths changed. It reads every archive and disk image format BBX knows, in pure Go.

In step with BBX commit 5ebe2e9 (2026-10-12): BBX took back AmiScan's decoder fixes (LhA
and LZX give what unpacked before the damage, the error names the member), so the decoders
are the same on both sides. The first copy was BBX commit 8066960. The tests differ on
purpose: AmiScan's skip when the unpublished real archives are missing; BBX has them.

The real-world test archives are not published (testdata/README.md); the
tests skip without them.

AmiScan's own addition is `walk.go` (every file inside, nested, plus disk boot blocks).
When fixing a decoder, fix it in BBX too.
