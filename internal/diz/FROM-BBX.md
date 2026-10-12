This folder is a copy of `internal/diz` from BBX (github.com/creep-ltx/bbx), commit
8066960de91bc46ef2d758a7e428e8bcc5306200, with the import paths changed. It reads every
archive and disk image format BBX knows, in pure Go.

AmiScan's own addition is `walk.go` (every file inside, nested, plus disk boot blocks).
When fixing a decoder, fix it in BBX too.
