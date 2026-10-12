package rardecode

import "os"

// present reports whether a test file is here. The real-world archives
// (old BBS uploads, Aminet programs) are not published with AmiScan; the
// tests that need them skip without them. See testdata/README.md.
func present(path string) bool { _, err := os.Stat(path); return err == nil }
