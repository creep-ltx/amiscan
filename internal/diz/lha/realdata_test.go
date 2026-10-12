package lha

import (
	"os"
	"testing"
)

// present reports whether a test file is here. The real-world archives
// (old BBS uploads, Aminet programs) are not published with AmiScan; the
// tests that need them skip without them. See testdata/README.md.
func present(path string) bool { _, err := os.Stat(path); return err == nil }

// needReal skips the test unless every one of the real-world files is here.
func needReal(t *testing.T, paths ...string) {
	t.Helper()
	for _, p := range paths {
		if !present(p) {
			t.Skipf("%s is not published; see testdata/README.md", p)
		}
	}
}
