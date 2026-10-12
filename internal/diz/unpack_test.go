package diz

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// TestUnpack: every file of real LHA and LZX archives comes out whole, the same bytes as
// lha (Lhasa) gives, when it is installed; a limit stops a big archive.
func TestUnpack(t *testing.T) {
	tested := 0
	for _, name := range []string{"5D-BCHCK.LHA", "quicksketch.lha", "config03.lzx"} {
		src := filepath.Join("testdata", name)
		if !present(src) {
			t.Logf("%s is not published, skipped", name)
			continue
		}
		tested++
		dest := t.TempDir()
		files, err := Unpack(src, dest, 64<<20)
		if err != nil || len(files) == 0 {
			t.Fatalf("%s: %v %v", name, files, err)
		}
		entries, _, _ := Contents(src)
		sizes := map[string]int64{}
		for _, e := range entries {
			sizes[e.Name] = e.Size
		}
		for _, f := range files {
			st, err := os.Stat(filepath.Join(dest, filepath.FromSlash(f)))
			if err != nil || (sizes[f] >= 0 && st.Size() != sizes[f]) {
				t.Errorf("%s: %s is %v bytes, the archive says %d (%v)", name, f, st.Size(), sizes[f], err)
			}
		}
		if lha, err := exec.LookPath("lha"); err == nil && filepath.Ext(name) != ".lzx" {
			ref := t.TempDir()
			abs, _ := filepath.Abs(src)
			if out, err := exec.Command(lha, "xqw="+ref, abs).CombinedOutput(); err != nil {
				t.Fatalf("lha: %v %s", err, out)
			}
			for _, f := range files {
				a, _ := os.ReadFile(filepath.Join(dest, filepath.FromSlash(f)))
				b, err := os.ReadFile(filepath.Join(ref, filepath.FromSlash(f)))
				if err != nil || !bytes.Equal(a, b) {
					t.Errorf("%s: %s differs from lha's (%v)", name, f, err)
				}
			}
		}
		if _, err := Unpack(src, t.TempDir(), 10); err == nil {
			t.Errorf("%s: unpacked past a 10-byte limit", name)
		}
	}
	if tested == 0 {
		t.Skip("none of the real archives is published; see testdata/README.md")
	}
}
