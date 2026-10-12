package diz

import (
	"archive/zip"
	"os"
	"path/filepath"
	"testing"
)

// An archive with only DESC.SDI gets that line, wrapped to 45 columns, as its DIZ.
func TestDescSDI(t *testing.T) {
	p := filepath.Join(t.TempDir(), "DCF32.ZIP")
	f, err := os.Create(p)
	if err != nil {
		t.Fatal(err)
	}
	z := zip.NewWriter(f)
	w, _ := z.Create("DESC.SDI")
	w.Write([]byte("DISK COPY FAST v3.2. VERY fast 1-pass diskette copy utility\r\n"))
	w, _ = z.Create("DCF.EXE")
	w.Write([]byte("MZ"))
	z.Close()
	f.Close()

	res, err := Examine(p, 10)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"DISK COPY FAST v3.2. VERY fast 1-pass", "diskette copy utility"}
	if len(res.DIZ) != 2 || res.DIZ[0] != want[0] || res.DIZ[1] != want[1] {
		t.Fatalf("got %q, want %q", res.DIZ, want)
	}
}
