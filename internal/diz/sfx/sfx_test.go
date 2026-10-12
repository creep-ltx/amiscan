package sfx

import (
	"os"
	"path/filepath"
	"testing"
)

// Self-extractors: real ones (LhA, PAK) and our own 512-byte DOS stub with
// an archive appended, as "copy /b stub.exe+archive" makes them.
func TestScan(t *testing.T) {
	cases := map[string]Found{
		"QG2IMPRT.EXE":    {"lha", -1},
		"PAK251.EXE":      {"arc", 6867},
		"sfx-arj-m1.exe":  {"arj", 512},
		"sfx-rar5.exe":    {"rar", 512},
		"sfx-zoo-lh5.exe": {"zoo", 512},
		"sfx-crunch.exe":  {"arc", 512},
		"sfx-seven.exe":   {"7z", 512},
		"sfx-cab.exe":     {"cab", 512},
	}
	for name, want := range cases {
		if !present(filepath.Join("..", "testdata", "pc", name)) {
			t.Logf("%s is not published, skipped", name)
			continue
		}
		f, err := os.Open(filepath.Join("..", "testdata", "pc", name))
		if err != nil {
			t.Fatal(err)
		}
		st, _ := f.Stat()
		got := Scan(f, st.Size())
		f.Close()
		if len(got) == 0 || got[0].Kind != want.Kind || want.Offset >= 0 && got[0].Offset != want.Offset {
			t.Errorf("%s: %v, want %v", name, got, want)
		}
	}
}

func TestNotExe(t *testing.T) {
	f, err := os.Open(filepath.Join("..", "testdata", "pc", "rar5.rar"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	st, _ := f.Stat()
	if got := Scan(f, st.Size()); got != nil {
		t.Errorf("a plain RAR scanned as a program: %v", got)
	}
}
