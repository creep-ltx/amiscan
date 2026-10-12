package arc

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func pc(name string) string { return filepath.Join("..", "testdata", "pc", name) }

// golden reads testdata/pc/golden.txt: archive -> member -> sha256, as
// extracted by independent tools ("*" holds the synthetic archives' sources).
func golden(t *testing.T) map[string]map[string]string {
	t.Helper()
	b, err := os.ReadFile(pc("golden.txt"))
	if err != nil {
		t.Fatal(err)
	}
	g := map[string]map[string]string{}
	for _, l := range strings.Split(string(b), "\n") {
		f := strings.Split(l, "\t")
		if len(f) < 4 || strings.HasPrefix(l, "#") {
			continue
		}
		if g[f[0]] == nil {
			g[f[0]] = map[string]string{}
		}
		g[f[0]][strings.ToLower(f[1])] = f[3]
	}
	return g
}

func sum(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }

func openAt(t *testing.T, name string, off int64) *Reader {
	t.Helper()
	b, err := os.ReadFile(pc(name))
	if err != nil {
		t.Fatal(err)
	}
	b = b[off:]
	r, err := NewReader(bytes.NewReader(b), int64(len(b)))
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return r
}

// Methods 2, 3, 4, 8 and 9 (made by ARC 5.21) and 6 (an old CP/M-era
// archive) byte for byte as the sources or as nomarch extracts them; PAK's
// crushed (10) and distilled (11) by their CRC (no other extractor here).
func TestMembers(t *testing.T) {
	g := golden(t)
	methods := map[int]int{}
	cases := []struct {
		name string
		off  int64
		want map[string]string
	}{
		{"crunch.arc", 0, g["*"]},
		{"squash.arc", 0, g["*"]},
		{"2001.ARC", 0, g["2001.ARC"]},
		{"SIL2.ARC", 0, g["SIL2.ARC"]},
		{"ARC2PAK1.PAK", 0, nil},
		{"PAK251.EXE", 6867, nil}, // PAK's own self-extractor
	}
	skipped := 0
	for _, c := range cases {
		if !present(pc(c.name)) {
			t.Logf("%s is not published, skipped", c.name)
			skipped++
			continue
		}
		r := openAt(t, c.name, c.off)
		for _, f := range r.Files {
			out, err := r.ReadFile(f, 0) // checks the CRC
			if err != nil {
				t.Errorf("%s: %s: %v", c.name, f.Name, err)
				continue
			}
			if c.want != nil && sum(out) != c.want[strings.ToLower(f.Name)] {
				t.Errorf("%s: %s differs", c.name, f.Name)
			}
			methods[f.Method]++
		}
	}
	if skipped > 0 {
		t.Skipf("%d real archives are not published, so not every method was tested; see testdata/README.md", skipped)
	}
	for _, m := range []int{2, 3, 4, 6, 8, 9, 10, 11} {
		if methods[m] == 0 {
			t.Errorf("no method %d member tested", m)
		}
	}
}

func TestLimit(t *testing.T) {
	needReal(t, pc("PAK251.EXE"))
	r := openAt(t, "PAK251.EXE", 6867)
	for _, f := range r.Files {
		full, err := r.ReadFile(f, 0)
		if err != nil {
			t.Fatal(err)
		}
		part, err := r.ReadFile(f, 300)
		if err != nil || !bytes.Equal(part, full[:min(300, len(full))]) {
			t.Errorf("%s (method %d): limited read %d bytes, %v", f.Name, f.Method, len(part), err)
		}
	}
}

func TestVerify(t *testing.T) {
	needReal(t, pc("PAK251.EXE"))
	b, _ := os.ReadFile(pc("PAK251.EXE"))
	if !Verify(bytes.NewReader(b), 6867, int64(len(b))) {
		t.Error("PAK251.EXE: archive at 6867 not verified")
	}
	if Verify(bytes.NewReader(b), 6868, int64(len(b))) {
		t.Error("PAK251.EXE: verified one byte off")
	}
}

// Damaged archives must never panic or hang.
func TestCorrupt(t *testing.T) {
	for _, name := range []string{"crunch.arc", "squash.arc", "ARC2PAK1.PAK", "SIL2.ARC", "2001.ARC"} {
		if !present(pc(name)) {
			t.Logf("%s is not published, skipped", name)
			continue
		}
		orig, _ := os.ReadFile(pc(name))
		for i := 0; i < 300; i++ {
			b := append([]byte{}, orig...)
			seed := uint32(i*2654435761 + 1)
			for k := 0; k < 1+i%8; k++ {
				seed = seed*1664525 + 1013904223
				b[int(seed>>8)%len(b)] ^= byte(seed >> 3)
			}
			if i%5 == 0 {
				b = b[:int(seed>>4)%len(b)]
			}
			r, err := NewReader(bytes.NewReader(b), int64(len(b)))
			if err != nil {
				continue
			}
			for _, f := range r.Files {
				r.ReadFile(f, 1<<16)
			}
		}
	}
	// Every method on random data.
	for m := 1; m <= 11; m++ {
		for i := 0; i < 50; i++ {
			b := make([]byte, 200+i*37)
			seed := uint32(m*7919 + i)
			for k := range b {
				seed = seed*1664525 + 1013904223
				b[k] = byte(seed >> 24)
			}
			Decode(m, bytes.NewReader(b), 1<<16)
		}
	}
}

func TestNotARC(t *testing.T) {
	b := []byte("\x1aplain text after a Ctrl-Z, not an archive")
	if _, err := NewReader(bytes.NewReader(b), int64(len(b))); err != ErrFormat {
		t.Errorf("got %v", err)
	}
}
