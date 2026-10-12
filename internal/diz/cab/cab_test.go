package cab

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

func open(t *testing.T, name string) *Reader {
	t.Helper()
	b, err := os.ReadFile(pc(name))
	if err != nil {
		t.Fatal(err)
	}
	r, err := NewReader(bytes.NewReader(b), int64(len(b)))
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return r
}

// A stored folder and an MSZIP folder whose blocks refer back to earlier
// ones (made for the tests, checked with cabextract), and a real MSZIP
// cabinet, byte for byte as cabextract extracts them.
func TestMembers(t *testing.T) {
	g := golden(t)
	for _, name := range []string{"mszip.cab", "FADER.CAB"} {
		r := open(t, name)
		if len(r.Files) != len(g[name]) {
			t.Errorf("%s: %d members", name, len(r.Files))
		}
		for _, f := range r.Files {
			out, err := r.ReadFile(f, 0)
			key := strings.ToLower(strings.ReplaceAll(f.Name, "\\", "/"))
			if err != nil || sum(out) != g[name][key] {
				t.Errorf("%s: %s: %d bytes, %v", name, f.Name, len(out), err)
			}
			if part, err := r.ReadFile(f, 50); err != nil || !bytes.Equal(part, out[:min(50, len(out))]) {
				t.Errorf("%s: %s: limited read %v", name, f.Name, err)
			}
		}
	}
}

// Damaged cabinets must never panic or hang.
func TestCorrupt(t *testing.T) {
	for _, name := range []string{"mszip.cab", "FADER.CAB"} {
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
}

func TestNotCAB(t *testing.T) {
	b := []byte("MSCF but not really a cabinet, just text that goes on")
	if _, err := NewReader(bytes.NewReader(b), int64(len(b))); err != ErrFormat {
		t.Errorf("got %v", err)
	}
}
