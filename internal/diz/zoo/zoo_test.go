package zoo

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

// Methods 0, 1 and 2 (made by zoo 2.10) and a real Atari archive with
// folders, byte for byte as the sources or as zoo extracts them.
func TestMembers(t *testing.T) {
	g := golden(t)
	methods := map[int]int{}
	for _, name := range []string{"zoo-lzd.zoo", "zoo-lh5.zoo", "zoo-stored.zoo", "PMLDOC19.ZOO"} {
		want := g["*"]
		if name == "PMLDOC19.ZOO" {
			want = g[name]
		}
		r := open(t, name)
		for _, f := range r.Files {
			out, err := r.ReadFile(f, 0)
			if err != nil {
				t.Errorf("%s: %s: %v", name, f.Name, err)
				continue
			}
			if sum(out) != want[strings.ToLower(f.Name)] {
				t.Errorf("%s: %s differs", name, f.Name)
			}
			methods[f.Method]++
		}
	}
	for m := 0; m <= 2; m++ {
		if methods[m] == 0 {
			t.Errorf("no method %d member tested", m)
		}
	}
	if r := open(t, "PMLDOC19.ZOO"); r.Files[0].Name != "doc/header.r" {
		t.Errorf("folder name %q", r.Files[0].Name)
	}
}

func TestLimit(t *testing.T) {
	for _, name := range []string{"zoo-lzd.zoo", "zoo-lh5.zoo"} {
		r := open(t, name)
		for _, f := range r.Files {
			full, _ := r.ReadFile(f, 0)
			part, err := r.ReadFile(f, 77)
			if err != nil || !bytes.Equal(part, full[:min(77, len(full))]) {
				t.Errorf("%s: %s: limited read %d bytes, %v", name, f.Name, len(part), err)
			}
		}
	}
}

// Damaged archives must never panic or hang.
func TestCorrupt(t *testing.T) {
	for _, name := range []string{"zoo-lzd.zoo", "zoo-lh5.zoo", "PMLDOC19.ZOO"} {
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

func TestNotZOO(t *testing.T) {
	b := []byte("ZOO 2.10 Archive.\x1a but nothing after it")
	if _, err := NewReader(bytes.NewReader(b), int64(len(b))); err != ErrFormat {
		t.Errorf("got %v", err)
	}
}
