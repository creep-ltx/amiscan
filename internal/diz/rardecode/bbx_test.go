package rardecode

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
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

// RAR 4 and 5 (made by RAR 6/7), plain and solid, and a solid RAR 2.0
// archive from 1990s BBS days whose window wraps (the BBX patch), byte for
// byte as the sources or as unrar extracts them.
func TestBBXArchives(t *testing.T) {
	g := golden(t)
	for _, name := range []string{"rar4.rar", "rar4-solid.rar", "rar5.rar", "rar5-solid.rar", "COCO2-14.RAR"} {
		want := g["*"]
		if name == "COCO2-14.RAR" {
			want = g[name]
		}
		f, err := os.Open(pc(name))
		if err != nil {
			t.Fatal(err)
		}
		r, err := NewReader(f)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		n := 0
		for {
			h, err := r.Next()
			if err == io.EOF {
				break
			}
			if err != nil {
				t.Fatalf("%s: %v", name, err)
			}
			out, err := io.ReadAll(r)
			if err != nil || sum(out) != want[strings.ToLower(h.Name)] {
				t.Errorf("%s: %s: %d bytes, %v", name, h.Name, len(out), err)
			}
			n++
		}
		f.Close()
		if n != len(want) {
			t.Errorf("%s: %d members, want %d", name, n, len(want))
		}
	}
}
