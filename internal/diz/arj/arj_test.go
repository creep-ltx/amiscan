package arj

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

// Every method, byte for byte as the sources (methods 0 to 4 by the open
// source ARJ 3.10) and as ARJ extracts a real 1990s BBS archive.
func TestMatchesGolden(t *testing.T) {
	g := golden(t)
	methods := map[int]int{}
	for _, name := range []string{"arj-m0.arj", "arj-m1.arj", "arj-m2.arj", "arj-m3.arj", "arj-m4.arj", "TWWORM.ARJ"} {
		want := g["*"]
		if name == "TWWORM.ARJ" {
			want = g[name]
		}
		if !present(pc(name)) {
			t.Logf("%s is not published, skipped", name)
			continue
		}
		r := open(t, name)
		if len(r.Files) != len(want) {
			t.Errorf("%s: %d members, want %d", name, len(r.Files), len(want))
		}
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
	for m := 0; m <= 4; m++ {
		if methods[m] == 0 {
			t.Errorf("no method %d member tested", m)
		}
	}
}

func TestLimit(t *testing.T) {
	r := open(t, "arj-m4.arj")
	for _, f := range r.Files {
		full, err := r.ReadFile(f, 0)
		if err != nil {
			t.Fatal(err)
		}
		part, err := r.ReadFile(f, 100)
		if err != nil || !bytes.HasPrefix(full, part) || len(part) != min(100, len(full)) {
			t.Errorf("%s: limited read %d bytes, %v", f.Name, len(part), err)
		}
	}
}

func TestGarbled(t *testing.T) {
	r := open(t, "arj-garbled.arj")
	if len(r.Files) != 2 {
		t.Fatalf("%d members", len(r.Files))
	}
	for _, f := range r.Files {
		if f.Flags&FlagGarbled == 0 {
			t.Errorf("%s not marked encrypted", f.Name)
		}
		if _, err := r.ReadFile(f, 0); err == nil {
			t.Errorf("%s: encrypted member read without error", f.Name)
		}
	}
}

// A volume set: ARJ packs each volume's part of a split file on its own,
// so the part at the end of the first volume is the file's start and the
// part at the start of the second is its end, each with its own CRC.
func TestVolumes(t *testing.T) {
	g := golden(t)["*"]
	parts := map[string][][]byte{}
	for _, name := range []string{"arjvol.arj", "arjvol.a01"} {
		r := open(t, name)
		for _, f := range r.Files {
			out, err := r.ReadFile(f, 0)
			if err != nil {
				t.Errorf("%s: %s: %v", name, f.Name, err)
				continue
			}
			if f.Flags&(FlagVolume|FlagExtFile) != 0 {
				parts[f.Name] = append(parts[f.Name], out)
			} else if sum(out) != g[strings.ToLower(f.Name)] {
				t.Errorf("%s: %s differs", name, f.Name)
			}
		}
	}
	if len(parts) == 0 {
		t.Fatal("volume set without a split member")
	}
	for n, p := range parts {
		if len(p) != 2 || sum(append(append([]byte{}, p[0]...), p[1]...)) != g[strings.ToLower(n)] {
			t.Errorf("%s: the two parts do not make the file", n)
		}
	}
}

// Damaged archives must never panic or hang.
func TestCorrupt(t *testing.T) {
	for _, name := range []string{"arj-m1.arj", "arj-m4.arj", "TWWORM.ARJ"} {
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
}

func TestNotARJ(t *testing.T) {
	b := []byte("plain text with \x60\xea in it, but no ARJ header")
	if _, err := NewReader(bytes.NewReader(b), int64(len(b))); err != ErrFormat {
		t.Errorf("got %v", err)
	}
	if IsHeader(b) {
		t.Error("IsHeader on text")
	}
}
