package zipold

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func pc(name string) string { return filepath.Join("..", "testdata", "pc", name) }

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

// PKZIP 1.x archives from 1990 (shrink, and implode with 4 or 8 KB windows
// and 2 or 3 trees) through archive/zip, byte for byte as unzip extracts
// them; archive/zip also checks each CRC.
func TestPKZIP1(t *testing.T) {
	Register()
	g := golden(t)
	seen := map[string]bool{}
	skipped := 0
	for _, name := range []string{"ATTSWIT.ZIP", "NAMEPATH.ZIP", "OX.ZIP", "PARKAT.ZIP", "MRIMHPLJ.ZIP"} {
		if !present(pc(name)) {
			t.Logf("%s is not published, skipped", name)
			skipped++
			continue
		}
		z, err := zip.OpenReader(pc(name))
		if err != nil {
			t.Fatal(err)
		}
		for _, f := range z.File {
			rc, err := f.Open()
			if err != nil {
				t.Errorf("%s: %s: %v", name, f.Name, err)
				continue
			}
			out, err := io.ReadAll(rc)
			rc.Close()
			s := sha256.Sum256(out)
			if err != nil || hex.EncodeToString(s[:]) != g[name][strings.ToLower(f.Name)] {
				t.Errorf("%s: %s: %d bytes, %v", name, f.Name, len(out), err)
			}
			variant := map[uint16]string{Shrink: "shrink", Implode: "implode"}[f.Method]
			if f.Method == Implode {
				variant += map[bool]string{true: " 8K", false: " 4K"}[f.Flags&2 != 0]
				variant += map[bool]string{true: " 3 trees", false: " 2 trees"}[f.Flags&4 != 0]
			}
			seen[variant] = true
		}
		z.Close()
	}
	if skipped > 0 {
		t.Skipf("%d real archives are not published, so not every variant was tested; see testdata/README.md", skipped)
	}
	// PKZIP 1.x writes only these two implode variants.
	for _, v := range []string{"shrink", "implode 4K 2 trees", "implode 8K 3 trees"} {
		if !seen[v] {
			t.Errorf("no %s member tested", v)
		}
	}
}

// Reduce (PKZIP 0.9, 1989) is rare and no other unpacker here reads it:
// this real Atari archive (factor 4) is checked by its CRC, which
// archive/zip verifies at the end of the data.
func TestReduce(t *testing.T) {
	needReal(t, pc("FIRETRKS.ZIP"))
	Register()
	z, err := zip.OpenReader(pc("FIRETRKS.ZIP"))
	if err != nil {
		t.Fatal(err)
	}
	defer z.Close()
	f := z.File[0]
	if f.Method != Reduce1+3 {
		t.Fatalf("method %d", f.Method)
	}
	rc, err := f.Open()
	if err != nil {
		t.Fatal(err)
	}
	out, err := io.ReadAll(rc)
	if err != nil || len(out) != int(f.UncompressedSize64) {
		t.Errorf("%d bytes, %v", len(out), err)
	}
}

// Random input must end in an error or the full size, never a panic or a
// hang, for every method and flag.
func TestRandomInput(t *testing.T) {
	for _, m := range []uint16{1, 2, 3, 4, 5, 6} {
		for i := 0; i < 200; i++ {
			b := make([]byte, 50+i*11)
			seed := uint32(int(m)*7919 + i)
			for k := range b {
				seed = seed*1664525 + 1013904223
				b[k] = byte(seed >> 24)
			}
			r := NewReader(bytes.NewReader(b), m, uint16(i&6), 1<<16)
			out, _ := io.ReadAll(r)
			if len(out) > 1<<16 {
				t.Fatalf("method %d: %d bytes past the size", m, len(out))
			}
		}
	}
}

// Damaged real archives must never panic or hang.
func TestCorrupt(t *testing.T) {
	Register()
	for _, name := range []string{"ATTSWIT.ZIP", "OX.ZIP", "MRIMHPLJ.ZIP"} {
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
			z, err := zip.NewReader(bytes.NewReader(b), int64(len(b)))
			if err != nil {
				continue
			}
			for _, f := range z.File {
				if rc, err := f.Open(); err == nil {
					io.Copy(io.Discard, io.LimitReader(rc, 1<<20))
					rc.Close()
				}
			}
		}
	}
}
