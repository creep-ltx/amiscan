package dms

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func td(t testing.TB, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// The SHA-256 of each file's disk as xDMS 1.3 (built from its source)
// unpacks it with "xdms u".
func TestSameAsXDMS(t *testing.T) {
	cases := []struct {
		file, sha       string
		diz, banner     bool
		modes           string
		tracks, imgSize int
	}{
		// all seven modes, state carried across tracks (made by gen_test.go)
		{"disk/modes.dms", "0fd4763d271a12b612dcbfd24581d4efa8194502390786dced27ea05f9cb675f", false, false, "0123456", 25, 0},
		// real files: HEAVY2 and NOCOMP tracks
		{"MTS-LS33.DMS", "a129c2046f315960751da8d4a04053e7829b941ec9d18073f0a1c6dcae9f5725", true, true, "", 80, 901120},
		{"disk/AMOSPRO4.DMS", "9a84c5feb347f1d7024ea752cdf44b1637285698c57e5894de140fb4e6de508d", false, true, "", 80, 901120},
	}
	for _, c := range cases {
		a, err := Read(td(t, c.file))
		if err != nil {
			t.Fatalf("%s: %v", c.file, err)
		}
		if a.Err != nil || len(a.Tracks) != c.tracks {
			t.Errorf("%s: %d tracks, %v", c.file, len(a.Tracks), a.Err)
		}
		if got := fmt.Sprintf("%x", sha256.Sum256(a.Concat())); got != c.sha {
			t.Errorf("%s: sha %s", c.file, got)
		}
		if (a.DIZ != nil) != c.diz || (a.Banner != nil) != c.banner {
			t.Errorf("%s: diz %d banner %d", c.file, len(a.DIZ), len(a.Banner))
		}
		if c.modes != "" {
			seen := map[int]bool{}
			for _, tr := range a.Tracks {
				seen[tr.Mode] = true
			}
			for _, m := range c.modes {
				if !seen[int(m-'0')] {
					t.Errorf("%s: mode %s missing", c.file, Modes[m-'0'])
				}
			}
		}
		if c.imgSize != 0 && len(a.Image()) != c.imgSize {
			t.Errorf("%s: image %d", c.file, len(a.Image()))
		}
	}
	a, _ := Read(td(t, "MTS-LS33.DMS"))
	if !strings.Contains(string(a.DIZ), "LogonStartup v0.33") {
		t.Errorf("DIZ %q", a.DIZ)
	}
}

// fixCRCs makes every CRC right again after the data was changed, so the
// decoders themselves see the damage.
func fixCRCs(b []byte) {
	put16(b[54:], int(crc16(b[4:54])))
	for pos := headLen; pos+trackLen <= len(b) && b[pos] == 'T' && b[pos+1] == 'R'; {
		h := b[pos : pos+trackLen]
		pk := int(be16(h[6:]))
		if pos+trackLen+pk > len(b) {
			return
		}
		put16(h[16:], int(crc16(b[pos+trackLen:pos+trackLen+pk])))
		put16(h[18:], int(crc16(h[:18])))
		pos += trackLen + pk
	}
}

func TestEncrypted(t *testing.T) {
	b := td(t, "disk/modes.dms")
	b[11] |= InfoEncrypted
	fixCRCs(b)
	a, err := Read(b)
	if err != nil || !a.Encrypted || len(a.Tracks) != 0 {
		t.Errorf("%+v %v", a, err)
	}
}

func TestNotDMS(t *testing.T) {
	if _, err := Read([]byte("DMS!short")); err != ErrNotDMS {
		t.Error(err)
	}
	b := td(t, "MTS-LS33.DMS")
	b[20]++
	if _, err := Read(b); err != ErrHeaderCRC {
		t.Error(err)
	}
	// A bad track keeps the tracks before it.
	b = td(t, "MTS-LS33.DMS")
	b[len(b)/2]++
	a, err := Read(b)
	if err != nil || a.Err == nil || len(a.Tracks) == 0 || len(a.Tracks) == 80 {
		t.Errorf("%v %v %d", err, a.Err, len(a.Tracks))
	}
}

// Damaged packed data with correct CRCs must never panic or hang.
func TestRandomDamage(t *testing.T) {
	rng := rand.New(rand.NewSource(7))
	for _, name := range []string{"disk/modes.dms", "MTS-LS33.DMS"} {
		orig := td(t, name)
		for round := 0; round < 300; round++ {
			b := append([]byte(nil), orig...)
			for k := 0; k < 1+rng.Intn(20); k++ {
				b[headLen+rng.Intn(len(b)-headLen)] = byte(rng.Intn(256))
			}
			fixCRCs(b)
			done := make(chan bool)
			go func() {
				Read(b)
				done <- true
			}()
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Fatalf("%s round %d hangs", name, round)
			}
		}
	}
}

func FuzzRead(f *testing.F) {
	f.Add(td(f, "disk/modes.dms")[:4000])
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 60 {
			fixCRCs(b)
		}
		if a, err := Read(b); err == nil {
			a.Image()
		}
	})
}

func TestModesTable(t *testing.T) {
	// The first and last entries of xDMS's d_code and d_len tables.
	if dCode[31] != 0 || dCode[32] != 1 || dCode[80] != 4 || dCode[255] != 0x3f ||
		dLen[0] != 3 || dLen[32] != 4 || dLen[80] != 5 || dLen[144] != 6 || dLen[192] != 7 || dLen[240] != 8 {
		t.Error("position tables")
	}
	if !bytes.Equal([]byte(Modes[6]), []byte("HEAVY2")) {
		t.Error(Modes)
	}
}
