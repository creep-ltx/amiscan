package lzx

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func tdPath(name string) string { return filepath.Join("..", "testdata", name) }

// The archives in ../testdata are real LZX uploads from BBS hard disks.
func open(t *testing.T, name string) *Reader {
	t.Helper()
	b, err := os.ReadFile(tdPath(name))
	if err != nil {
		t.Fatal(err)
	}
	r, err := NewReader(bytes.NewReader(b), int64(len(b)))
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return r
}

func TestAllMembersCRC(t *testing.T) {
	for _, name := range []string{"dtr-am21.lzx", "msgconvert02.lzx", "config03.lzx"} {
		if !present(tdPath(name)) {
			t.Logf("%s is not published, skipped", name)
			continue
		}
		r := open(t, name)
		for _, f := range r.Files {
			if _, err := r.ReadFile(f, 0); err != nil {
				t.Errorf("%s: %s: %v", name, f.Name, err)
			}
		}
	}
}

// The FILE_ID.DIZ must come out byte for byte as unlzx extracts it.
func TestMatchesUnlzx(t *testing.T) {
	needReal(t, tdPath("dtr-am21.lzx"), tdPath("golden/dtr-am21.lzx.diz"))
	want, err := os.ReadFile(filepath.Join("..", "testdata", "golden", "dtr-am21.lzx.diz"))
	if err != nil {
		t.Fatal(err)
	}
	r := open(t, "dtr-am21.lzx")
	for _, f := range r.Files {
		if strings.EqualFold(f.Name, "file_id.diz") {
			got, err := r.ReadFile(f, 0)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, want) {
				t.Errorf("FILE_ID.DIZ differs from unlzx's")
			}
			return
		}
	}
	t.Error("no FILE_ID.DIZ listed")
}

func TestLimit(t *testing.T) {
	needReal(t, tdPath("msgconvert02.lzx"))
	r := open(t, "msgconvert02.lzx")
	f := r.Files[len(r.Files)-1]
	full, err := r.ReadFile(f, 0)
	if err != nil {
		t.Fatal(err)
	}
	part, err := r.ReadFile(f, 50)
	if err != nil || !bytes.Equal(part, full[:50]) {
		t.Errorf("limited read: %v", err)
	}
}

// Damaged archives must never panic or hang.
func TestCorrupt(t *testing.T) {
	for _, name := range []string{"dtr-am21.lzx", "msgconvert02.lzx"} {
		if !present(tdPath(name)) {
			t.Logf("%s is not published, skipped", name)
			continue
		}
		orig, _ := os.ReadFile(tdPath(name))
		for i := 0; i < 300; i++ {
			b := append([]byte{}, orig...)
			seed := uint32(i*2654435761 + 7)
			for k := 0; k < 1+i%8; k++ {
				seed = seed*1664525 + 1013904223
				// Leave the headers alone half the time so the packed
				// data gets damaged too (headers have a CRC).
				pos := int(seed>>8) % len(b)
				if i%2 == 0 && pos < 200 {
					pos += 200
				}
				if pos < len(b) {
					b[pos] ^= byte(seed>>3) | 1
				}
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

func TestNotLzx(t *testing.T) {
	b := []byte("not an archive")
	if _, err := NewReader(bytes.NewReader(b), int64(len(b))); err != ErrFormat {
		t.Errorf("got %v", err)
	}
}
