package lha

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The archives in ../testdata are real BBS uploads: -lh1- (LHarc) and -lh5-
// members, header levels 0, 1 and 2, and BBS adverts added afterwards.
func open(t *testing.T, name string) *Reader {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "testdata", name))
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
	methods := map[string]int{}
	levels := map[int]int{}
	for _, name := range []string{"5D-AVL01.LZH", "5D-BCHCK.LHA", "AFL-NM02.LHA", "DPH-CONQ.LHA", "ls-level1.lha", "quicksketch.lha"} {
		r := open(t, name)
		for _, f := range r.Files {
			if _, err := r.ReadFile(f, 0); err != nil {
				t.Errorf("%s: %s: %v", name, f.Name, err)
			}
			methods[f.Method]++
			levels[f.Level]++
		}
	}
	for _, m := range []string{"-lh0-", "-lh1-", "-lh5-", "-lhd-"} {
		if methods[m] == 0 {
			t.Errorf("no %s members tested", m)
		}
	}
	for l := 0; l <= 2; l++ {
		if levels[l] == 0 {
			t.Errorf("no level %d headers tested", l)
		}
	}
}

// The FILE_ID.DIZ must come out byte for byte as lha (Lhasa) extracts it.
func TestMatchesLha(t *testing.T) {
	for _, name := range []string{"5D-AVL01.LZH", "5D-BCHCK.LHA", "AFL-NM02.LHA", "DPH-CONQ.LHA"} {
		want, err := os.ReadFile(filepath.Join("..", "testdata", "golden", name+".diz"))
		if err != nil {
			t.Fatal(err)
		}
		r := open(t, name)
		found := false
		for _, f := range r.Files {
			if strings.EqualFold(f.Name, "file_id.diz") {
				got, err := r.ReadFile(f, 0)
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(got, want) {
					t.Errorf("%s: FILE_ID.DIZ differs from lha's", name)
				}
				found = true
			}
		}
		if !found {
			t.Errorf("%s: no FILE_ID.DIZ listed", name)
		}
	}
}

func TestNames(t *testing.T) {
	r := open(t, "5D-BCHCK.LHA")
	want := []string{"5D-Baudcheck/5D-BaudCheck", "5D-Baudcheck/5D-BaudCheck.guide",
		"5D-Baudcheck/5D-BaudCheck.info", "Commands/SysCmd/FRONTEND.info", "file_id.diz"}
	if len(r.Files) != len(want) {
		t.Fatalf("got %d files", len(r.Files))
	}
	for i, f := range r.Files {
		if f.Name != want[i] {
			t.Errorf("file %d: %q, want %q", i, f.Name, want[i])
		}
	}
	// Level 1 with directories (-lhd-).
	r = open(t, "ls-level1.lha")
	if r.Files[0].Name != "Ls/ALIASES" || !r.Files[0].Dir {
		t.Errorf("first entry %q dir=%v", r.Files[0].Name, r.Files[0].Dir)
	}
}

func TestLimit(t *testing.T) {
	r := open(t, "5D-BCHCK.LHA")
	full, err := r.ReadFile(r.Files[0], 0)
	if err != nil {
		t.Fatal(err)
	}
	part, err := r.ReadFile(r.Files[0], 100)
	if err != nil || !bytes.Equal(part, full[:100]) {
		t.Errorf("limited read: %v", err)
	}
}

// Damaged archives must never panic or hang.
func TestCorrupt(t *testing.T) {
	for _, name := range []string{"5D-BCHCK.LHA", "DPH-CONQ.LHA", "ls-level1.lha"} {
		orig, _ := os.ReadFile(filepath.Join("..", "testdata", name))
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

func TestNotLha(t *testing.T) {
	b := []byte("just some text, not an archive at all, with -lh in it")
	if _, err := NewReader(bytes.NewReader(b), int64(len(b))); err != ErrFormat {
		t.Errorf("got %v", err)
	}
}

func TestCRC16(t *testing.T) {
	if c := CRC16([]byte("123456789")); c != 0xbb3d {
		t.Errorf("CRC16 = %04x", c)
	}
}
