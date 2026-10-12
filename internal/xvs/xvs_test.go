package xvs

import (
	"os"
	"path/filepath"
	"testing"
)

// xvs.library is not in the repository (its licence allows passing it on
// only as the whole archive). Set AMISCAN_LIBS to a folder holding it.
var scanner *Scanner

func open(t *testing.T) *Scanner {
	t.Helper()
	dir := os.Getenv("AMISCAN_LIBS")
	if dir == "" {
		t.Skip("AMISCAN_LIBS not set: no xvs.library to test with")
	}
	if scanner == nil {
		s, err := Open(dir)
		if err != nil {
			t.Fatal(err)
		}
		s.Machine().Log = nil
		scanner = s
	}
	return scanner
}

func TestSelfTestAndLists(t *testing.T) {
	s := open(t)
	if ok, err := s.SelfTest(); !ok || err != nil {
		t.Fatalf("self test: %v %v", ok, err)
	}
	for _, k := range []uint32{ListBoot, ListData, ListFile, ListLink} {
		names, err := s.VirusList(k)
		if err != nil || len(names) < 10 {
			t.Fatalf("list %x: %d names, %v", k, len(names), err)
		}
	}
	boot, _ := s.VirusList(ListBoot)
	t.Logf("%s: %d boot viruses, first %q", s.IDString, len(boot), boot[0])
}

func TestCheckFileTypes(t *testing.T) {
	s := open(t)
	exe, err := os.ReadFile(filepath.Join("..", "..", "internal", "diz", "testdata", "disk", "hunk.exe"))
	if err != nil {
		// any small Amiga program will do
		exe = []byte{0, 0, 3, 0xf3, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
			0, 0, 3, 0xe9, 0, 0, 0, 1, 0x4e, 0x75, 0x4e, 0x71, 0, 0, 3, 0xf2}
	}
	for _, c := range []struct {
		name string
		data []byte
		want uint8
	}{
		{"empty", nil, FileEmpty},
		{"text", []byte("hello, Amiga\n"), FileData},
		{"program", exe, FileExe},
	} {
		r, err := s.CheckFile(c.data)
		if err != nil || r.Type != c.want {
			t.Errorf("%s: type %d (%s), %v; want %d", c.name, r.Type, r.Name, err, c.want)
		}
	}
}

func TestCheckBootblock(t *testing.T) {
	s := open(t)
	r, err := s.CheckBootblock(make([]byte, 1024))
	if err != nil || r.Infected() || r.Type != BootNotDOS {
		t.Fatalf("empty boot block: %+v %v", r, err)
	}
}

func TestManyChecksDoNotLeak(t *testing.T) {
	s := open(t)
	data := make([]byte, 100_000)
	for i := 0; i < 500; i++ {
		if _, err := s.CheckFile(data); err != nil {
			t.Fatalf("check %d: %v", i, err)
		}
	}
}
