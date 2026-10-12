package adf

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"
)

// The images in testdata/disk were made by amitools' xdftool and rdbtool
// (the recipe is in the test names): the same files on every DOS type.

func gunzip(t testing.TB, name string) []byte {
	t.Helper()
	f, err := os.Open(filepath.Join("..", "testdata", "disk", name))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	z, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	var b bytes.Buffer
	if _, err := b.ReadFrom(z); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

// bigBin is the content of big.bin: `seq 1 15000` (78894 bytes, two
// extension blocks on both OFS and FFS).
func bigBin() []byte {
	var b bytes.Buffer
	for i := 1; i <= 15000; i++ {
		fmt.Fprintf(&b, "%d\n", i)
	}
	return b.Bytes()
}

func wantPaths() []string {
	p := []string{"FILE_ID.DIZ", "ReadMe", "big.bin", "empty", "deep", "deep/er", "deep/er/still",
		"deep/er/still/note.txt", "many"}
	for i := 1; i <= 100; i++ {
		p = append(p, fmt.Sprintf("many/f%d", i))
	}
	sort.Strings(p)
	return p
}

func TestFloppies(t *testing.T) {
	cases := []struct {
		file string
		dos  byte
		typ  string
		size int
	}{
		{"ofs.adz", 0, "OFS", SizeDD},
		{"ffs.adz", 1, "FFS", SizeDD},
		{"ofs-intl.adz", 2, "OFS-INTL", SizeDD},
		{"ffs-intl.adz", 3, "FFS-INTL", SizeDD},
		{"ofs-dc.adz", 4, "OFS-DC", SizeDD},
		{"ffs-dc.adz", 5, "FFS-DC", SizeDD},
		{"ffs-hd.adz", 1, "FFS", SizeHD},
	}
	big := bigBin()
	for _, c := range cases {
		img := gunzip(t, c.file)
		if len(img) != c.size {
			t.Fatalf("%s: %d bytes", c.file, len(img))
		}
		v, err := OpenFloppy(bytes.NewReader(img), int64(len(img)))
		if err != nil {
			t.Fatalf("%s: %v", c.file, err)
		}
		want := "BBX " + strings.Replace(strings.TrimSuffix(strings.TrimSuffix(c.file, ".adz"), "-hd"), "-", "+", 1)
		if c.size == SizeHD {
			want = "BBX ffs-hd"
		}
		if v.Name != want || v.DOSType != c.dos || v.Type() != c.typ || v.Problems != 0 {
			t.Errorf("%s: %q DOS\\%d %s problems %d", c.file, v.Name, v.DOSType, v.Type(), v.Problems)
		}
		var got []string
		files := map[string]Entry{}
		for _, e := range v.Entries {
			got = append(got, e.Path)
			files[e.Path] = e
			if isDir := e.Path == "deep" || e.Path == "deep/er" || e.Path == "deep/er/still" || e.Path == "many"; e.Dir != isDir {
				t.Errorf("%s: %s dir=%v", c.file, e.Path, e.Dir)
			}
		}
		sort.Strings(got)
		if strings.Join(got, ",") != strings.Join(wantPaths(), ",") {
			t.Errorf("%s: entries\n%v", c.file, got)
		}
		for name, want := range map[string]string{
			"big.bin":                string(big),
			"deep/er/still/note.txt": "hello\n",
			"many/f42":               "file 42\n",
			"empty":                  "",
		} {
			b, err := v.ReadFile(files[name], 1<<20)
			if err != nil || string(b) != want {
				t.Errorf("%s: %s: %d bytes, %v", c.file, name, len(b), err)
			}
		}
		// A limit stops early, also across data blocks.
		if b, _ := v.ReadFile(files["big.bin"], 1000); string(b) != string(big[:1000]) {
			t.Errorf("%s: limited read %d bytes", c.file, len(b))
		}
	}
}

func TestRDB(t *testing.T) {
	img := gunzip(t, "rdb.hdf.gz")
	r := bytes.NewReader(img)
	parts, err := Partitions(r, int64(len(img)))
	if err != nil || len(parts) != 3 {
		t.Fatalf("partitions %v %v", parts, err)
	}
	if parts[0].Name != "DH0" || parts[1].Name != "WORK" || parts[2].Name != "PFS" ||
		!parts[0].IsDOS() || !parts[1].IsDOS() || parts[2].IsDOS() || parts[2].DOSTypeString() != "PFS\\3" {
		t.Errorf("partitions %+v %s", parts, parts[2].DOSTypeString())
	}
	v, err := parts[1].Open(r)
	if err != nil || v.Name != "Work" || len(v.Entries) != 2 || v.FFS() {
		t.Fatalf("WORK: %+v %v", v, err)
	}
	for _, e := range v.Entries {
		if e.Path == "big.bin" {
			if b, _ := v.ReadFile(e, 1<<20); !bytes.Equal(b, bigBin()) {
				t.Errorf("WORK big.bin: %d bytes", len(b))
			}
		}
	}
	v, err = parts[0].Open(r)
	if err != nil || v.Name != "System" || len(v.Entries) != 106 || !v.FFS() {
		t.Fatalf("DH0: %v %d %v", v.Name, len(v.Entries), err)
	}
	if _, err := Partitions(bytes.NewReader(gunzip(t, "ffs.adz")), SizeDD); err != ErrNoRDB {
		t.Errorf("floppy: %v", err)
	}
}

func TestNotDOS(t *testing.T) {
	img := make([]byte, SizeDD)
	copy(img, "BOOT\x00\x00\x00\x00\x60\x00Crack by the Gang - call our board!\x00\x4e\x75")
	if _, err := OpenFloppy(bytes.NewReader(img), SizeDD); err != ErrNotDOS {
		t.Errorf("err %v", err)
	}
	if got := BootText(img); len(got) != 1 || got[0] != "Crack by the Gang - call our board!" {
		t.Errorf("boot text %q", got)
	}
	copy(img, "DOS\x00")
	if _, err := OpenFloppy(bytes.NewReader(img), SizeDD); err != ErrNoRoot {
		t.Errorf("err %v", err)
	}
	if _, err := OpenFloppy(bytes.NewReader(img[:100]), 100); err == nil {
		t.Error("tiny image opened")
	}
}

func put32(b []byte, v uint32) {
	b[0], b[1], b[2], b[3] = byte(v>>24), byte(v>>16), byte(v>>8), byte(v)
}

// Crafted loops: a hash chain pointing back at itself and at the root,
// a directory listing its parent, an extension block pointing to itself.
func TestCraftedLoops(t *testing.T) {
	img := gunzip(t, "ffs.adz")
	v, err := OpenFloppy(bytes.NewReader(img), SizeDD)
	if err != nil {
		t.Fatal(err)
	}
	blk := map[string]uint32{}
	for _, e := range v.Entries {
		blk[e.Path] = e.block
	}
	at := func(n uint32) []byte { return img[int(n)*512 : int(n)*512+512] }
	put32(at(blk["many/f1"])[512-16:], blk["many/f1"])  // chain to itself
	put32(at(blk["many/f2"])[512-16:], 880)             // chain to the root
	put32(at(blk["deep/er"])[24:], blk["deep"])         // dir lists its parent
	put32(at(blk["big.bin"])[512-8:], blk["big.bin"])   // extension = header
	put32(at(blk["deep/er/still"])[512-16:], 0xfffffff) // chain out of range
	done := make(chan *Volume)
	go func() {
		v, _ := OpenFloppy(bytes.NewReader(img), SizeDD)
		if v != nil {
			for _, e := range v.Entries {
				v.ReadFile(e, 1<<20)
			}
		}
		done <- v
	}()
	select {
	case v := <-done:
		if v == nil || v.Problems == 0 {
			t.Errorf("no problems seen")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("hangs")
	}
}

// Random damage must never panic or hang.
func TestRandomDamage(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	for _, name := range []string{"ofs.adz", "ffs-dc.adz", "ffs-hd.adz"} {
		orig := gunzip(t, name)
		for round := 0; round < 150; round++ {
			img := append([]byte(nil), orig...)
			for k := 0; k < 1+rng.Intn(400); k++ {
				i := rng.Intn(len(img))
				if rng.Intn(3) == 0 {
					// aim at the root and directory area
					i = 880*512 + rng.Intn(20*512)
				}
				img[i] = byte(rng.Intn(256))
			}
			v, err := OpenFloppy(bytes.NewReader(img), int64(len(img)))
			if err != nil {
				continue
			}
			for _, e := range v.Entries {
				v.ReadFile(e, 1<<20)
			}
		}
	}
}

func FuzzOpen(f *testing.F) {
	f.Add(gunzip(f, "ofs.adz")[:4096])
	f.Fuzz(func(t *testing.T, b []byte) {
		v, err := OpenFloppy(bytes.NewReader(b), int64(len(b)))
		if err == nil {
			for _, e := range v.Entries {
				v.ReadFile(e, 1<<16)
			}
		}
		Partitions(bytes.NewReader(b), int64(len(b)))
		BootText(b)
	})
}
