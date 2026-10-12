package stream

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
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

func file(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(pc(name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// tar, plain and compressed (made by GNU tar, gzip, bzip2, xz), byte for
// byte as the sources.
func TestTars(t *testing.T) {
	want := golden(t)["*"]
	for _, c := range []struct {
		name string
		kind Kind
	}{{"files.tar", None}, {"files.tar.gz", Gzip}, {"files.tar.bz2", Bzip2}, {"files.tar.xz", XZ}} {
		b := file(t, c.name)
		if k := Detect(b); k != c.kind {
			t.Errorf("%s: detected %d", c.name, k)
		}
		var ms []Member
		var err error
		if c.kind == None {
			if !IsTar(b) {
				t.Errorf("%s: not a tar", c.name)
			}
			ms, err = OpenTar(bytes.NewReader(b), int64(len(b)))
		} else {
			var isTar bool
			ms, isTar, err = Open(c.kind, bytes.NewReader(b), int64(len(b)))
			if !isTar {
				t.Errorf("%s: tar not seen", c.name)
			}
		}
		if err != nil || len(ms) != len(want) {
			t.Fatalf("%s: %d members, %v", c.name, len(ms), err)
		}
		for _, m := range ms {
			out, err := m.Read(1 << 20)
			if err != nil || sum(out) != want[strings.ToLower(m.Name)] {
				t.Errorf("%s: %s: %v", c.name, m.Name, err)
			}
		}
	}
}

// A bare .gz of one text file: one member, named from the gzip header.
func TestSingleGzip(t *testing.T) {
	b := file(t, "README.TXT.gz")
	ms, isTar, err := Open(Gzip, bytes.NewReader(b), int64(len(b)))
	if err != nil || isTar || len(ms) != 1 || ms[0].Name != "README.TXT" {
		t.Fatalf("%v %v %+v", err, isTar, ms)
	}
	out, err := ms[0].Read(1 << 20)
	if err != nil || sum(out) != golden(t)["*"]["readme.txt"] {
		t.Errorf("README.TXT differs: %v", err)
	}
	if p := Peek(Gzip, b, 4); string(p) != string(out[:4]) {
		t.Errorf("Peek %q", p)
	}
}

// A member beyond what the listing keeps is read by decompressing again.
func TestReadAgain(t *testing.T) {
	var buf bytes.Buffer
	z := gzip.NewWriter(&buf)
	w := tar.NewWriter(z)
	big := bytes.Repeat([]byte("0123456789abcdef"), (KeepEach+5000)/16)
	for _, f := range []struct {
		name string
		data []byte
	}{{"big.bin", big}, {"link", nil}, {"FILE_ID.DIZ", []byte("hello\r\n")}} {
		h := &tar.Header{Name: f.name, Mode: 0o644, Size: int64(len(f.data)), Typeflag: tar.TypeReg}
		if f.data == nil {
			h = &tar.Header{Name: f.name, Linkname: "big.bin", Typeflag: tar.TypeLink}
		}
		w.WriteHeader(h)
		w.Write(f.data)
	}
	w.Close()
	z.Close()
	b := buf.Bytes()
	ms, _, err := Open(Gzip, bytes.NewReader(b), int64(len(b)))
	if err != nil || len(ms) != 2 {
		t.Fatalf("%d members (links left out), %v", len(ms), err)
	}
	out, err := ms[0].Read(1 << 20)
	if err != nil || !bytes.Equal(out, big) {
		t.Errorf("big member: %d bytes, %v", len(out), err)
	}
	out, err = ms[1].Read(100)
	if err != nil || string(out) != "hello\r\n" {
		t.Errorf("DIZ %q %v", out, err)
	}
}

func TestNotStream(t *testing.T) {
	b := make([]byte, 600)
	copy(b, "just text")
	if Detect(b) != None || IsTar(b) {
		t.Error("text detected as a stream or tar")
	}
	if _, err := OpenTar(bytes.NewReader(b), int64(len(b))); err == nil {
		t.Error("text opened as tar")
	}
	// Damaged compressed tars must never panic or hang.
	for _, name := range []string{"files.tar.gz", "files.tar.bz2", "files.tar.xz"} {
		orig := file(t, name)
		for i := 0; i < 100; i++ {
			b := append([]byte{}, orig...)
			seed := uint32(i*2654435761 + 1)
			for k := 0; k < 1+i%8; k++ {
				seed = seed*1664525 + 1013904223
				b[int(seed>>8)%len(b)] ^= byte(seed >> 3)
			}
			if i%5 == 0 {
				b = b[:int(seed>>4)%len(b)]
			}
			ms, _, err := Open(Detect(orig), bytes.NewReader(b), int64(len(b)))
			if err != nil {
				continue
			}
			for _, m := range ms {
				m.Read(1 << 16)
			}
		}
	}
}
