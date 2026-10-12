package diz

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func pcFile(name string) string { return filepath.Join("testdata", "pc", name) }

// pcGolden reads testdata/pc/golden.txt: archive -> member -> sha256, as
// extracted by independent tools (unrar, arj, zoo, nomarch, lha, unzip);
// "*" holds the sources of the archives made for the tests.
func pcGolden(t *testing.T) map[string]map[string]string {
	t.Helper()
	b, err := os.ReadFile(pcFile("golden.txt"))
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

// pcMembers opens a test archive the way Examine does.
func pcMembers(t *testing.T, name string) (string, []member) {
	t.Helper()
	f, err := os.Open(pcFile(name))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.Close() })
	st, _ := f.Stat()
	head := make([]byte, headSize)
	n, _ := f.ReadAt(head, 0)
	fm := detect(head[:n], st.Size(), strings.ToLower(strings.TrimPrefix(filepath.Ext(name), ".")))
	if fm == nil {
		t.Fatalf("%s: no format", name)
	}
	ms, _, ok := list(f, st.Size(), fm)
	if !ok {
		t.Fatalf("%s: not %s", name, fm.name)
	}
	return fm.name, ms
}

// Every member of every PC test archive, through detection and the
// format's reader, byte for byte as an independent extractor gives it.
func TestPCMembersMatchGolden(t *testing.T) {
	g := pcGolden(t)
	cases := []struct {
		file, format, golden string
	}{
		{"arj-m0.arj", "arj", "*"}, {"arj-m1.arj", "arj", "*"}, {"arj-m2.arj", "arj", "*"},
		{"arj-m3.arj", "arj", "*"}, {"arj-m4.arj", "arj", "*"}, {"TWWORM.ARJ", "arj", "TWWORM.ARJ"},
		{"crunch.arc", "arc", "*"}, {"squash.arc", "arc", "*"},
		{"2001.ARC", "arc", "2001.ARC"}, {"SIL2.ARC", "arc", "SIL2.ARC"},
		{"zoo-lzd.zoo", "zoo", "*"}, {"zoo-lh5.zoo", "zoo", "*"}, {"PMLDOC19.ZOO", "zoo", "PMLDOC19.ZOO"},
		{"rar4.rar", "rar", "*"}, {"rar4-solid.rar", "rar", "*"}, {"rar5.rar", "rar", "*"},
		{"rar5-solid.rar", "rar", "*"}, {"COCO2-14.RAR", "rar", "COCO2-14.RAR"},
		{"files.tar", "tar", "*"}, {"files.tar.gz", "gzip", "*"}, {"files.tar.bz2", "bzip2", "*"},
		{"files.tar.xz", "xz", "*"},
		{"sfx-arj-m1.exe", "sfx", "*"}, {"sfx-rar5.exe", "sfx", "*"}, {"sfx-zoo-lh5.exe", "sfx", "*"},
		{"sfx-crunch.exe", "sfx", "*"}, {"QG2IMPRT.EXE", "sfx", "QG2IMPRT.EXE"},
		{"LOOZ101.EXE", "sfx", "LOOZ101.EXE"}, {"sfx-cab.exe", "sfx", "mszip.cab"},
		{"mszip.cab", "cab", "mszip.cab"}, {"FADER.CAB", "cab", "FADER.CAB"},
		{"ATTSWIT.ZIP", "zip", "ATTSWIT.ZIP"}, {"NAMEPATH.ZIP", "zip", "NAMEPATH.ZIP"},
		{"OX.ZIP", "zip", "OX.ZIP"}, {"PARKAT.ZIP", "zip", "PARKAT.ZIP"}, {"MRIMHPLJ.ZIP", "zip", "MRIMHPLJ.ZIP"},
	}
	for _, c := range cases {
		format, ms := pcMembers(t, c.file)
		want := g[c.golden]
		if format != c.format || len(ms) != len(want) {
			t.Errorf("%s: format %s, %d members, want %s, %d", c.file, format, len(ms), c.format, len(want))
		}
		for _, m := range ms {
			out, err := m.read(1 << 30)
			s := sha256.Sum256(out)
			if err != nil || hex.EncodeToString(s[:]) != want[strings.ToLower(m.name)] {
				t.Errorf("%s: %s differs (%d bytes, %v)", c.file, m.name, len(out), err)
			}
		}
	}
	// 7z inside a self-extractor: only two of the sources.
	if _, ms := pcMembers(t, "sfx-seven.exe"); len(ms) != 2 {
		t.Errorf("sfx-seven.exe: %d members", len(ms))
	}
}

func TestExaminePC(t *testing.T) {
	diz := Clean([]byte("BBX TEST ARCHIVE v1.0 by creep/ltx\r\n\xb0\xb1\xb2\xdb PC test data, 2026 \xdb\xb2\xb1\xb0\r\nThird line of the description.\r\n"), 10)
	if diz == nil || diz[1] != "░▒▓█ PC test data, 2026 █▓▒░" {
		t.Fatalf("test DIZ cleans to %q", diz)
	}
	withDIZ := map[string]string{
		"arj-m1.arj": "arj", "arj-m4.arj": "arj", "crunch.arc": "arc", "squash.arc": "arc",
		"zoo-lzd.zoo": "zoo", "zoo-lh5.zoo": "zoo", "zoo-stored.zoo": "zoo",
		"rar4.rar": "rar", "rar5-solid.rar": "rar", "rar4vol.part1.rar": "rar",
		"files.tar": "tar", "files.tar.gz": "gzip", "files.tar.bz2": "bzip2", "files.tar.xz": "xz",
		"sfx-arj-m1.exe": "sfx", "sfx-rar5.exe": "sfx", "sfx-zoo-lh5.exe": "sfx", "sfx-crunch.exe": "sfx",
		"sfx-seven.exe": "sfx", "arjvol.arj": "arj", "mszip.cab": "cab", "sfx-cab.exe": "sfx",
	}
	for name, format := range withDIZ {
		res, err := Examine(pcFile(name), 10)
		if err != nil || res.Format != format || !reflect.DeepEqual(res.DIZ, diz) {
			t.Errorf("%s: format %q, DIZ %q, %v", name, res.Format, res.DIZ, err)
		}
	}

	// A real BBS archive with FILE_ID.DIZ (and DESC.SDI).
	res, _ := Examine(pcFile("TWWORM.ARJ"), 10)
	if res.Format != "arj" || len(res.DIZ) == 0 || res.DIZ[0] != "Roaming WormHole. Put a roaming WormHole in" {
		t.Errorf("TWWORM.ARJ: %q", res.DIZ)
	}

	// No DIZ: fallbacks from the readme, or the names.
	res, _ = Examine(pcFile("PAK251.EXE"), 10)
	if res.Format != "sfx" || res.DIZ != nil || len(res.Candidates) < 2 || res.Candidates[0].Source != "from READ.ME" {
		t.Errorf("PAK251.EXE: %+v", res)
	}
	res, _ = Examine(pcFile("README.TXT.gz"), 10)
	if res.Format != "gzip" || len(res.Candidates) == 0 || res.Candidates[0].Source != "from README.TXT" {
		t.Errorf("README.TXT.gz: %+v", res)
	}
	res, _ = Examine(pcFile("ARC2PAK1.PAK"), 10)
	if res.Format != "arc" || len(res.Candidates) == 0 || res.Candidates[len(res.Candidates)-1].Source != "contents" {
		t.Errorf("ARC2PAK1.PAK: %+v", res)
	}

	// A RAR whose names are encrypted, and the second volume of a set: a
	// RAR with nothing to read. Encrypted members are left out.
	for _, name := range []string{"rar5-hdrenc.rar", "rar4vol.part2.rar"} {
		res, err := Examine(pcFile(name), 10)
		if err != nil || res.Format != "rar" || res.DIZ != nil {
			t.Errorf("%s: %+v %v", name, res, err)
		}
	}
	res, _ = Examine(pcFile("rar5-enc.rar"), 10)
	if res.Format != "rar" || res.DIZ != nil || len(res.Candidates) != 0 {
		t.Errorf("rar5-enc.rar: %+v", res)
	}
	res, _ = Examine(pcFile("arj-garbled.arj"), 10)
	if res.Format != "arj" || res.DIZ != nil {
		t.Errorf("arj-garbled.arj: %+v", res)
	}
}

// A gzipped Amiga disk image (.adz) is left to the disk formats.
func TestGzipLeavesADZ(t *testing.T) {
	var buf bytes.Buffer
	z := gzip.NewWriter(&buf)
	z.Write(append([]byte("DOS\x00"), make([]byte, 2000)...))
	z.Close()
	if isGzip(buf.Bytes(), int64(buf.Len())) {
		t.Error("an ADF in gzip taken as gzip")
	}
	buf.Reset()
	z = gzip.NewWriter(&buf)
	z.Write([]byte("just a text file\n"))
	z.Close()
	if !isGzip(buf.Bytes(), int64(buf.Len())) {
		t.Error("a gzipped text not taken")
	}
}

// Damaged PC archives must never panic or hang Examine.
func TestExaminePCCorrupt(t *testing.T) {
	dir := t.TempDir()
	names := []string{"arj-m1.arj", "arj-m4.arj", "crunch.arc", "squash.arc", "ARC2PAK1.PAK",
		"zoo-lzd.zoo", "zoo-lh5.zoo", "rar4.rar", "rar5-solid.rar", "COCO2-14.RAR", "files.tar.gz",
		"files.tar.xz", "sfx-arj-m1.exe", "sfx-crunch.exe", "PAK251.EXE"}
	for _, name := range names {
		orig, err := os.ReadFile(pcFile(name))
		if err != nil {
			t.Fatal(err)
		}
		for i := 0; i < 40; i++ {
			b := append([]byte{}, orig...)
			seed := uint32(i*2654435761 + 7)
			for k := 0; k < 1+i%6; k++ {
				seed = seed*1664525 + 1013904223
				b[int(seed>>8)%len(b)] ^= byte(seed>>3) | 1
			}
			if i%4 == 0 {
				b = b[:int(seed>>4)%len(b)]
			}
			p := filepath.Join(dir, name)
			os.WriteFile(p, b, 0o644)
			done := make(chan error, 1)
			go func() { _, err := Examine(p, 10); done <- err }()
			select {
			case err := <-done:
				if err != nil {
					t.Errorf("%s #%d: %v", name, i, err)
				}
			case <-time.After(20 * time.Second):
				t.Fatalf("%s #%d: hangs", name, i)
			}
		}
	}
}
