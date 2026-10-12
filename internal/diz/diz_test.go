package diz

import (
	"archive/zip"
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"unicode/utf8"
)

func td(name string) string { return filepath.Join("testdata", name) }

// The DIZ found in real archives must equal the cleaned FILE_ID.DIZ that
// lha (Lhasa) and unlzx extract (kept in testdata/golden).
func TestExamineMatchesTools(t *testing.T) {
	cases := map[string]string{
		"5D-AVL01.LZH": "lha", // -lh5- DIZ next to -lh1- members
		"5D-BCHCK.LHA": "lha",
		"AFL-NM02.LHA": "lha", // BBS-added members with garbage names
		"DPH-CONQ.LHA": "lha", // level 2 headers, then level 0 ones a BBS added
		"dtr-am21.lzx": "lzx",
	}
	for name, format := range cases {
		res, err := Examine(td(name), 10)
		if err != nil {
			t.Fatal(err)
		}
		raw, err := os.ReadFile(td("golden/" + name + ".diz"))
		if err != nil {
			t.Fatal(err)
		}
		if res.Format != format {
			t.Errorf("%s: format %q", name, res.Format)
		}
		if want := Clean(raw, 10); !reflect.DeepEqual(res.DIZ, want) || want == nil {
			t.Errorf("%s: DIZ\n%q\nwant\n%q", name, res.DIZ, want)
		}
		if len(res.Candidates) != 0 {
			t.Errorf("%s: candidates with a DIZ", name)
		}
	}
}

func TestExamineDIZText(t *testing.T) {
	res, _ := Examine(td("5D-BCHCK.LHA"), 10)
	if got := res.DIZ[len(res.DIZ)-1]; got != "     Baud rate detecter for ami/x" {
		t.Errorf("last line %q", got)
	}
	res, _ = Examine(td("dtr-am21.lzx"), 10)
	if got := res.DIZ[5]; got != "| © by gravedancer@poboxes.com of desaster |" {
		t.Errorf("Latin-1 line %q", got)
	}
}

func TestExamineFallbacks(t *testing.T) {
	// LhA with an Aminet readme inside.
	res, _ := Examine(td("quicksketch.lha"), 10)
	want := []Candidate{
		{"Aminet Short:", []string{"A simple WB-prg to sketch and write in."}},
		{"from QuickSketch.readme", []string{
			"This program is much like QuickNote but with",
			"drawing facilities!",
			"(QuickNote can also be found on OnyxSoft",
			"homegpage.)",
			"Have you ever felt the need to just sketch",
			"something down, just to",
		}},
		{"contents", []string{"Contains: QuickSketch/"}},
	}
	if res.DIZ != nil || !reflect.DeepEqual(res.Candidates, want) {
		t.Errorf("quicksketch: %q", res.Candidates)
	}

	// LZX with a .doc only.
	res, _ = Examine(td("msgconvert02.lzx"), 3)
	if len(res.Candidates) != 2 || res.Candidates[0].Source != "from MSGConvert.doc" ||
		len(res.Candidates[0].Lines) != 3 ||
		res.Candidates[0].Lines[0] != "FAME MsgBase-Converter V0.2 by SieGeL of" {
		t.Errorf("msgconvert02: %q", res.Candidates)
	}

	// LZX with nothing to read: only the contents.
	res, _ = Examine(td("config03.lzx"), 10)
	if !reflect.DeepEqual(res.Candidates, []Candidate{{"contents", []string{"Contains: NF-Config, NF-Config.history"}}}) {
		t.Errorf("config03: %q", res.Candidates)
	}

	// Level 1 LhA with directories, readme two levels down, COPYING skipped.
	res, _ = Examine(td("ls-level1.lha"), 10)
	if len(res.Candidates) == 0 || res.Candidates[0].Source != "from README" {
		t.Errorf("ls-level1: %q", res.Candidates)
	}
}

func TestExamine7z(t *testing.T) {
	res, err := Examine(td("tool.7z"), 10)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"Tool v1.0 - a 7-Zip test archive", "for the BBX DIZ reader"}
	if res.Format != "7z" || !reflect.DeepEqual(res.DIZ, want) {
		t.Errorf("7z: %q %q", res.Format, res.DIZ)
	}
}

func TestExamineDMSAndOthers(t *testing.T) {
	res, err := Examine(td("MTS-LS33.DMS"), 10)
	if err != nil || res.Format != "dms" || res.DIZ == nil || len(res.Candidates) != 0 {
		t.Errorf("dms: %+v %v", res, err)
	}
	// A golden .diz file is plain text, not an archive.
	res, err = Examine(td("golden/AFL-NM02.LHA.diz"), 10)
	if err != nil || res.Format != "" || res.DIZ != nil {
		t.Errorf("text file: %+v %v", res, err)
	}
	if _, err := Examine(td("no-such-file.lha"), 10); err == nil {
		t.Error("missing file: no error")
	}
}

func writeZip(t *testing.T, path string, files map[string]string, order []string) {
	t.Helper()
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	for _, name := range order {
		f, err := w.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		f.Write([]byte(files[name]))
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, buf.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestExamineZip(t *testing.T) {
	dir := t.TempDir()

	// A PC DIZ: CP437 blocks, ANSI colours, a SAUCE record after Ctrl-Z.
	p := filepath.Join(dir, "PCTOOL.ZIP")
	diz := "\x1b[1;37m\xdb\xdb\xb0 PC Tool 2.0 \xb0\xdb\xdb\x1b[0m\r\n\r\n Does things.\r\n\x1aSAUCE00junk"
	writeZip(t, p, map[string]string{"TOOL.EXE": "MZ", "FILE_ID.DIZ": diz}, []string{"TOOL.EXE", "FILE_ID.DIZ"})
	res, err := Examine(p, 10)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"██░ PC Tool 2.0 ░██", "", " Does things."}; res.Format != "zip" || !reflect.DeepEqual(res.DIZ, want) {
		t.Errorf("zip DIZ %q", res.DIZ)
	}

	// No FILE_ID.DIZ, but another .diz deeper down: it is used.
	p = filepath.Join(dir, "other.zip")
	writeZip(t, p, map[string]string{"a/b/desc.diz": "Other DIZ\n", "x.txt": "hello"}, []string{"x.txt", "a/b/desc.diz"})
	res, _ = Examine(p, 10)
	if !reflect.DeepEqual(res.DIZ, []string{"Other DIZ"}) {
		t.Errorf("other .diz: %q", res.DIZ)
	}

	// No DIZ: readme beats docs and licence; logo art is skipped; the
	// Aminet readme next to the archive gives the Short: line.
	p = filepath.Join(dir, "cooldemo.zip")
	readme := "  ___  ___\n /__/ /__/  //\n\nCool Demo by The Group\n\tReleased at the Party 1996, first place!\n"
	writeZip(t, p, map[string]string{
		"CoolDemo/LICENSE.txt":   "This licence text should not be picked first.",
		"CoolDemo/demo.doc":      "Documentation text for the demo here.",
		"CoolDemo/ReadMe":        readme,
		"CoolDemo/CoolDemo":      "\x00\x00\x03\xf3",
		"CoolDemo/CoolDemo.info": "icon",
		"music.mod":              "M.K.",
	}, []string{"CoolDemo/LICENSE.txt", "CoolDemo/demo.doc", "CoolDemo/ReadMe", "CoolDemo/CoolDemo", "CoolDemo/CoolDemo.info", "music.mod"})
	os.WriteFile(filepath.Join(dir, "cooldemo.readme"), []byte("Short:        Cool AGA demo by Group, 1st at Party 96\nAuthor:       group@example.org\nType:         demo/aga\n\nLong text.\n"), 0o644)
	res, _ = Examine(p, 10)
	want := []Candidate{
		{"Aminet Short:", []string{"Cool AGA demo by Group, 1st at Party 96"}},
		{"from ReadMe", []string{"Cool Demo by The Group", "Released at the Party 1996, first place!"}},
		{"contents", []string{"Contains: CoolDemo/, music.mod"}},
	}
	if res.DIZ != nil || !reflect.DeepEqual(res.Candidates, want) {
		t.Errorf("fallbacks:\n%q\nwant\n%q", res.Candidates, want)
	}

	// Many names: the contents line is wrapped and ends in "...".
	p = filepath.Join(dir, "many.zip")
	files := map[string]string{}
	var order []string
	for i := 0; i < 20; i++ {
		n := "file" + strings.Repeat("x", i%3) + string(rune('a'+i)) + ".bin"
		files[n] = "x"
		order = append(order, n)
	}
	writeZip(t, p, files, order)
	res, _ = Examine(p, 2)
	c := res.Candidates[len(res.Candidates)-1]
	if c.Source != "contents" || len(c.Lines) != 2 {
		t.Errorf("contents %q", c)
	}
	for _, l := range c.Lines {
		if utf8.RuneCountInString(l) > Width {
			t.Errorf("line too long: %q", l)
		}
	}
}

func TestExamineCorruptNeverPanics(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"5D-BCHCK.LHA", "dtr-am21.lzx", "quicksketch.lha", "tool.7z"} {
		orig, _ := os.ReadFile(td(name))
		for i := 0; i < 60; i++ {
			b := append([]byte{}, orig...)
			seed := uint32(i*2654435761 + 3)
			for k := 0; k < 1+i%6; k++ {
				seed = seed*1664525 + 1013904223
				b[int(seed>>8)%len(b)] ^= byte(seed>>3) | 1
			}
			if i%4 == 0 {
				b = b[:int(seed>>4)%len(b)]
			}
			p := filepath.Join(dir, name)
			os.WriteFile(p, b, 0o644)
			if _, err := Examine(p, 10); err != nil {
				t.Errorf("%s #%d: %v", name, i, err)
			}
		}
	}
}
