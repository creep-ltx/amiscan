package diz

import (
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func diskTD(name string) string { return filepath.Join("testdata", "disk", name) }

func sources(cs []Candidate) []string {
	var s []string
	for _, c := range cs {
		s = append(s, c.Source)
	}
	return s
}

var testDiskDIZ = []string{" BBX TEST DISK", " Made by xdftool for the unit tests"}

// Every floppy type, gzipped (ADZ): the FILE_ID.DIZ on the disk is found.
func TestExamineADZ(t *testing.T) {
	for _, n := range []string{"ofs", "ffs", "ofs-intl", "ffs-intl", "ofs-dc", "ffs-dc", "ffs-hd"} {
		res, err := Examine(diskTD(n+".adz"), 10)
		if err != nil || res.Format != "adz" || !reflect.DeepEqual(res.DIZ, testDiskDIZ) {
			t.Errorf("%s: %+v %v", n, res, err)
		}
	}
}

func gunzipTo(t *testing.T, src, dst string) string {
	t.Helper()
	f, err := os.Open(src)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	z, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	var b bytes.Buffer
	b.ReadFrom(z)
	p := filepath.Join(t.TempDir(), dst)
	if err := os.WriteFile(p, b.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestExamineADFAndHDF(t *testing.T) {
	// Plain ADF, found by its size and "DOS".
	p := gunzipTo(t, diskTD("ffs.adz"), "disk.img")
	res, err := Examine(p, 10)
	if err != nil || res.Format != "adf" || !reflect.DeepEqual(res.DIZ, testDiskDIZ) {
		t.Errorf("adf: %+v %v", res, err)
	}
	// RDB hard disk image: DH0 (FFS, readme), WORK (OFS, the DIZ), PFS (not read).
	p = gunzipTo(t, diskTD("rdb.hdf.gz"), "test.hdf")
	res, err = Examine(p, 10)
	if err != nil || res.Format != "hdf" || !reflect.DeepEqual(res.DIZ, testDiskDIZ) {
		t.Errorf("hdf: %+v %v", res, err)
	}
	f, _ := os.Open(p)
	defer f.Close()
	st, _ := f.Stat()
	ms, extra, err := openHDF(f, st.Size())
	count := map[string]int{}
	for _, m := range readable(ms) {
		count[m.name[:strings.IndexByte(m.name, '/')]]++
	}
	if err != nil || count["DH0"] != 102 || count["WORK"] != 2 || len(count) != 2 {
		t.Errorf("hdf members: %v %v", count, err)
	}
	if len(extra) != 1 || strings.Join(extra[0].Lines, " ") != "Hard disk: DH0: System, WORK: Work, PFS (PFS\\3, not read)" {
		t.Errorf("hdf extra: %q", extra)
	}
}

func TestExamineDMS(t *testing.T) {
	// The FILE_ID.DIZ a BBS attached as track 80.
	res, err := Examine(td("MTS-LS33.DMS"), 10)
	if err != nil || res.Format != "dms" || len(res.DIZ) != 10 || res.DIZ[8] != "      LogonStartup v0.33 by WD/MtS" {
		t.Errorf("MTS-LS33: %q %v", res.DIZ, err)
	}
	// No DIZ: the readme on the disk, the banner, the disk itself.
	res, err = Examine(diskTD("AMOSPRO4.DMS"), 10)
	if err != nil || res.DIZ != nil {
		t.Fatalf("AMOSPRO4: %+v %v", res, err)
	}
	if got := sources(res.Candidates); strings.Join(got, ",") != "from AMOSPro_Help.Txt,DMS banner,disk,contents" {
		t.Errorf("AMOSPRO4 candidates %q", got)
	}
	disk := res.Candidates[2].Lines
	if disk[0] != "Disk: AMOSPro_Accessories" || !strings.HasPrefix(disk[1], "Contains: AMAL_Editor.AMOS, AMOSPro_Help,") {
		t.Errorf("disk candidate %q", disk)
	}
	if !strings.Contains(strings.Join(res.Candidates[1].Lines, "\n"), "IMPACT UK") {
		t.Errorf("banner %q", res.Candidates[1].Lines)
	}
	// The all-modes test file is no AmigaDOS disk; the generator wrote random tracks.
	res, _ = Examine(diskTD("modes.dms"), 10)
	if res.Format != "dms" || len(res.Candidates) == 0 || res.Candidates[0].Source != "disk" {
		t.Errorf("modes.dms: %+v", res)
	}
}

func TestExamineNotDOS(t *testing.T) {
	img := make([]byte, 901120)
	copy(img, "BOOT\x00\x00\x00\x00\x60\x00Mega Game cracked by the Gang - call our board!\x00\x4e\x75")
	p := filepath.Join(t.TempDir(), "game.adf")
	os.WriteFile(p, img, 0o644)
	res, err := Examine(p, 10)
	want := []Candidate{
		{"disk", []string{"Not an AmigaDOS disk (boot block only)"}},
		{"boot block", []string{"Mega Game cracked by the Gang - call our", "board!"}},
	}
	if err != nil || res.Format != "adf" || !reflect.DeepEqual(res.Candidates, want) {
		t.Errorf("%+v %v", res, err)
	}
}

// hunkFile is a tiny Amiga program: one code hunk holding text.
func hunkFile(text string) []byte {
	for len(text)%4 != 0 {
		text += "\x00"
	}
	var b bytes.Buffer
	w := func(v ...uint32) { binary.Write(&b, binary.BigEndian, v) }
	n := uint32(len(text) / 4)
	w(0x3f3, 0, 1, 0, 0, n, 0x3e9, n)
	b.WriteString(text)
	w(0x3f2)
	return b.Bytes()
}

func TestExamineAmigaExe(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "MyDemo")
	os.WriteFile(p, hunkFile("\x4e\x75$VER: MyDemo 1.2 (12.3.94)\x00"), 0o644)
	res, err := Examine(p, 10)
	want := []Candidate{{"$VER string", []string{"MyDemo 1.2 (12.3.94)"}}}
	if err != nil || res.Format != "amigaexe" || !reflect.DeepEqual(res.Candidates, want) {
		t.Errorf("%+v %v", res, err)
	}
	p = filepath.Join(dir, "NoVer")
	os.WriteFile(p, hunkFile("\x4e\x75 $VER: \x00"), 0o644)
	res, err = Examine(p, 10)
	if err != nil || res.Format != "amigaexe" || len(res.Candidates) != 0 {
		t.Errorf("no $VER: %+v %v", res, err)
	}
}
