package diz

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// Contents lists files and folders in the archive's order, with the sizes
// and dates from the headers. Dates are compared as shown, wall clock.
func TestContents(t *testing.T) {
	cases := []struct {
		path, format string
		count        int
		want         []Entry // the first entries; Time checked when set
	}{
		{td("config03.lzx"), "lzx", 3, []Entry{
			{Name: "NF-Config", Size: 15804, Time: wall("1996-03-03 15:28:36")},
			{Name: "NF-Config.history", Size: 987},
			{Name: "NF-Config.info", Size: 1664},
		}},
		{td("ls-level1.lha"), "lha", 24, []Entry{
			{Name: "Ls/ALIASES/", Size: 0},
			{Name: "Ls/ALIASES/hexls", Size: 33, Time: wall("1992-12-05 15:19:44")},
			{Name: "Ls/ALIASES/timels", Size: 215},
			{Name: "Ls/COPYING", Size: 17982},
		}},
		{td("tool.7z"), "7z", 3, []Entry{{Name: "Tool/", Size: 0}, {Name: "Tool/ReadMe", Size: 37}}},
		{pcFile("TWWORM.ARJ"), "arj", 10, []Entry{
			{Name: "ROAMWH.EXE", Size: 12944},
			{Name: "FILE_ID.DIZ", Size: 120, Time: wall("1993-04-02 21:13:12")},
		}},
		{pcFile("COCO2-14.RAR"), "rar", 12, []Entry{{Name: "COCO.DOC", Size: 41108}}},
		{pcFile("FADER.CAB"), "cab", 5, []Entry{{Name: "Fader_t.class", Size: 4483, Time: wall("1997-11-16 17:18:26")}}},
		{pcFile("2001.ARC"), "arc", 3, []Entry{{Name: "2001.doc", Size: 801, Time: wall("1987-04-21 17:21:08")}}},
		{pcFile("PMLDOC19.ZOO"), "zoo", 2, []Entry{{Name: "doc/header.r", Size: 7828}}},
		{pcFile("OX.ZIP"), "zip", 4, []Entry{{Name: "OX", Size: 149, Time: wall("1986-12-26 22:38:12")}}},
		{pcFile("files.tar.xz"), "xz", 8, []Entry{{Name: "FILE_ID.DIZ", Size: 98}}},
		{pcFile("README.TXT.gz"), "gzip", 1, []Entry{{Name: "README.TXT", Size: 3000}}},
		{pcFile("PAK251.EXE"), "sfx", 9, []Entry{{Name: "READ.ME", Size: 953}}},
		{diskTD("AMOSPRO4.DMS"), "dms", 17, []Entry{
			{Name: "Menu_Editor.AMOS", Size: 358, Time: wall("1992-10-04 14:34:33")},
		}},
		{diskTD("ofs.adz"), "adz", 109, []Entry{
			{Name: "ReadMe", Size: 81}, {Name: "many/", Size: 0}, {Name: "FILE_ID.DIZ", Size: 51},
		}},
	}
	for _, c := range cases {
		if !present(c.path) {
			t.Logf("%s is not published, skipped", c.path)
			continue
		}
		es, format, err := Contents(c.path)
		if err != nil || format != c.format || len(es) != c.count {
			t.Errorf("%s: %s, %d entries, %v; want %s, %d", c.path, format, len(es), err, c.format, c.count)
			continue
		}
		for i, w := range c.want {
			g := es[i]
			if g.Name != w.Name || g.Size != w.Size || !w.Time.IsZero() && g.Time.Format(wallFormat) != w.Time.Format(wallFormat) {
				t.Errorf("%s entry %d: %q %d %s, want %q %d %s", c.path, i, g.Name, g.Size,
					g.Time.Format(wallFormat), w.Name, w.Size, w.Time.Format(wallFormat))
			}
		}
	}

	// A file that is not an archive, and one that is not there.
	p := filepath.Join(t.TempDir(), "notes.txt")
	os.WriteFile(p, []byte("just some text\n"), 0o644)
	if es, format, err := Contents(p); es != nil || format != "" || err != nil {
		t.Errorf("text file: %v %q %v", es, format, err)
	}
	if _, _, err := Contents(filepath.Join(t.TempDir(), "gone.lha")); err == nil {
		t.Error("missing file: no error")
	}
}

const wallFormat = "2006-01-02 15:04:05"

// wall is a stored wall-clock date, compared as it would be shown.
func wall(s string) time.Time {
	tm, err := time.Parse(wallFormat, s)
	if err != nil {
		panic(err)
	}
	return tm
}
