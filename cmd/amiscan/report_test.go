package main

import (
	"flag"
	"os"
	"strings"
	"testing"
)

func TestVerdictAndCodes(t *testing.T) {
	top := "UP.LHA"
	for _, c := range []struct {
		items []finding
		code  int
		msg   string
	}{
		{nil, codePass, "is clean"},
		{[]finding{{Path: top + "/a", Result: resVirus, Virus: "SCA"}, {Path: top + "/b", Result: resVirus, Virus: "SCA"},
			{Path: top + "/c", Result: resVirus, Virus: "Lamer"}, {Path: top + "/d", Result: resDamaged, Reason: "CRC"}},
			codeVirus, "is infected with SCA, Lamer"},
		{[]finding{{Path: top + "/x", Result: resUnchecked, Reason: "too big"}, {Path: top + "/y", Result: resDamaged, Reason: "lha: CRC mismatch"}},
			codeCorrupted, "is corrupted: y: lha: CRC mismatch"},
		{[]finding{{Path: top + " (packed contents)", Result: resUnchecked, Reason: "XPK Crypted needs a password to unpack"},
			{Path: top + "/z", Result: resUnchecked, Reason: "too big"}},
			codeUnchecked, "could not be checked: the file itself (packed contents): XPK Crypted needs a password to unpack (and 1 more)"},
	} {
		st := &fileState{top: top, worst: resClean}
		for _, f := range c.items {
			f.Top = top
			if rank[f.Result] > rank[st.worst] {
				st.worst = f.Result
			}
			st.items = append(st.items, f)
		}
		if got := verdict(st); codeOf[st.worst] != c.code || got != c.msg {
			t.Errorf("got %d %q, want %d %q", codeOf[st.worst], got, c.code, c.msg)
		}
	}
}

func TestParseShow(t *testing.T) {
	s, err := parseShow("viruses, corrupted,skipped")
	if err != nil || !s[resVirus] || !s[resDamaged] || !s[resUnchecked] || s[resClean] {
		t.Fatalf("%v %v", s, err)
	}
	if _, err := parseShow("bogus"); err == nil {
		t.Fatal("bogus kind accepted")
	}
}

func TestUniform(t *testing.T) {
	if !uniform(nil) || !uniform(make([]byte, 1000)) || uniform([]byte{0, 0, 1}) {
		t.Fatal("uniform is wrong")
	}
}

func TestOptionsFirst(t *testing.T) {
	// main registers the real options; these two stand in for them
	if flag.Lookup("max") == nil {
		flag.String("max", "", "")
		flag.Bool("bbs", false, "")
	}
	got := strings.Join(optionsFirst([]string{"up.lha", "-max", "300M", "-bbs", "-o=r.html", "two.lha", "-bogus", "--", "-name"}), " ")
	if want := "-max 300M -bbs -o=r.html -bogus -- up.lha two.lha -name"; got != want {
		t.Fatalf("got %q\nwant %q", got, want)
	}
}

// The manual page must name the same version as the program.
func TestManPageVersion(t *testing.T) {
	b, err := os.ReadFile("../../man/amiscan.1")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"AmiScan `+version+`"`) {
		t.Errorf("man/amiscan.1 .TH does not say AmiScan %s", version)
	}
	for _, f := range []string{"-max", "-max-total", "-bbs", "-update", "-show", "-format"} {
		if !strings.Contains(string(b), strings.ReplaceAll(f, "-", `\-`)) { // roff writes - as \-
			t.Errorf("man page does not describe %s", f)
		}
	}
}
