package main

import "testing"

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
