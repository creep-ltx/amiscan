package main

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// Exit status and -bbs codes, as Amiga BBS file checkers report them.
const (
	codePass      = 0
	codeVirus     = 1
	codeCorrupted = 2
	codeUnchecked = 3 // also: AmiScan itself could not run
)

// rank orders results by how bad they are; the worst one decides a file's code.
var rank = map[string]int{resClean: 0, resUnchecked: 1, resDamaged: 2, resVirus: 3}

var codeOf = map[string]int{resClean: codePass, resVirus: codeVirus, resDamaged: codeCorrupted, resUnchecked: codeUnchecked}

// Output modes.
const (
	outText = "text"
	outJSON = "json"
	outBBS  = "bbs"
)

// fileState collects what was found in one file on disk.
type fileState struct {
	top   string
	worst string
	items []finding // everything not clean
}

type reporter struct {
	mode  string
	show  map[string]bool // which results the text report lists
	start time.Time

	files, boots, unpacked int
	counts                 map[string]int // per result
	listed                 []finding      // for the text report, in order
	cur                    *fileState
	worst                  string // over all files
}

func newReporter(mode string, show map[string]bool) *reporter {
	return &reporter{mode: mode, show: show, start: time.Now(), counts: map[string]int{}, worst: resClean}
}

// begin and end bracket the findings of one file on disk.
func (r *reporter) begin(top string) { r.cur = &fileState{top: top, worst: resClean} }

func (r *reporter) end(top string) {
	st := r.cur
	r.cur = nil
	if st == nil {
		return
	}
	if rank[st.worst] > rank[r.worst] {
		r.worst = st.worst
	}
	if r.mode == outBBS {
		fmt.Printf("%d %s %s\n", codeOf[st.worst], st.top, verdict(st))
	}
}

func (r *reporter) add(f finding) {
	if r.cur == nil || r.cur.top != f.Top { // a problem outside any file (an unreadable folder)
		r.begin(f.Top)
		defer r.end(f.Top)
	}
	if f.Result != resUnchecked {
		if f.Kind == "boot" {
			r.boots++
		} else {
			r.files++
		}
	}
	r.counts[f.Result]++
	if rank[f.Result] > rank[r.cur.worst] {
		r.cur.worst = f.Result
	}
	if f.Result != resClean {
		r.cur.items = append(r.cur.items, f)
	}
	switch r.mode {
	case outJSON:
		b, _ := json.Marshal(f)
		fmt.Println(string(b))
	case outText:
		if r.show[f.Result] {
			r.listed = append(r.listed, f)
		}
	}
}

// inside is where in its file on disk a finding is.
func inside(f finding) string {
	in := strings.TrimSpace(strings.TrimPrefix(strings.TrimPrefix(f.Path, f.Top), "/"))
	if in == "" {
		return "(the file itself)"
	}
	if strings.HasPrefix(in, "(") {
		return "the file itself " + in
	}
	return in
}

// verdict is the -bbs message for one file.
func verdict(st *fileState) string {
	var names, reasons []string
	seen := map[string]bool{}
	for _, f := range st.items {
		switch {
		case f.Result == resVirus && !seen[f.Virus]:
			seen[f.Virus] = true
			names = append(names, f.Virus)
		case f.Result == st.worst && f.Result != resVirus:
			reasons = append(reasons, inside(f)+": "+f.Reason)
		}
	}
	more := func() string {
		if len(reasons) > 1 {
			return fmt.Sprintf(" (and %d more)", len(reasons)-1)
		}
		return ""
	}
	switch st.worst {
	case resVirus:
		return "is infected with " + strings.Join(names, ", ")
	case resDamaged:
		return "is corrupted: " + reasons[0] + more()
	case resUnchecked:
		return "could not be checked: " + reasons[0] + more()
	}
	return "is clean"
}

var sections = []struct{ result, title string }{
	{resVirus, "Viruses"},
	{resDamaged, "Damaged, checked as far as they unpack"},
	{resUnchecked, "Not checked"},
	{resClean, "Clean"},
}

// finish prints the report and returns the exit status.
func (r *reporter) finish() int {
	took := time.Since(r.start).Round(time.Millisecond)
	code := codeOf[r.worst]
	switch r.mode {
	case outJSON:
		b, _ := json.Marshal(map[string]any{
			"summary": true, "files": r.files, "bootblocks": r.boots, "unpacked": r.unpacked,
			"viruses": r.counts[resVirus], "damaged": r.counts[resDamaged], "unchecked": r.counts[resUnchecked],
			"seconds": took.Seconds(), "exit": code,
		})
		fmt.Println(string(b))
		return code
	case outBBS:
		return code
	}
	for _, sec := range sections {
		if !r.show[sec.result] || r.counts[sec.result] == 0 {
			continue
		}
		fmt.Printf("\n%s (%d):\n", sec.title, r.counts[sec.result])
		last := ""
		for _, f := range r.listed {
			if f.Result != sec.result {
				continue
			}
			if f.Top != last {
				fmt.Printf("\n  %s\n", f.Top)
				last = f.Top
			}
			switch f.Result {
			case resVirus:
				extra := ""
				if f.FoundBy == "bootblock database" {
					extra = ", found by the boot block database"
				}
				if f.Reason != "" {
					extra += "; " + f.Reason
				}
				fmt.Printf("      %s: %s (%s%s)\n", inside(f), f.Virus, f.Type, extra)
			case resClean:
				fmt.Printf("      %s: %s\n", inside(f), f.Type)
			default:
				fmt.Printf("      %s: %s\n", inside(f), f.Reason)
			}
		}
	}
	plural := func(n int, one, many string) string {
		if n == 1 {
			return "1 " + one
		}
		return fmt.Sprintf("%d %s", n, many)
	}
	unpacked := ""
	if r.unpacked > 0 {
		unpacked = fmt.Sprintf(" (%d of them unpacked)", r.unpacked)
	}
	var found []string
	if n := r.counts[resVirus]; n > 0 {
		found = append(found, strings.ToUpper(plural(n, "virus", "viruses")))
	}
	if n := r.counts[resDamaged]; n > 0 {
		found = append(found, plural(n, "damaged", "damaged"))
	}
	if n := r.counts[resUnchecked]; n > 0 {
		found = append(found, plural(n, "not checked", "not checked"))
	}
	if len(found) == 0 {
		found = []string{"nothing found"}
	}
	fmt.Printf("\nChecked %s%s and %s in %s: %s.\n", plural(r.files, "file", "files"), unpacked,
		plural(r.boots, "boot block", "boot blocks"), took, strings.Join(found, ", "))
	return code
}
