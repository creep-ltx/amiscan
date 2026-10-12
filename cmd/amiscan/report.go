package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
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

// Output formats.
const (
	outText     = "text"
	outMarkdown = "markdown"
	outHTML     = "html"
	outJSON     = "json"
	outBBS      = "bbs"
)

// reportInfo is what a saved report says about the scan itself.
type reportInfo struct {
	Started time.Time
	Paths   []string
	Parts   [][2]string // name, version
}

// fileState collects what was found in one file on disk.
type fileState struct {
	top   string
	worst string
	items []finding // everything not clean
}

type reporter struct {
	mode  string
	w     io.Writer // where the report goes
	file  string    // the report file, "" for the terminal
	info  reportInfo
	show  map[string]bool // which results the text report lists
	start time.Time

	files, boots, unpacked int
	counts                 map[string]int // per result
	listed                 []finding      // for the text report, in order
	cur                    *fileState
	worst                  string // over all files
}

func newReporter(mode string, show map[string]bool, w io.Writer) *reporter {
	return &reporter{mode: mode, show: show, w: w, start: time.Now(), counts: map[string]int{}, worst: resClean}
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
		fmt.Fprintf(r.w, "%d %s %s\n", codeOf[st.worst], st.top, verdict(st))
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
		fmt.Fprintln(r.w, string(b))
	case outText, outMarkdown, outHTML:
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

// summary is the one-line result.
func (r *reporter) summary(took time.Duration) string {
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
	return fmt.Sprintf("Checked %s%s and %s in %s: %s.", plural(r.files, "file", "files"), unpacked,
		plural(r.boots, "boot block", "boot blocks"), took, strings.Join(found, ", "))
}

// what is the text of one listed finding after "where:".
func what(f finding) string {
	switch f.Result {
	case resVirus:
		extra := ""
		if f.FoundBy == "bootblock database" {
			extra = ", found by the boot block database"
		}
		if f.Reason != "" {
			extra += "; " + f.Reason
		}
		return fmt.Sprintf("%s (%s%s)", f.Virus, f.Type, extra)
	case resClean:
		return f.Type
	}
	return f.Reason
}

// groups yields the listed findings of one result, file by file.
func (r *reporter) groups(result string, fn func(top string, items []finding)) {
	var top string
	var items []finding
	for _, f := range r.listed {
		if f.Result != result {
			continue
		}
		if f.Top != top && items != nil {
			fn(top, items)
			items = nil
		}
		top = f.Top
		items = append(items, f)
	}
	if items != nil {
		fn(top, items)
	}
}

// finish writes the report and returns the exit status.
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
		fmt.Fprintln(r.w, string(b))
	case outText:
		r.writeText(took)
	case outMarkdown:
		r.writeMarkdown(took)
	case outHTML:
		r.writeHTML(took)
	}
	if r.file != "" { // the terminal still hears how it went
		fmt.Println(r.summary(took))
		fmt.Printf("Report written to %s\n", r.file)
	}
	return code
}

func (r *reporter) writeText(took time.Duration) {
	w := r.w
	if r.file != "" {
		r.writeHeaderText()
	}
	for _, sec := range sections {
		if !r.show[sec.result] || r.counts[sec.result] == 0 {
			continue
		}
		fmt.Fprintf(w, "\n%s (%d):\n", sec.title, r.counts[sec.result])
		r.groups(sec.result, func(top string, items []finding) {
			fmt.Fprintf(w, "\n  %s\n", top)
			for _, f := range items {
				fmt.Fprintf(w, "      %s: %s\n", inside(f), what(f))
			}
		})
	}
	fmt.Fprintf(w, "\n%s\n", r.summary(took))
}

func (r *reporter) writeHeaderText() {
	fmt.Fprintf(r.w, "AmiScan %s report, %s\n", version, r.info.Started.Format("2006-01-02 15:04"))
	fmt.Fprintf(r.w, "Checked: %s\n", strings.Join(r.info.Paths, ", "))
	for _, p := range r.info.Parts {
		fmt.Fprintf(r.w, "  %-20s %s\n", p[0], p[1])
	}
}

// rel shortens a file name to below the folder that was checked, for the
// tables of saved reports (the folder is named at the top).
func (r *reporter) rel(top string) string {
	best := ""
	for _, p := range r.info.Paths {
		p = strings.TrimRight(p, "/")
		if strings.HasPrefix(top, p+"/") && len(p) > len(best) {
			best = p
		}
	}
	if best == "" {
		return top
	}
	return strings.TrimPrefix(top, best+"/")
}

// mdEscape keeps file names from breaking a Markdown table.
func mdEscape(s string) string {
	r := strings.NewReplacer("|", "\\|", "*", "\\*", "_", "\\_", "`", "\\`", "<", "&lt;", ">", "&gt;", "[", "\\[", "]", "\\]")
	return r.Replace(s)
}

func (r *reporter) writeMarkdown(took time.Duration) {
	w := r.w
	fmt.Fprintf(w, "# AmiScan report\n\n")
	fmt.Fprintf(w, "- **When:** %s\n", r.info.Started.Format("2006-01-02 15:04"))
	fmt.Fprintf(w, "- **Checked:** %s\n", mdEscape(strings.Join(r.info.Paths, ", ")))
	fmt.Fprintf(w, "- **Result:** %s\n", mdEscape(r.summary(took)))
	fmt.Fprintf(w, "- **AmiScan %s with:** ", version)
	var parts []string
	for _, p := range r.info.Parts {
		parts = append(parts, p[0]+" "+p[1])
	}
	fmt.Fprintf(w, "%s\n", mdEscape(strings.Join(parts, ", ")))
	for _, sec := range sections {
		if !r.show[sec.result] || r.counts[sec.result] == 0 {
			continue
		}
		head := map[string]string{resVirus: "Virus", resClean: "What it is"}[sec.result]
		if head == "" {
			head = "Why"
		}
		fmt.Fprintf(w, "\n## %s (%d)\n\n| File | Where inside | %s |\n|---|---|---|\n", sec.title, r.counts[sec.result], head)
		r.groups(sec.result, func(top string, items []finding) {
			for i, f := range items {
				name := ""
				if i == 0 {
					name = mdEscape(r.rel(top))
				}
				fmt.Fprintf(w, "| %s | %s | %s |\n", name, mdEscape(inside(f)), mdEscape(what(f)))
			}
		})
	}
}

func (r *reporter) writeHTML(took time.Duration) {
	w := r.w
	esc := htmlEscape
	fmt.Fprintf(w, `<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>AmiScan report %s</title>
<style>
body{font-family:system-ui,sans-serif;margin:2rem auto;max-width:72rem;padding:0 1rem;color:#222;background:#fafafa}
h1{font-size:1.6rem}h2{font-size:1.2rem;margin-top:2rem}
.summary{font-size:1.1rem;padding:.8rem 1rem;border-radius:6px;background:#eef}
.virus h2{color:#b00}.damaged h2{color:#a60}.unchecked h2{color:#555}
table{border-collapse:collapse;width:100%%;font-size:.92rem}
th,td{text-align:left;vertical-align:top;padding:.35rem .6rem;border-bottom:1px solid #ddd}
th{background:#eee}td{overflow-wrap:anywhere}td.file{font-weight:600;width:30%%}td.where{width:35%%}
dl{display:grid;grid-template-columns:max-content 1fr;gap:.2rem 1rem}dt{font-weight:600}
@media (prefers-color-scheme:dark){body{background:#181818;color:#ddd}.summary{background:#223}th{background:#2a2a2a}th,td{border-color:#333}.virus h2{color:#f66}.damaged h2{color:#fb5}.unchecked h2{color:#aaa}}
</style></head><body>
<h1>AmiScan report</h1>
<p class="summary">%s</p>
<dl><dt>When</dt><dd>%s</dd><dt>Checked</dt><dd>%s</dd>
`, esc(r.info.Started.Format("2006-01-02 15:04")), esc(r.summary(took)), esc(r.info.Started.Format("2006-01-02 15:04")), esc(strings.Join(r.info.Paths, ", ")))
	for _, p := range r.info.Parts {
		fmt.Fprintf(w, "<dt>%s</dt><dd>%s</dd>\n", esc(p[0]), esc(p[1]))
	}
	fmt.Fprintf(w, "<dt>AmiScan</dt><dd>%s</dd></dl>\n", esc(version))
	for _, sec := range sections {
		if !r.show[sec.result] || r.counts[sec.result] == 0 {
			continue
		}
		head := map[string]string{resVirus: "Virus", resClean: "What it is"}[sec.result]
		if head == "" {
			head = "Why"
		}
		fmt.Fprintf(w, "<section class=\"%s\"><h2>%s (%d)</h2>\n<table><tr><th>File</th><th>Where inside</th><th>%s</th></tr>\n",
			sec.result, esc(sec.title), r.counts[sec.result], head)
		r.groups(sec.result, func(top string, items []finding) {
			for i, f := range items {
				name := ""
				if i == 0 {
					name = esc(r.rel(top))
				}
				fmt.Fprintf(w, "<tr><td class=\"file\">%s</td><td class=\"where\">%s</td><td>%s</td></tr>\n", name, esc(inside(f)), esc(what(f)))
			}
		})
		fmt.Fprintf(w, "</table></section>\n")
	}
	fmt.Fprintf(w, "</body></html>\n")
}

func htmlEscape(s string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;").Replace(s)
}

// openReport picks the format for -o from -format or the file's extension.
func openReport(path, format string) (io.WriteCloser, string, error) {
	if format == "" {
		switch ext := strings.ToLower(path[strings.LastIndex(path, ".")+1:]); ext {
		case "md", "markdown":
			format = outMarkdown
		case "html", "htm":
			format = outHTML
		case "json", "jsonl":
			format = outJSON
		default:
			format = outText
		}
	}
	f, err := os.Create(path)
	return f, format, err
}
