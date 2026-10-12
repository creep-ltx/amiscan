// Package diz finds the description of an uploaded file: the FILE_ID.DIZ
// inside an archive, cleaned to the DIZ rules (at most 45 columns by the
// board's line limit), or, when there is none, other descriptions to offer
// the uploader: an Aminet "Short:" line, real text from a readme, or the
// names inside. The fallback rules are those of the sysop's dizlist tool.
//
// Archives (LhA, LZX, Zip incl. PKZIP 1.x methods, 7z, RAR, ARJ, ARC/PAK, ZOO,
// CAB, tar with gzip/bzip2/xz, self-extracting programs) and Amiga disk images
// (ADF, ADZ, DMS, HDF) are read in pure Go, in memory. Formats register
// themselves: see archive.go, disk.go and pc.go.
package diz

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode"
)

// Candidate is one possible description for an archive.
type Candidate struct {
	Source string   // "FILE_ID.DIZ", "Aminet Short:", "from ReadMe.txt", "contents"
	Lines  []string // cleaned, Unicode, each at most 45 runes, at most maxLines lines
}

// Result of examining one file.
type Result struct {
	DIZ        []string    // the archive's own FILE_ID.DIZ (or other .diz), cleaned; nil if none or unreadable
	Candidates []Candidate // fallbacks found when DIZ is nil, best first (Short:, readme, contents); empty when DIZ != nil
	Format     string      // "lha", "lzx", "zip", "7z", "dms", "" (unknown/not an archive)
}

const (
	dizLimit   = 64 << 10 // bytes read from a .diz
	docLimit   = 30000    // bytes read from a readme (as dizlist)
	docLines   = 4        // lines of real text taken from a readme
	proseLines = 6        // at most this many once wrapped (as dizlist)
)

// Examine opens the file at path and finds its description. maxLines is the
// board's line limit (default 10). It never panics on corrupt input; it
// returns an error only when the file cannot be opened or read.
func Examine(path string, maxLines int) (res Result, err error) {
	if maxLines <= 0 {
		maxLines = DefaultLines
	}
	f, size, f0, err := sniff(path)
	if err != nil {
		return Result{}, err
	}
	defer f.Close()

	defer func() {
		// A decoder bug on strange data must not take the board down.
		if r := recover(); r != nil {
			res.DIZ = nil
			res.Candidates = nil
		}
	}()

	var members []member
	var extra []Candidate
	if f0 != nil {
		var ok bool
		if members, extra, ok = list(f, size, f0); ok {
			res.Format = f0.name
		}
	}
	sort.SliceStable(members, func(i, j int) bool { return members[i].name < members[j].name })

	if d := findDIZ(members, maxLines); d != nil {
		res.DIZ = d
		return res, nil
	}
	res.Candidates = withExtra(fallbacks(path, members, maxLines), extra, maxLines)
	return res, nil
}

// sniff opens the file at path and names its format (nil when unknown).
func sniff(path string) (f *os.File, size int64, f0 *format, err error) {
	f, err = os.Open(path)
	if err != nil {
		return nil, 0, nil, err
	}
	st, err := f.Stat()
	if err == nil && st.IsDir() {
		err = fmt.Errorf("diz: %s is a directory", path)
	}
	if err != nil {
		f.Close()
		return nil, 0, nil, err
	}
	head := make([]byte, headSize)
	n, err := f.ReadAt(head, 0)
	if err != nil && n == 0 && st.Size() > 0 {
		f.Close()
		return nil, 0, nil, err
	}
	ext := strings.ToLower(strings.TrimPrefix(filepath.Ext(path), "."))
	return f, st.Size(), detect(head[:n], st.Size(), ext), nil
}

// Entry is one file or folder inside an archive or disk image.
type Entry struct {
	Name string    // '/' separated path inside the archive; folders end in '/'
	Size int64     // unpacked size in bytes, -1 when the format does not say (0 for folders)
	Time time.Time // date stored in the archive, zero when unknown; format it as it is (see package stamp)
}

// Contents lists what is inside the archive or disk image at path, in the
// archive's own order (not sorted), and the format name as in Result.Format.
// A hard disk image's partitions come as folders. For a file that is not an
// archive it returns format "" and no entries. Nothing is unpacked to find
// sizes (a DMS or ADZ is, as it has to be to read the disk). It never panics
// on corrupt input; it returns an error only when the file cannot be opened
// or read.
func Contents(path string) (entries []Entry, format string, err error) {
	f, size, f0, err := sniff(path)
	if err != nil {
		return nil, "", err
	}
	defer f.Close()
	if f0 == nil {
		return nil, "", nil
	}
	defer func() {
		// A decoder bug on strange data must not take the board down.
		if r := recover(); r != nil {
			entries, format, err = nil, "", nil
		}
	}()
	ms, _, ok := listAll(f, size, f0)
	if !ok {
		return nil, "", nil
	}
	entries = make([]Entry, 0, len(ms))
	for _, m := range ms {
		if m.name == "." || m.name == "./" {
			continue
		}
		entries = append(entries, Entry{Name: m.name, Size: m.size, Time: m.time})
	}
	return entries, f0.name, nil
}

// withExtra puts the format's own descriptions just before the "Contains: ..."
// candidate, cleaned to the board's rules.
func withExtra(cands, extra []Candidate, maxLines int) []Candidate {
	if len(extra) == 0 {
		return cands
	}
	var clean []Candidate
	for _, e := range extra {
		if lines := Clean([]byte(strings.Join(e.Lines, "\n")), maxLines); lines != nil {
			clean = append(clean, Candidate{Source: e.Source, Lines: lines})
		}
	}
	at := len(cands)
	for i, c := range cands {
		if c.Source == "contents" {
			at = i
			break
		}
	}
	out := append(append(append([]Candidate{}, cands[:at]...), clean...), cands[at:]...)
	return out
}

// findDIZ returns the cleaned FILE_ID.DIZ, or another .diz, as dizlist picks
// them: FILE_ID.DIZ first, shortest path first, at most two tried.
func findDIZ(ms []member, maxLines int) []string {
	var ids, others, sdi []member // DESC.SDI: the old one-line PC alternative
	for _, m := range ms {
		base := strings.ToLower(baseName(m.name))
		switch {
		case base == "file_id.diz":
			ids = append(ids, m)
		case strings.HasSuffix(base, ".diz"):
			others = append(others, m)
		case base == "desc.sdi":
			sdi = append(sdi, m)
		}
	}
	byLen := func(s []member) {
		sort.SliceStable(s, func(i, j int) bool { return len(s[i].name) < len(s[j].name) })
	}
	byLen(ids)
	byLen(others)
	tries := append(ids, others...)
	if len(tries) > 2 {
		tries = tries[:2]
	}
	tries = append(tries, sdi...)
	for _, m := range tries {
		raw, err := m.read(dizLimit)
		if err != nil {
			continue
		}
		if strings.EqualFold(baseName(m.name), "desc.sdi") {
			// one line of up to about 60 characters: wrap it to the DIZ width
			var lines []string
			for _, l := range strings.Split(strings.ReplaceAll(string(raw), "\r", ""), "\n") {
				lines = append(lines, wrap(l)...)
			}
			raw = []byte(strings.Join(lines, "\n"))
		}
		if lines := Clean(raw, maxLines); lines != nil {
			return lines
		}
	}
	return nil
}

func baseName(name string) string {
	if i := strings.LastIndexByte(name, '/'); i >= 0 {
		return name[i+1:]
	}
	return name
}

var (
	docName  = regexp.MustCompile(`(?i)(^|/)(read[._ -]?me|readme[^/]*|[^/]*\.(readme|doc|docs|txt|nfo|guide|diz|1st|asc|ann))$`)
	docSkip  = regexp.MustCompile(`(?i)(licen[cs]e|copying|gpl|history|changes|changelog|todo|install)`)
	docRead  = regexp.MustCompile(`(?i)read`)
	docExt   = regexp.MustCompile(`(?i)\.(doc|docs|guide|nfo|ann|1st)$`)
	guideTag = regexp.MustCompile(`@\{[^}]*\}`)
	aminet   = regexp.MustCompile(`(?i)^(short|author|uploader|type|version|architecture|requires|replaces|distribution|kurz|url|email|e-mail|date|origin|license|licence)\s*:`)
)

// pickDocs returns the readme-like files, best first (at most three):
// readme > doc/guide/nfo > txt, licence and history files last.
func pickDocs(ms []member) []member {
	var c []member
	for _, m := range ms {
		if docName.MatchString(m.name) && !strings.HasSuffix(strings.ToLower(m.name), ".info") {
			c = append(c, m)
		}
	}
	rank := func(n string) int {
		switch {
		case docRead.MatchString(n):
			return 0
		case docExt.MatchString(n):
			return 1
		}
		return 2
	}
	sort.SliceStable(c, func(i, j int) bool {
		a, b := c[i].name, c[j].name
		sa, sb := docSkip.MatchString(baseName(a)), docSkip.MatchString(baseName(b))
		if sa != sb {
			return !sa
		}
		if ra, rb := rank(a), rank(b); ra != rb {
			return ra < rb
		}
		if da, db := strings.Count(a, "/"), strings.Count(b, "/"); da != db {
			return da < db
		}
		return len(a) < len(b)
	})
	if len(c) > 3 {
		c = c[:3]
	}
	return c
}

// doc is a readme's text, ready for the line rules.
type doc struct {
	name string
	text string
}

func readDoc(name string, raw []byte) doc {
	if len(raw) > docLimit {
		raw = raw[:docLimit]
	}
	t := decode(raw)
	t = strings.ReplaceAll(strings.ReplaceAll(t, "\r\n", "\n"), "\r", "\n")
	if strings.HasSuffix(strings.ToLower(name), ".guide") {
		// AmigaGuide: drop @{...} codes and @ command lines.
		t = guideTag.ReplaceAllString(t, "")
		var keep []string
		for _, l := range strings.Split(t, "\n") {
			if !strings.HasPrefix(strings.TrimLeft(l, " \t"), "@") {
				keep = append(keep, l)
			}
		}
		t = strings.Join(keep, "\n")
	}
	return doc{name: baseName(name), text: t}
}

// short returns the Aminet "Short:" line from the first 15 lines.
func (d doc) short() string {
	for i, l := range strings.Split(d.text, "\n") {
		if i == 15 {
			break
		}
		if strings.HasPrefix(strings.ToLower(l), "short:") {
			return strings.TrimSpace(l[len("short:"):])
		}
	}
	return ""
}

// wordy is dizlist's test for real text: at least 4 letters, and letters
// make up at least 45% of the line. Logo art fails it.
func wordy(l string) bool {
	letters, n := 0, 0
	for _, c := range strings.TrimSpace(l) {
		n++
		if unicode.IsLetter(c) {
			letters++
		}
	}
	return letters >= 4 && float64(letters) >= 0.45*float64(n)
}

// prose returns up to docLines lines of real text, wrapped to Width.
func (d doc) prose(maxLines int) []string {
	var keep []string
	for _, l := range strings.Split(d.text, "\n") {
		l = strings.Join(strings.Fields(cleanControls(l)), " ")
		if aminet.MatchString(l) || !wordy(l) {
			continue
		}
		keep = append(keep, l)
		if len(keep) == docLines {
			break
		}
	}
	var lines []string
	for _, l := range keep {
		lines = append(lines, wrap(l)...)
	}
	return cleanText(strings.Join(lines, "\n"), min(maxLines, proseLines))
}

// cleanControls drops control characters (tabs become spaces).
func cleanControls(s string) string {
	return strings.Map(func(c rune) rune {
		switch {
		case c == '\t':
			return ' '
		case c < 0x20, c == 0x7f, c >= 0x80 && c < 0xa0:
			return -1
		}
		return c
	}, s)
}

// fallbacks finds the descriptions to offer when there is no DIZ.
func fallbacks(path string, ms []member, maxLines int) []Candidate {
	var docs []doc
	for _, m := range pickDocs(ms) {
		if raw, err := m.read(docLimit); err == nil && len(raw) > 0 {
			docs = append(docs, readDoc(m.name, raw))
		}
	}
	// An Aminet upload has its readme next to the archive.
	stem := strings.TrimSuffix(path, filepath.Ext(path))
	for _, side := range []string{stem + ".readme", stem + ".README"} {
		if raw, err := readStart(side, docLimit); err == nil && len(raw) > 0 {
			docs = append(docs, readDoc(side, raw))
			break
		}
	}

	var out []Candidate
	for _, d := range docs {
		if s := d.short(); s != "" {
			if lines := cleanText(strings.Join(wrap(s), "\n"), maxLines); lines != nil {
				out = append(out, Candidate{Source: "Aminet Short:", Lines: lines})
				break
			}
		}
	}
	for _, d := range docs {
		if lines := d.prose(maxLines); lines != nil {
			out = append(out, Candidate{Source: "from " + d.name, Lines: lines})
			break
		}
	}
	if lines := contents(ms, maxLines); lines != nil {
		out = append(out, Candidate{Source: "contents", Lines: lines})
	}
	return out
}

func readStart(path string, limit int) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b := make([]byte, limit)
	n, _ := f.Read(b)
	return b[:n], nil
}

// contents is "Contains: a, b/, c" with the top-level names (icons left out).
func contents(ms []member, maxLines int) []string {
	var top []string
	seen := map[string]bool{}
	for _, m := range ms {
		n := strings.Trim(m.name, "/")
		if n == "" || strings.HasSuffix(strings.ToLower(n), ".info") {
			continue
		}
		k := n
		if i := strings.IndexByte(n, '/'); i >= 0 {
			k = n[:i+1]
		}
		if !seen[k] {
			seen[k] = true
			top = append(top, k)
		}
	}
	if len(top) == 0 {
		return nil
	}
	more := ""
	if len(top) > 12 {
		top, more = top[:12], ", ..."
	}
	s := "Contains: " + strings.Join(top, ", ") + more
	return cleanText(strings.Join(wrap(s), "\n"), maxLines)
}
