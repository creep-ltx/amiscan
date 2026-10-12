// Package bootdb reads the boot block database of Amiga Bootblock Reader
// (Jason and Jordan Smith, github.com/jasonthesmith79/AmigaBootBlockReader)
// and names boot blocks with it, matching the way that program does:
// CRC-32 first, then the byte sequences of the search list, then the
// seven offset/value pairs of the main brain file.
package bootdb

import (
	"bytes"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"os"
	"strconv"
	"strings"

	"golang.org/x/text/encoding/charmap"
)

// File names in the libs folder.
const (
	BrainFile  = "abr-brainfile.xml"
	SearchFile = "abr-searchbrain.xml"
)

// Classes are the categories of catlist.xml.
var Classes = map[string]string{
	"5060sw": "50-60Hz switch", "g": "boot game", "bl": "boot loader", "bm": "boot menu",
	"bom": "boot message", "bbc": "boot block copier", "cb": "colour boot", "cp": "copy protection",
	"cu": "custom", "cust": "custom", "ds": "demoscene", "extds": "external drive switch",
	"fakev": "fake virus", "filtled": "filter/LED switch", "ga": "game", "gs": "group spread",
	"i": "intro", "l": "logo", "oldav": "old anti-virus", "palntsc": "PAL/NTSC switch",
	"pass": "password", "pic": "picture", "rsds": "RAM and drives switch", "rs": "RAM switch",
	"rip": "ripper", "sc": "scroller", "s": "standard", "u": "utility", "v": "virus",
	"vfm": "virus-free message", "xc": "X-Copy boot block",
}

// Entry is one known boot block.
type Entry struct {
	Name  string
	Class string // abbreviation, see Classes
	Notes string
	crcs  []uint32
	pairs [][2]int // offset, value
	seq   []byte   // search list: bytes found anywhere
}

// IsVirus reports whether the database calls this boot block a virus.
func (e *Entry) IsVirus() bool { return e.Class == "v" }

// ClassName is the class in words.
func (e *Entry) ClassName() string {
	if n, ok := Classes[e.Class]; ok {
		return n
	}
	return e.Class
}

// DB is the loaded database.
type DB struct {
	main, search []*Entry
}

// Size is how many boot blocks the database knows.
func (db *DB) Size() int { return len(db.main) + len(db.search) }

// Counts are the entries of the brain file and of the search list.
func (db *DB) Counts() (brain, search int) { return len(db.main), len(db.search) }

type xmlEntry struct {
	Name, Recog, Class, Notes, CRC string
}

func parse(data []byte) ([]xmlEntry, error) {
	d := xml.NewDecoder(bytes.NewReader(data))
	d.CharsetReader = func(cs string, r io.Reader) (io.Reader, error) {
		if strings.EqualFold(cs, "windows-1252") {
			return charmap.Windows1252.NewDecoder().Reader(r), nil
		}
		return nil, fmt.Errorf("unknown charset %s", cs)
	}
	var doc struct {
		Entries []xmlEntry `xml:"Bootblock"`
	}
	if err := d.Decode(&doc); err != nil {
		return nil, err
	}
	return doc.Entries, nil
}

// Load reads the brain file and, if present, the search list from dir.
func Load(dir string) (*DB, error) {
	db := &DB{}
	data, err := os.ReadFile(dir + "/" + BrainFile)
	if err != nil {
		return nil, err
	}
	es, err := parse(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", BrainFile, err)
	}
	for _, x := range es {
		if x.Name == "" || x.Name == "DELETED" {
			continue
		}
		e := &Entry{Name: strings.TrimSpace(x.Name), Class: strings.TrimSpace(x.Class), Notes: strings.TrimSpace(x.Notes)}
		for _, c := range strings.Split(x.CRC, ",") {
			if v, err := strconv.ParseUint(strings.TrimSpace(c), 16, 32); err == nil {
				e.crcs = append(e.crcs, uint32(v))
			}
		}
		if nums := strings.Split(x.Recog, ","); len(nums) >= 14 {
			for i := 0; i+1 < 14; i += 2 {
				p, err1 := strconv.Atoi(strings.TrimSpace(nums[i]))
				v, err2 := strconv.Atoi(strings.TrimSpace(nums[i+1]))
				if err1 != nil || err2 != nil || p < 0 || p >= 1024 || (p == 0 && v == 0) {
					e.pairs = nil
					break
				}
				e.pairs = append(e.pairs, [2]int{p, v})
			}
		}
		db.main = append(db.main, e)
	}
	if len(db.main) < 100 {
		return nil, errors.New(BrainFile + ": fewer than 100 boot blocks, not a brain file")
	}
	if data, err := os.ReadFile(dir + "/" + SearchFile); err == nil {
		es, err := parse(data)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", SearchFile, err)
		}
		for _, x := range es {
			seq, err := base64.StdEncoding.DecodeString(strings.TrimSpace(x.Recog))
			if err != nil || len(seq) < 4 {
				continue
			}
			db.search = append(db.search, &Entry{Name: strings.TrimSpace(x.Name), Class: strings.TrimSpace(x.Class),
				Notes: strings.TrimSpace(x.Notes), seq: seq})
		}
	}
	return db, nil
}

// Match names a 1024-byte boot block, or returns nil.
func (db *DB) Match(boot []byte) *Entry {
	if len(boot) < 1024 {
		return nil
	}
	boot = boot[:1024]
	sum := crc32.ChecksumIEEE(boot)
	for _, e := range db.main {
		for _, c := range e.crcs {
			if c == sum {
				return e
			}
		}
	}
	for _, e := range db.search {
		if bytes.Contains(boot, e.seq) {
			return e
		}
	}
	for _, e := range db.main {
		if len(e.pairs) != 7 {
			continue
		}
		hit := true
		for _, pv := range e.pairs {
			if int(boot[pv[0]]) != pv[1] {
				hit = false
				break
			}
		}
		if hit {
			return e
		}
	}
	return nil
}
