// Package adf reads AmigaDOS volumes: floppy images (ADF, 880 KB DD and
// 1760 KB HD) and the partitions of hard disk images (HDF, see rdb.go). It
// understands the original and fast file systems (OFS, FFS) and their
// international and directory-cache variants (DOS\0 to DOS\5); it walks the
// directories by their hash tables and hash chains and reads files through
// their block lists and extension blocks.
//
// It is read-only and lenient (checksums are not required), but bounded:
// every chain is followed at most a fixed number of steps, every block is
// visited at most once, so a corrupt or crafted image cannot make it panic
// or loop.
package adf

import (
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/creep-ltx/amiscan/internal/diz/stamp"
)

// Image sizes of floppy disks.
const (
	SizeDD = 901120  // 80 cylinders x 2 sides x 11 sectors x 512
	SizeHD = 1802240 // 22 sectors a track
)

// ErrNotDOS means the disk has no AmigaDOS file system: its boot block
// does not start with "DOS" (games, trackloaded demos, bootblock intros).
var ErrNotDOS = errors.New("adf: not an AmigaDOS disk")

// ErrNoRoot means the boot block says DOS but no root block was found
// (often a trackloader that kept a DOS boot block).
var ErrNoRoot = errors.New("adf: no root block")

const (
	maxEntries = 100000 // files and directories in one volume
	maxDepth   = 64
	tHeader    = 2
	tList      = 16
	tData      = 8
	stRoot     = 1
	stUserDir  = 2
	stFile     = -3
)

// Entry is a file or directory in a volume.
type Entry struct {
	Path  string // '/' separated, from the volume's root
	Dir   bool
	Size  int64
	Time  time.Time // last changed, AmigaDOS date
	block uint32
}

// Volume is an opened AmigaDOS volume.
type Volume struct {
	Name     string
	DOSType  byte // the n in DOS\n: bit 0 FFS, bit 1 international, bit 2 dircache
	Entries  []Entry
	Problems int // blocks that were not what they should be (skipped)

	r       io.ReaderAt
	off     int64 // where block 0 is
	bsize   int
	nblocks uint32
}

// FFS reports a fast file system volume.
func (v *Volume) FFS() bool { return v.DOSType&1 != 0 }

// Type is "OFS", "FFS", "OFS-INTL", "FFS-DC" and so on.
func (v *Volume) Type() string {
	s := "OFS"
	if v.FFS() {
		s = "FFS"
	}
	switch v.DOSType {
	case 2, 3:
		s += "-INTL"
	case 4, 5:
		s += "-DC"
	case 6, 7:
		s += "-LNFS"
	}
	return s
}

// OpenFloppy opens an ADF image (any size; 901120 and 1802240 are usual).
func OpenFloppy(r io.ReaderAt, size int64) (*Volume, error) {
	return Open(r, 0, size/512, 512, 2)
}

// Open opens the volume of nblocks blocks of bsize bytes starting at off;
// reserved is the number of boot blocks (2 for floppies and nearly every
// partition).
func Open(r io.ReaderAt, off, nblocks int64, bsize, reserved int) (*Volume, error) {
	if bsize < 512 || bsize > 65536 || bsize%4 != 0 || nblocks < 4 || nblocks > 1<<31 {
		return nil, fmt.Errorf("adf: bad geometry (%d blocks of %d)", nblocks, bsize)
	}
	v := &Volume{r: r, off: off, bsize: bsize, nblocks: uint32(nblocks)}
	boot, err := v.block(0)
	if err != nil {
		return nil, err
	}
	if string(boot[:3]) != "DOS" {
		return nil, ErrNotDOS
	}
	v.DOSType = boot[3]
	if v.DOSType > 7 {
		return nil, ErrNotDOS
	}
	// The root is in the middle; the boot block names it too.
	rootAt := uint32((nblocks - 1 + int64(reserved)) / 2)
	root, err := v.block(rootAt)
	if err != nil || !isRoot(root) {
		alt := be32(boot[8:])
		if r2, err2 := v.block(alt); err2 == nil && isRoot(r2) {
			root, rootAt = r2, alt
		} else {
			return nil, ErrNoRoot
		}
	}
	v.Name = v.name(root)
	v.walk(rootAt, root)
	return v, nil
}

func isRoot(b []byte) bool {
	return be32(b) == tHeader && int32(be32(b[len(b)-4:])) == stRoot
}

// block reads one block; it returns an error past the volume's end.
func (v *Volume) block(n uint32) ([]byte, error) {
	if n >= v.nblocks {
		return nil, fmt.Errorf("adf: block %d out of range", n)
	}
	b := make([]byte, v.bsize)
	if _, err := v.r.ReadAt(b, v.off+int64(n)*int64(v.bsize)); err != nil {
		return nil, err
	}
	return b, nil
}

func be32(b []byte) uint32 {
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}

// name reads the BCPL name at bsize-80 (Latin-1, at most 30 characters).
func (v *Volume) name(b []byte) string {
	at := v.bsize - 80
	n := int(b[at])
	if n > 30 {
		n = 30
	}
	var s strings.Builder
	for _, c := range b[at+1 : at+1+n] {
		switch {
		case c == '/' || c == ':':
			s.WriteByte('_')
		case c < 0x20 || (c >= 0x7f && c < 0xa0):
			s.WriteByte('?')
		default:
			s.WriteRune(rune(c)) // Latin-1
		}
	}
	return s.String()
}

// table returns the hash table / block list of a header block.
func (v *Volume) table(b []byte) []byte { return b[24 : v.bsize-200] }

// walk lists every entry under the root, breadth first.
func (v *Volume) walk(rootAt uint32, root []byte) {
	seen := map[uint32]bool{rootAt: true}
	type dir struct {
		path  string
		b     []byte
		depth int
	}
	queue := []dir{{"", root, 0}}
	for len(queue) > 0 && len(v.Entries) < maxEntries {
		d := queue[0]
		queue = queue[1:]
		ht := v.table(d.b)
		for i := 0; i+4 <= len(ht); i += 4 {
			// Follow this slot's hash chain.
			for n := be32(ht[i:]); n != 0 && len(v.Entries) < maxEntries; {
				if seen[n] {
					v.Problems++
					break
				}
				seen[n] = true
				b, err := v.block(n)
				if err != nil || be32(b) != tHeader || be32(b[4:]) != n {
					v.Problems++
					break
				}
				name := v.name(b)
				p := name
				if d.path != "" {
					p = d.path + "/" + name
				}
				at := v.bsize - 92 // days, minutes, ticks
				t := stamp.Amiga(be32(b[at:]), be32(b[at+4:]), be32(b[at+8:]))
				switch int32(be32(b[v.bsize-4:])) {
				case stUserDir:
					v.Entries = append(v.Entries, Entry{Path: p, Dir: true, Time: t, block: n})
					if d.depth+1 < maxDepth {
						queue = append(queue, dir{p, b, d.depth + 1})
					}
				case stFile:
					v.Entries = append(v.Entries, Entry{Path: p, Size: int64(be32(b[v.bsize-188:])), Time: t, block: n})
				default:
					// links: left out
				}
				n = be32(b[v.bsize-16:]) // hash chain
			}
		}
	}
}

// ReadFile returns the start of a file, at most limit bytes.
func (v *Volume) ReadFile(e Entry, limit int64) ([]byte, error) {
	if e.Dir {
		return nil, errors.New("adf: a directory")
	}
	size := e.Size
	if size > limit {
		size = limit
	}
	if size <= 0 {
		return []byte{}, nil
	}
	per := int64(v.bsize)
	if !v.FFS() {
		per -= 24
	}
	need := (size + per - 1) / per
	hdr, err := v.block(e.block)
	if err != nil {
		return nil, err
	}
	// Data block numbers, from the header and its extension blocks;
	// each table is filled from its end.
	var blocks []uint32
	seen := map[uint32]bool{e.block: true}
	for b := hdr; b != nil && int64(len(blocks)) < need; {
		t := v.table(b)
		cnt := int(be32(b[8:])) // high_seq: entries used
		if most := len(t) / 4; cnt > most || cnt < 0 {
			cnt = most
		}
		for k := 0; k < cnt && int64(len(blocks)) < need; k++ {
			blocks = append(blocks, be32(t[len(t)-4*(k+1):]))
		}
		ext := be32(b[v.bsize-8:])
		b = nil
		if ext != 0 && !seen[ext] {
			seen[ext] = true
			if x, err := v.block(ext); err == nil && be32(x) == tList {
				b = x
			}
		}
	}
	out := make([]byte, 0, size)
	for _, n := range blocks {
		if int64(len(out)) >= size {
			break
		}
		b, err := v.block(n)
		if err != nil {
			break
		}
		data := b
		if !v.FFS() {
			if be32(b) != tData {
				break
			}
			ds := int(be32(b[12:]))
			if ds > v.bsize-24 || ds < 0 {
				ds = v.bsize - 24
			}
			data = b[24 : 24+ds]
		}
		if rest := size - int64(len(out)); int64(len(data)) > rest {
			data = data[:rest]
		}
		out = append(out, data...)
	}
	if len(out) == 0 {
		return nil, errors.New("adf: file data unreadable")
	}
	return out, nil
}

// BootText returns the readable text in a boot block (the first 1024
// bytes of a disk): runs of at least 6 printable characters, mostly
// letters, one per line. Bootblock intros and game loaders often
// carry a greeting or a title there.
func BootText(boot []byte) []string {
	if len(boot) > 1024 {
		boot = boot[:1024]
	}
	var lines []string
	var run []byte
	flush := func() {
		s := strings.TrimSpace(string(run))
		run = run[:0]
		letters := 0
		distinct := map[rune]bool{}
		for _, c := range s {
			if c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' {
				letters++
				distinct[c|0x20] = true
			}
		}
		if len(s) >= 6 && letters*10 >= len(s)*6 && len(distinct) >= 4 {
			lines = append(lines, strings.Join(strings.Fields(s), " "))
		}
	}
	for i, c := range boot {
		if i < 4 { // "DOS" and its flags, or a game's own tag
			continue
		}
		if c >= 0x20 && c < 0x7f {
			run = append(run, c)
		} else {
			flush()
		}
	}
	flush()
	return lines
}
