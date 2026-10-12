// Package sfx finds the archive inside a self-extracting DOS or Windows
// program (an MZ executable): a Zip, RAR, ARJ, LhA, ARC, ZOO, 7z or CAB archive
// appended to the unpacker. It scans for each format's signature and keeps
// only places where a real header follows (checked by the format's own
// rules), strongest signatures first.
package sfx

import (
	"bytes"
	"encoding/binary"
	"io"
	"sort"

	"github.com/creep-ltx/amiscan/internal/diz/arc"
	"github.com/creep-ltx/amiscan/internal/diz/arj"
	"github.com/creep-ltx/amiscan/internal/diz/cab"
	"github.com/creep-ltx/amiscan/internal/diz/lha"
	"github.com/creep-ltx/amiscan/internal/diz/zoo"
)

// MaxScan is how far into the program the archive may start.
const MaxScan = 8 << 20

// Found is a place where an archive seems to start.
type Found struct {
	Kind   string // "rar", "7z", "arj", "zoo", "cab", "lha", "arc"
	Offset int64
}

// IsExe reports whether h starts like a DOS or Windows program.
func IsExe(h []byte) bool {
	return len(h) >= 64 && (h[0] == 'M' && h[1] == 'Z' || h[0] == 'Z' && h[1] == 'M')
}

// dosEnd is where the DOS program image ends, by its MZ header.
func dosEnd(h []byte) int64 {
	if len(h) < 6 {
		return 0
	}
	last := int64(binary.LittleEndian.Uint16(h[2:]))
	pages := int64(binary.LittleEndian.Uint16(h[4:]))
	if pages == 0 {
		return 0
	}
	end := pages * 512
	if last != 0 {
		end -= 512 - last
	}
	return end
}

var sigs = []struct {
	kind string
	sig  []byte
	rank int // lower = stronger
}{
	{"rar", []byte("Rar!\x1a\x07"), 0},
	{"7z", []byte("7z\xbc\xaf\x27\x1c"), 0},
	{"arj", []byte{0x60, 0xea}, 0},
	{"zoo", []byte{0xdc, 0xa7, 0xc4, 0xfd}, 0},
	{"cab", []byte("MSCF\x00\x00\x00\x00"), 0},
	{"lha", []byte("-l"), 1},
	{"arc", []byte{0x1a}, 2},
}

// Scan returns the places, best first, where an archive starts.
func Scan(r io.ReaderAt, size int64) []Found {
	n := min(size, MaxScan+4096)
	buf := make([]byte, n)
	got, _ := r.ReadAt(buf, 0)
	buf = buf[:got]
	if !IsExe(buf) {
		return nil
	}
	end := dosEnd(buf)
	type cand struct {
		Found
		rank int
	}
	var cs []cand
	seen := map[int64]bool{}
	for _, s := range sigs {
		count := 0
		for i := 2; i < len(buf) && i <= MaxScan && count < 4; {
			j := bytes.Index(buf[i:], s.sig)
			if j < 0 {
				break
			}
			i += j
			off := int64(i)
			ok := false
			switch s.kind {
			case "rar":
				ok = bytes.HasPrefix(buf[i:], []byte("Rar!\x1a\x07\x00")) ||
					bytes.HasPrefix(buf[i:], []byte("Rar!\x1a\x07\x01\x00"))
			case "7z":
				ok = len(buf) >= i+32
			case "arj":
				ok = arj.IsHeader(buf[i:]) && buf[i+10] == 2
			case "zoo":
				off -= 20
				ok = off >= 0 && zoo.IsArchive(buf[off:])
			case "cab":
				ok = cab.IsCabinet(buf[i:])
			case "lha":
				off -= 2
				ok = off >= 0 && lha.IsHeader(buf[off:])
			case "arc":
				ok = off >= end && arc.IsHeader(buf[i:]) && arc.Verify(r, off, size)
			}
			if ok && !seen[off] {
				seen[off] = true
				cs = append(cs, cand{Found{s.kind, off}, s.rank})
				count++
			}
			i++
		}
	}
	sort.SliceStable(cs, func(i, j int) bool {
		if cs[i].rank != cs[j].rank {
			return cs[i].rank < cs[j].rank
		}
		return cs[i].Offset < cs[j].Offset
	})
	out := make([]Found, len(cs))
	for i, c := range cs {
		out[i] = c.Found
	}
	return out
}
