// Package arc reads ARC archives (SEA's ARC, 1985, the first BBS archive
// format) and NoGate's PAK, which extends it, in pure Go: stored (1, 2),
// packed (3, run-length), squeezed (4, Huffman), crunched (5 to 8, LZW),
// squashed (9, 13-bit LZW), and PAK's crushed (10) and distilled (11).
//
// Written for BBX from the format as described in the ARC 5.21 sources, the
// PAK notes and The Unarchiver's descriptions; corrupt input returns an
// error, never a panic or a hang.
package arc

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/creep-ltx/amiscan/internal/diz/stamp"
)

// ErrFormat means the data is not an ARC archive.
var ErrFormat = errors.New("arc: not an arc archive")

const marker = 0x1a

// File is one member.
type File struct {
	Name       string // raw DOS name (at most 12 characters), '/' joined under PAK/ARC 7 directories
	Method     int
	Size       int64
	PackedSize int64
	CRC        uint16
	Time       time.Time // MS-DOS time
	dataOffset int64
}

// Reader is an open archive.
type Reader struct {
	Files []*File
	r     io.ReaderAt
	size  int64
}

// IsHeader reports whether b starts with a plausible ARC member header (the
// marker, a known method, a printable NUL-terminated name and sane sizes),
// followed, when b is long enough to show it, by the next header's marker.
func IsHeader(b []byte) bool {
	if len(b) < 29 || b[0] != marker {
		return false
	}
	m := int(b[1] & 0x7f)
	if m < 1 || m > 11 {
		return false
	}
	name := b[2:15]
	if name[0] == 0 {
		return false
	}
	end := bytes.IndexByte(name, 0)
	if end < 0 {
		return false
	}
	for _, c := range name[:end] {
		if c < 0x21 || c == 0x7f {
			return false
		}
	}
	packed := int64(binary.LittleEndian.Uint32(b[15:]))
	hdr := int64(29)
	size := packed
	if m == 1 {
		hdr = 25
	} else {
		size = int64(binary.LittleEndian.Uint32(b[25:]))
		if packed > size+size/8+1024 && m != 2 {
			return false // ARC never stores data bigger than the original
		}
	}
	if size > 1<<30 {
		return false
	}
	if b[1]&0x80 != 0 {
		hdr += 12
	}
	if next := hdr + packed; next < int64(len(b)) && b[next] != marker {
		return false
	}
	return true
}

// Verify reports whether a whole ARC archive starts at off: a chain of
// member headers with DOS-style names that ends exactly at an end marker.
// It is stricter than IsHeader, for finding an archive inside a program.
func Verify(r io.ReaderAt, off, size int64) bool {
	n := 0
	for i := 0; i < 1<<14 && off+2 <= size; i++ {
		var h [29]byte
		got, _ := r.ReadAt(h[:], off)
		if got < 2 || h[0] != marker {
			return false
		}
		if h[1] == 0 {
			return n > 0 // the end marker
		}
		if got < 29 || !IsHeader(h[:]) || !dosName(h[2:15]) {
			return false
		}
		hdr := int64(29)
		if h[1] == 1 {
			hdr = 25
		}
		if h[1]&0x80 != 0 {
			hdr += 12
		}
		off += hdr + int64(binary.LittleEndian.Uint32(h[15:]))
		n++
	}
	return false
}

// dosName reports whether a NUL-terminated name is a DOS 8.3 name.
func dosName(b []byte) bool {
	end := bytes.IndexByte(b, 0)
	if end <= 0 {
		return false
	}
	base, ext, dot := bytes.Cut(b[:end], []byte("."))
	if len(base) == 0 || len(base) > 8 || len(ext) > 3 || dot && bytes.IndexByte(ext, '.') >= 0 {
		return false
	}
	for _, c := range b[:end] {
		if c <= 0x20 || c >= 0x7f || bytes.IndexByte([]byte(`"*+,/:;<=>?[\]|`), c) >= 0 {
			return false
		}
	}
	return true
}

// maxSkip is how many bytes before the first header are skipped (some
// Atari and CP/M archives carry a few).
const maxSkip = 1024

// NewReader reads the member list.
func NewReader(r io.ReaderAt, size int64) (*Reader, error) {
	rd := &Reader{r: r, size: size}
	head := make([]byte, min(size, maxSkip+64<<10))
	n, _ := r.ReadAt(head, 0)
	head = head[:n]
	off := int64(-1)
	for i := 0; i < len(head) && i < maxSkip; i++ {
		if head[i] == marker && IsHeader(head[i:]) {
			off = int64(i)
			break
		}
	}
	if off < 0 {
		return nil, ErrFormat
	}
	var dir []string
	for i := 0; off < size && i < 1<<16; i++ {
		var h [41]byte
		n, _ := r.ReadAt(h[:], off)
		if n < 2 || h[0] != marker {
			break
		}
		method := int(h[1])
		if method == 0 {
			break // end of archive
		}
		if method == 0x1f || method == 0x80 {
			// end of a directory (ARC 7 / Spark)
			if len(dir) > 0 {
				dir = dir[:len(dir)-1]
			}
			off += 2
			continue
		}
		hdr := int64(29)
		if method == 1 {
			hdr = 25
		}
		if method&0x80 != 0 {
			hdr += 12
		}
		if int64(n) < hdr {
			break
		}
		name := h[2:15]
		if i := bytes.IndexByte(name, 0); i >= 0 {
			name = name[:i]
		}
		f := &File{
			Name:       string(name),
			Method:     method & 0x7f,
			PackedSize: int64(binary.LittleEndian.Uint32(h[15:])),
			CRC:        binary.LittleEndian.Uint16(h[23:]),
			Time:       stamp.DOS(binary.LittleEndian.Uint16(h[19:]), binary.LittleEndian.Uint16(h[21:])),
			dataOffset: off + hdr,
		}
		if method == 1 {
			f.Size = f.PackedSize
		} else {
			f.Size = int64(binary.LittleEndian.Uint32(h[25:]))
		}
		if method == 0x1e {
			// a directory: its members follow, up to an end marker
			dir = append(dir, f.Name)
			off += hdr
			continue
		}
		if len(dir) > 0 {
			f.Name = joinPath(dir) + "/" + f.Name
		}
		rd.Files = append(rd.Files, f)
		off = f.dataOffset + f.PackedSize
	}
	if len(rd.Files) == 0 {
		return nil, ErrFormat
	}
	return rd, nil
}

func joinPath(dir []string) string {
	var b bytes.Buffer
	for i, d := range dir {
		if i > 0 {
			b.WriteByte('/')
		}
		b.WriteString(d)
	}
	return b.String()
}

// ReadFile unpacks a member. limit > 0 stops after that many bytes (the CRC
// is then not checked); limit <= 0 unpacks all and checks the CRC.
func (rd *Reader) ReadFile(f *File, limit int64) (out []byte, err error) {
	defer func() {
		if r := recover(); r != nil {
			out, err = nil, fmt.Errorf("arc: corrupt data in %s: %v", f.Name, r)
		}
	}()
	want := f.Size
	partial := limit > 0 && limit < want
	if partial {
		want = limit
	}
	packed := min(f.PackedSize, rd.size-f.dataOffset)
	if packed < 0 {
		return nil, io.ErrUnexpectedEOF
	}
	src := bufio.NewReader(io.NewSectionReader(rd.r, f.dataOffset, packed))
	out, err = Decode(f.Method, src, want)
	if err != nil {
		return out, err
	}
	if int64(len(out)) < want {
		return out, io.ErrUnexpectedEOF
	}
	if !partial && crc16(out) != f.CRC {
		return out, fmt.Errorf("arc: CRC mismatch in %s", f.Name)
	}
	return out, nil
}

// Decode unpacks want bytes of a member packed with method from src.
func Decode(method int, src io.ByteReader, want int64) ([]byte, error) {
	o := &output{want: want, buf: make([]byte, 0, min(want, 1<<20))}
	var err error
	switch method {
	case 1, 2:
		for !o.full() {
			c, e := src.ReadByte()
			if e != nil {
				break
			}
			o.raw(c)
		}
	case 3:
		o.rle = true
		for !o.full() {
			c, e := src.ReadByte()
			if e != nil {
				break
			}
			o.put(c)
		}
	case 4:
		o.rle = true
		err = unsqueeze(src, o)
	case 5, 6, 7:
		o.rle = method != 5
		err = uncrunchOld(src, o, method == 7)
	case 8:
		o.rle = true
		bits, e := src.ReadByte()
		if e != nil {
			return nil, io.ErrUnexpectedEOF
		}
		if bits != 12 {
			return nil, fmt.Errorf("arc: crunched with %d bits", bits)
		}
		err = uncompress(src, o, 12)
	case 9:
		err = uncompress(src, o, 13)
	case 10:
		o.rle = true
		err = uncrush(src, o)
	case 11:
		err = undistill(src, o)
	default:
		return nil, fmt.Errorf("arc: method %d not supported", method)
	}
	if err == errFull {
		err = nil
	}
	return o.buf, err
}

var errFull = errors.New("arc: output complete")

// output collects unpacked bytes, optionally through ARC's run-length
// coding: 0x90 n repeats the previous byte n-1 more times; 0x90 0 is 0x90.
type output struct {
	buf   []byte
	want  int64
	rle   bool
	inRun bool
	last  byte
}

func (o *output) full() bool { return int64(len(o.buf)) >= o.want }

func (o *output) raw(c byte) {
	if !o.full() {
		o.buf = append(o.buf, c)
	}
}

func (o *output) put(c byte) {
	if !o.rle {
		o.raw(c)
		return
	}
	if o.inRun {
		o.inRun = false
		if c == 0 {
			o.raw(0x90) // the repeated byte stays what it was (as ARC 5.21)
			return
		}
		for i := 1; i < int(c) && !o.full(); i++ {
			o.raw(o.last)
		}
		return
	}
	if c == 0x90 {
		o.inRun = true
		return
	}
	o.raw(c)
	o.last = c
}

var crcTable = func() (t [256]uint16) {
	for i := range t {
		c := uint16(i)
		for k := 0; k < 8; k++ {
			if c&1 != 0 {
				c = c>>1 ^ 0xa001
			} else {
				c >>= 1
			}
		}
		t[i] = c
	}
	return
}()

// crc16 is ARC's CRC (CRC-16/ARC).
func crc16(b []byte) uint16 {
	var c uint16
	for _, x := range b {
		c = crcTable[byte(c)^x] ^ c>>8
	}
	return c
}
