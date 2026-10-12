// Package arj reads ARJ archives (Robert Jung, 1990s DOS BBS standard) in
// pure Go: the member list and the start of each member, for methods 0
// (stored), 1 to 3 (LZ77 with static Huffman codes) and 4 (fastest).
// Encrypted ("garbled") members are listed but not unpacked. In a
// multi-volume set each volume is read on its own: ARJ packs each volume's
// part of a split file separately (its sizes and CRC are the part's), so
// every part can be unpacked; FlagVolume and FlagExtFile tell which parts
// are not the whole file.
//
// Written for BBX from the ARJ technical notes; corrupt input returns an
// error, never a panic or a hang.
package arj

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"time"

	"github.com/creep-ltx/amiscan/internal/diz/lzh"
	"github.com/creep-ltx/amiscan/internal/diz/stamp"
)

// ErrFormat means the data is not an ARJ archive.
var ErrFormat = errors.New("arj: not an arj archive")

const (
	maxHeader = 2600     // the largest basic header ARJ writes
	maxScan   = 64 << 10 // how far to look for the main header
)

// Member flags.
const (
	FlagGarbled = 0x01 // encrypted
	FlagVolume  = 0x04 // goes on in the next volume
	FlagExtFile = 0x08 // started in the previous volume
	FlagPathSym = 0x10 // '/' already used as the path separator
)

// File is one member.
type File struct {
	Name       string // raw name as stored (DOS code page, '\\' or '/')
	Comment    string
	Method     int
	Type       int // 0 binary, 1 text, 2 comment header, 3 directory, 4 label
	Flags      int
	Size       int64
	PackedSize int64
	CRC        uint32
	Dir        bool
	Time       time.Time // MS-DOS time, Unix time from UNIX and NeXT
	dataOffset int64
}

// Reader is an open archive.
type Reader struct {
	Name    string // the archive's own name, from the main header
	Comment string // the archive comment
	Files   []*File
	r       io.ReaderAt
	size    int64
}

// header is one basic header and where the data after it starts.
type header struct {
	b    []byte // from first_hdr_size up to the comment's end
	next int64  // offset just after the header (and its extended headers)
}

// IsHeader reports whether b holds a whole valid ARJ header at its start:
// the 0x60 0xEA id, a sane size and a matching CRC-32.
func IsHeader(b []byte) bool {
	if len(b) < 4 || b[0] != 0x60 || b[1] != 0xea {
		return false
	}
	n := int(binary.LittleEndian.Uint16(b[2:]))
	if n < 30 || n > maxHeader || len(b) < 4+n+4 {
		return false
	}
	return crc32.ChecksumIEEE(b[4:4+n]) == binary.LittleEndian.Uint32(b[4+n:])
}

// NewReader reads the member list. The main header must lie within the
// first 64 KB (self-extractors are handled by giving the archive's start).
func NewReader(r io.ReaderAt, size int64) (*Reader, error) {
	rd := &Reader{r: r, size: size}
	start, ok := rd.findMain()
	if !ok {
		return nil, ErrFormat
	}
	h, err := rd.readHeader(start)
	if err != nil || h == nil {
		return nil, ErrFormat
	}
	rd.Name, rd.Comment = names(h.b)
	off := h.next
	for off < size {
		h, err := rd.readHeader(off)
		if err != nil || h == nil {
			break // end of archive, or garbage / truncation after it
		}
		f, ok := parseFile(h.b)
		if !ok {
			break
		}
		f.dataOffset = h.next
		rd.Files = append(rd.Files, f)
		next := h.next + f.PackedSize
		if next <= off {
			break
		}
		off = next
	}
	return rd, nil
}

func (rd *Reader) findMain() (int64, bool) {
	n := min(int64(maxScan+maxHeader+8), rd.size)
	buf := make([]byte, n)
	got, _ := rd.r.ReadAt(buf, 0)
	buf = buf[:got]
	for i := 0; i < len(buf) && i <= maxScan; {
		j := bytes.Index(buf[i:], []byte{0x60, 0xea})
		if j < 0 {
			return 0, false
		}
		i += j
		if IsHeader(buf[i:]) && len(buf) > i+10 && buf[i+10] == 2 {
			return int64(i), true // file type 2: the main header
		}
		i++
	}
	return 0, false
}

// readHeader reads the header at off; nil with no error is the end marker.
func (rd *Reader) readHeader(off int64) (*header, error) {
	var pre [4]byte
	if _, err := rd.r.ReadAt(pre[:], off); err != nil {
		return nil, err
	}
	if pre[0] != 0x60 || pre[1] != 0xea {
		return nil, ErrFormat
	}
	n := int64(binary.LittleEndian.Uint16(pre[2:]))
	if n == 0 {
		return nil, nil
	}
	if n < 30 || n > maxHeader {
		return nil, ErrFormat
	}
	b := make([]byte, n+4+2)
	if _, err := rd.r.ReadAt(b, off+4); err != nil {
		return nil, err
	}
	if crc32.ChecksumIEEE(b[:n]) != binary.LittleEndian.Uint32(b[n:]) {
		return nil, ErrFormat
	}
	next := off + 4 + n + 4
	// Extended headers: size, data, CRC, until a zero size.
	for i := 0; i < 16; i++ {
		var s [2]byte
		if _, err := rd.r.ReadAt(s[:], next); err != nil {
			return nil, err
		}
		next += 2
		es := int64(binary.LittleEndian.Uint16(s[:]))
		if es == 0 {
			break
		}
		next += es + 4
	}
	return &header{b: b[:n], next: next}, nil
}

// names returns the name and comment strings after the fixed fields.
func names(b []byte) (string, string) {
	first := int(b[0])
	if first > len(b) {
		return "", ""
	}
	rest := b[first:]
	name, rest, _ := bytes.Cut(rest, []byte{0})
	comment, _, _ := bytes.Cut(rest, []byte{0})
	return string(name), string(comment)
}

func parseFile(b []byte) (*File, bool) {
	if len(b) < 30 || int(b[0]) < 26 {
		return nil, false
	}
	f := &File{
		Flags:      int(b[4]),
		Method:     int(b[5]),
		Type:       int(b[6]),
		PackedSize: int64(binary.LittleEndian.Uint32(b[12:])),
		Size:       int64(binary.LittleEndian.Uint32(b[16:])),
		CRC:        binary.LittleEndian.Uint32(b[20:]),
	}
	if t := binary.LittleEndian.Uint32(b[8:]); b[3] == 2 || b[3] == 8 {
		f.Time = stamp.Unix(int64(t)) // ARJ for UNIX and NeXT store Unix time
	} else {
		f.Time = stamp.DOS32(t)
	}
	f.Name, f.Comment = names(b)
	f.Dir = f.Type == 3
	return f, true
}

// ReadFile unpacks a member. limit > 0 stops after that many bytes (the CRC
// is then not checked); limit <= 0 unpacks all and checks the CRC.
func (rd *Reader) ReadFile(f *File, limit int64) (out []byte, err error) {
	defer func() {
		if r := recover(); r != nil {
			out, err = nil, fmt.Errorf("arj: corrupt data in %s: %v", f.Name, r)
		}
	}()
	switch {
	case f.Dir || f.Type == 4 || f.Type == 5:
		return nil, nil
	case f.Flags&FlagGarbled != 0:
		return nil, fmt.Errorf("arj: %s is encrypted", f.Name)
	}
	want := f.Size
	partial := limit > 0 && limit < want
	if partial {
		want = limit
	}
	packed := min(f.PackedSize, rd.size-f.dataOffset)
	if packed < 0 {
		return nil, io.ErrUnexpectedEOF
	}
	src := io.NewSectionReader(rd.r, f.dataOffset, packed)
	switch f.Method {
	case 0:
		out = make([]byte, min(want, packed))
		if _, err := io.ReadFull(src, out); err != nil {
			return nil, err
		}
		if int64(len(out)) < want {
			err = io.ErrUnexpectedEOF
		}
	case 1, 2, 3:
		out, err = lzh.Decode(bufio.NewReader(src), want, lzh.ARJ)
	case 4:
		out, err = decodeFastest(bufio.NewReader(src), want)
	default:
		return nil, fmt.Errorf("arj: method %d not supported", f.Method)
	}
	if err != nil {
		return out, err
	}
	if !partial && crc32.ChecksumIEEE(out) != f.CRC {
		return out, fmt.Errorf("arj: CRC mismatch in %s", f.Name)
	}
	return out, nil
}

// decodeFastest unpacks method 4: LZ77 with Elias-gamma-like lengths and
// positions, no Huffman codes.
func decodeFastest(r io.ByteReader, want int64) ([]byte, error) {
	b := lzh.NewBitReader(r)
	out := make([]byte, 0, min(want, 1<<20))
	for int64(len(out)) < want {
		if b.Overrun() {
			return out, lzh.ErrCorrupt
		}
		// Length: up to 7 one bits pick the width, then that many bits.
		c, width := 0, 0
		for ; width < 7; width++ {
			if b.Bit() == 0 {
				break
			}
			c += 1 << width
		}
		c += b.Bits(uint(width))
		if c == 0 {
			out = append(out, byte(b.Bits(8)))
			continue
		}
		length := c + 2
		// Position: widths 9 to 13.
		pos, pw := 0, 9
		for ; pw < 13; pw++ {
			if b.Bit() == 0 {
				break
			}
			pos += 1 << pw
		}
		pos += b.Bits(uint(pw))
		from := len(out) - pos - 1
		for k := 0; k < length && int64(len(out)) < want; k++ {
			if from+k < 0 {
				out = append(out, 0)
			} else {
				out = append(out, out[from+k])
			}
		}
	}
	return out, nil
}
