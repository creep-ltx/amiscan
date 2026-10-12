// Package lha reads LhA/LZH archives (header levels 0, 1 and 2) in pure Go.
//
// It unpacks -lh0- (stored), -lh1- (LHarc dynamic Huffman), -lh4- to -lh7-
// (static Huffman) and -lz4- (stored) members. Directories (-lhd-) are listed but have no data.
// The reader is tolerant: garbage before the first header (self-extractors) or
// after the last one (BBS adverts, padding) is ignored, and bad header
// checksums are not fatal, so archives that went through old BBS software
// still list.
package lha

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/creep-ltx/amiscan/internal/diz/stamp"
)

// File is one member of an archive.
type File struct {
	Name       string // path inside the archive, '/' separated, UTF-8
	Comment    string // Amiga file note, if any
	Method     string // "-lh5-" and so on
	PackedSize int64
	Size       int64
	CRC        uint16
	Dir        bool
	Level      int
	Time       time.Time // when packed: MS-DOS time (levels 0, 1) or Unix time (level 2)

	dataOffset int64
}

// Reader lists and unpacks the members of an archive.
type Reader struct {
	r     io.ReaderAt
	size  int64
	Files []*File
}

// ErrFormat means the data is not an LhA archive.
var ErrFormat = errors.New("lha: not an lha archive")

// maxScan is how far into the file we look for the first header.
const maxScan = 64 << 10

// NewReader reads the member list. It returns ErrFormat when no header is
// found; a damaged archive returns the members it could read and no error.
func NewReader(r io.ReaderAt, size int64) (*Reader, error) {
	rd := &Reader{r: r, size: size}
	start, ok := findStart(r, size)
	if !ok {
		return nil, ErrFormat
	}
	off := start
	for off < size {
		f, next, err := rd.readHeader(off)
		if err != nil {
			break // end marker, garbage after the archive, or a truncated header
		}
		rd.Files = append(rd.Files, f)
		if next <= off {
			break
		}
		off = next
	}
	if len(rd.Files) == 0 {
		return nil, ErrFormat
	}
	return rd, nil
}

// IsHeader reports whether b (at least 7 bytes) looks like the start of a header.
func IsHeader(b []byte) bool {
	if len(b) < 22 {
		return false
	}
	m := b[2:7]
	if m[0] != '-' || m[1] != 'l' || m[4] != '-' {
		return false
	}
	if m[2] != 'h' && m[2] != 'z' {
		return false
	}
	lvl := b[20]
	if lvl > 2 {
		return false
	}
	if lvl < 2 && b[0] < 21 {
		return false
	}
	return true
}

func findStart(r io.ReaderAt, size int64) (int64, bool) {
	n := int64(maxScan)
	if n > size {
		n = size
	}
	buf := make([]byte, n)
	got, _ := r.ReadAt(buf, 0)
	buf = buf[:got]
	for i := 0; i+22 <= len(buf); i++ {
		j := bytes.Index(buf[i:], []byte("-l"))
		if j < 0 {
			return 0, false
		}
		i += j
		if i >= 2 && IsHeader(buf[i-2:]) {
			return int64(i - 2), true
		}
	}
	return 0, false
}

func (rd *Reader) readAt(off int64, n int) ([]byte, error) {
	if off < 0 || n < 0 || off+int64(n) > rd.size {
		return nil, io.ErrUnexpectedEOF
	}
	b := make([]byte, n)
	if _, err := rd.r.ReadAt(b, off); err != nil && err != io.EOF {
		return nil, err
	}
	return b, nil
}

// readHeader parses the header at off and returns the member and where the
// next header starts.
func (rd *Reader) readHeader(off int64) (*File, int64, error) {
	b, err := rd.readAt(off, 22)
	if err != nil {
		// A lone zero byte (the end marker) may be the last byte of the file.
		return nil, 0, io.EOF
	}
	if b[0] == 0 || !IsHeader(b) {
		return nil, 0, io.EOF
	}
	f := &File{
		Method:     string(b[2:7]),
		PackedSize: int64(binary.LittleEndian.Uint32(b[7:])),
		Size:       int64(binary.LittleEndian.Uint32(b[11:])),
		Level:      int(b[20]),
	}
	if f.Level == 2 {
		f.Time = stamp.Unix(int64(binary.LittleEndian.Uint32(b[15:])))
	} else {
		f.Time = stamp.DOS32(binary.LittleEndian.Uint32(b[15:]))
	}
	var dir, name string
	switch f.Level {
	case 0, 1:
		hsize := int(b[0]) + 2
		h, err := rd.readAt(off, hsize)
		if err != nil {
			return nil, 0, err
		}
		nlen := int(h[21])
		if 22+nlen+2 > hsize {
			return nil, 0, fmt.Errorf("lha: bad header at %d", off)
		}
		name = rawName(h[22 : 22+nlen])
		f.Comment = rawComment(h[22 : 22+nlen])
		f.CRC = binary.LittleEndian.Uint16(h[22+nlen:])
		next := off + int64(hsize)
		if f.Level == 1 {
			// Extended headers follow the base header; their sizes are
			// counted in the packed size.
			extSize := int(binary.LittleEndian.Uint16(h[hsize-2:]))
			for extSize > 0 {
				e, err := rd.readAt(next, extSize)
				if err != nil || extSize < 3 {
					return nil, 0, fmt.Errorf("lha: bad extended header at %d", next)
				}
				applyExt(e[:extSize-2], &dir, &name, f)
				next += int64(extSize)
				f.PackedSize -= int64(extSize)
				extSize = int(binary.LittleEndian.Uint16(e[extSize-2:]))
			}
			if f.PackedSize < 0 {
				return nil, 0, fmt.Errorf("lha: bad sizes at %d", off)
			}
		}
		f.dataOffset = next
	case 2:
		total := int(binary.LittleEndian.Uint16(b[0:]))
		if total < 26 {
			return nil, 0, fmt.Errorf("lha: bad header at %d", off)
		}
		h, err := rd.readAt(off, total)
		if err != nil {
			return nil, 0, err
		}
		f.CRC = binary.LittleEndian.Uint16(h[21:])
		pos := 24
		for pos+2 <= total {
			extSize := int(binary.LittleEndian.Uint16(h[pos:]))
			pos += 2
			if extSize == 0 {
				break
			}
			if extSize < 3 || pos+extSize-2 > total {
				break
			}
			applyExt(h[pos:pos+extSize-2], &dir, &name, f)
			pos += extSize - 2
		}
		f.dataOffset = off + int64(total)
	}
	if dir != "" {
		if name != "" {
			name = strings.TrimSuffix(dir, "/") + "/" + name
		} else {
			name = dir
		}
	}
	f.Name = strings.Trim(name, "/")
	f.Dir = f.Method == "-lhd-"
	next := f.dataOffset + f.PackedSize
	if next > rd.size+1 {
		// Truncated archive: keep the member, the read will fail cleanly.
		next = rd.size
	}
	return f, next, nil
}

// applyExt reads one extended header (type byte plus data, without the
// trailing next-size field).
func applyExt(e []byte, dir, name *string, f *File) {
	if len(e) == 0 {
		return
	}
	switch e[0] {
	case 0x01: // file name
		*name = toUTF8(e[1:])
	case 0x02: // directory name, 0xFF separated
		d := bytes.ReplaceAll(e[1:], []byte{0xff}, []byte{'/'})
		*dir = toUTF8(d)
	case 0x54: // Unix time, from Unix archivers at level 1
		if len(e) >= 5 {
			f.Time = stamp.Unix(int64(binary.LittleEndian.Uint32(e[1:])))
		}
	}
}

// rawName decodes a level 0/1 name field. Amiga LhA puts the file note after
// a NUL byte; MS-DOS archivers use '\' between directories.
func rawName(b []byte) string {
	if i := bytes.IndexByte(b, 0); i >= 0 {
		b = b[:i]
	}
	b = bytes.ReplaceAll(b, []byte{'\\'}, []byte{'/'})
	b = bytes.ReplaceAll(b, []byte{0xff}, []byte{'/'})
	return toUTF8(b)
}

func rawComment(b []byte) string {
	if i := bytes.IndexByte(b, 0); i >= 0 {
		return toUTF8(b[i+1:])
	}
	return ""
}

// toUTF8 keeps valid UTF-8 and reads anything else as ISO-8859-1 (Amiga).
func toUTF8(b []byte) string {
	if utf8.Valid(b) {
		return string(b)
	}
	r := make([]rune, len(b))
	for i, c := range b {
		r[i] = rune(c)
	}
	return string(r)
}

// ReadFile unpacks a member. limit > 0 stops after that many bytes (the CRC
// is then not checked); limit <= 0 unpacks all and checks the CRC.
func (rd *Reader) ReadFile(f *File, limit int64) (out []byte, err error) {
	defer func() {
		// Corrupt data must never take the caller down.
		if r := recover(); r != nil {
			out, err = nil, fmt.Errorf("lha: corrupt data in %s: %v", f.Name, r)
		}
	}()
	if f.Dir {
		return nil, nil
	}
	want := f.Size
	partial := limit > 0 && limit < want
	if partial {
		want = limit
	}
	n := min(f.PackedSize, rd.size-f.dataOffset)
	if f.Method == "-lh0-" || f.Method == "-lz4-" {
		n = min(n, want) // stored: read only what is wanted
	}
	packed, err := rd.readAt(f.dataOffset, int(n))
	if err != nil {
		return nil, err
	}
	switch f.Method {
	case "-lh0-", "-lz4-":
		if int64(len(packed)) < want {
			return nil, io.ErrUnexpectedEOF
		}
		out = packed
	case "-lh1-":
		out, err = decodeLH1(packed, want)
	case "-lh4-":
		out, err = decodeStatic(packed, want, 12)
	case "-lh5-":
		out, err = decodeStatic(packed, want, 13)
	case "-lh6-":
		out, err = decodeStatic(packed, want, 15)
	case "-lh7-":
		out, err = decodeStatic(packed, want, 16)
	default:
		return nil, fmt.Errorf("lha: method %s not supported", f.Method)
	}
	if err != nil {
		return nil, err
	}
	if !partial && CRC16(out) != f.CRC {
		return out, fmt.Errorf("lha: CRC mismatch in %s", f.Name)
	}
	return out, nil
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

// CRC16 is the CRC used by LhA (CRC-16/ARC).
func CRC16(b []byte) uint16 {
	var c uint16
	for _, x := range b {
		c = crcTable[byte(c)^x] ^ c>>8
	}
	return c
}
