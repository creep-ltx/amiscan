// Package zoo reads ZOO archives (Rahul Dhesi, 1986) in pure Go: the member
// list and the start of each member, for methods 0 (stored), 1 (LZW, 13
// bits) and 2 (-lh5-, as LhA). Deleted members are left out.
//
// Written for BBX from the ZOO 2.1 format description; corrupt input
// returns an error, never a panic or a hang.
package zoo

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/creep-ltx/amiscan/internal/diz/lzh"
	"github.com/creep-ltx/amiscan/internal/diz/stamp"
)

// ErrFormat means the data is not a ZOO archive.
var ErrFormat = errors.New("zoo: not a zoo archive")

const magic = 0xfdc4a7dc

// IsArchive reports whether b starts like a ZOO archive.
func IsArchive(b []byte) bool {
	return len(b) >= 34 && binary.LittleEndian.Uint32(b[20:]) == magic
}

// File is one member.
type File struct {
	Name       string // raw name ('/' separated, DOS or host code page)
	Comment    string
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

// NewReader reads the member list.
func NewReader(r io.ReaderAt, size int64) (*Reader, error) {
	var h [34]byte
	if n, _ := r.ReadAt(h[:], 0); !IsArchive(h[:n]) {
		return nil, ErrFormat
	}
	rd := &Reader{r: r, size: size}
	off := int64(binary.LittleEndian.Uint32(h[24:]))
	seen := map[int64]bool{}
	for i := 0; i < 1<<16 && off > 0 && off < size && !seen[off]; i++ {
		seen[off] = true
		var e [56 + 256 + 256 + 16]byte
		n, _ := r.ReadAt(e[:], off)
		if n < 51 || binary.LittleEndian.Uint32(e[0:]) != magic {
			break
		}
		next := int64(binary.LittleEndian.Uint32(e[6:]))
		if next == 0 {
			break // the end entry
		}
		typ := e[4]
		f := &File{
			Method:     int(e[5]),
			dataOffset: int64(binary.LittleEndian.Uint32(e[10:])),
			CRC:        binary.LittleEndian.Uint16(e[18:]),
			Time:       stamp.DOS(binary.LittleEndian.Uint16(e[14:]), binary.LittleEndian.Uint16(e[16:])),
			Size:       int64(binary.LittleEndian.Uint32(e[20:])),
			PackedSize: int64(binary.LittleEndian.Uint32(e[24:])),
		}
		deleted := e[30] != 0
		f.Name = cstr(e[38:51])
		if typ == 2 && n >= 56 {
			vlen := int(binary.LittleEndian.Uint16(e[51:]))
			v := e[56:min(n, 56+vlen)]
			var long, dir string
			if len(v) >= 1 {
				ln := int(v[0])
				dl := 0
				if len(v) >= 2 {
					dl = int(v[1])
				}
				if ln > 0 && 2+ln <= len(v) {
					long = cstr(v[2 : 2+ln])
				}
				if dl > 0 && 2+ln+dl <= len(v) {
					dir = cstr(v[2+ln : 2+ln+dl])
				}
			}
			if long != "" {
				f.Name = long
			}
			if dir != "" {
				f.Name = strings.TrimRight(dir, "/") + "/" + f.Name
			}
		}
		if co, cl := int64(binary.LittleEndian.Uint32(e[32:])), int(binary.LittleEndian.Uint16(e[36:])); co > 0 && cl > 0 && cl < 4096 {
			c := make([]byte, cl)
			if m, _ := r.ReadAt(c, co); m == cl {
				f.Comment = cstr(c)
			}
		}
		if !deleted && f.Name != "" {
			rd.Files = append(rd.Files, f)
		}
		off = next
	}
	if len(rd.Files) == 0 {
		return nil, ErrFormat
	}
	return rd, nil
}

func cstr(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}

// ReadFile unpacks a member. limit > 0 stops after that many bytes (the CRC
// is then not checked); limit <= 0 unpacks all and checks the CRC.
func (rd *Reader) ReadFile(f *File, limit int64) (out []byte, err error) {
	defer func() {
		if r := recover(); r != nil {
			out, err = nil, fmt.Errorf("zoo: corrupt data in %s: %v", f.Name, r)
		}
	}()
	want := f.Size
	partial := limit > 0 && limit < want
	if partial {
		want = limit
	}
	packed := min(f.PackedSize, rd.size-f.dataOffset)
	if packed < 0 || f.dataOffset < 0 {
		return nil, io.ErrUnexpectedEOF
	}
	src := io.NewSectionReader(rd.r, f.dataOffset, packed)
	switch f.Method {
	case 0:
		out = make([]byte, min(want, packed))
		if _, err := io.ReadFull(src, out); err != nil {
			return nil, err
		}
	case 1:
		out, err = unLZD(bufio.NewReader(src), want)
	case 2:
		out, err = lzh.Decode(bufio.NewReader(src), want, lzh.LH5)
	default:
		return nil, fmt.Errorf("zoo: method %d not supported", f.Method)
	}
	if err != nil {
		return out, err
	}
	if int64(len(out)) < want {
		return out, io.ErrUnexpectedEOF
	}
	if !partial && crc16(out) != f.CRC {
		return out, fmt.Errorf("zoo: CRC mismatch in %s", f.Name)
	}
	return out, nil
}

// unLZD decodes method 1: LZW, codes least significant bit first, 9 bits
// growing to 13; 256 clears the table, 257 ends the data.
func unLZD(src io.ByteReader, want int64) ([]byte, error) {
	const (
		clearCode = 256
		endCode   = 257
		firstFree = 258
		max       = 8192
	)
	var (
		prefix [max]int32
		suffix [max]byte
		stack  [max]byte
		buf    uint64
		nb     uint
		past   int
	)
	read := func(n uint) int {
		for nb < n {
			c, err := src.ReadByte()
			if err != nil {
				c = 0
				past++
			}
			buf |= uint64(c) << nb
			nb += 8
		}
		v := int(buf & (1<<n - 1))
		buf >>= n
		nb -= n
		return v
	}
	out := make([]byte, 0, min(want, 1<<20))
	bits, free, old := uint(9), firstFree, -1
	var fin byte
	for int64(len(out)) < want {
		if past > 8 {
			return out, io.ErrUnexpectedEOF
		}
		code := read(bits)
		switch {
		case code == clearCode:
			bits, free, old = 9, firstFree, -1
			continue
		case code == endCode:
			return out, nil
		case old < 0:
			if code > 255 {
				return out, lzh.ErrCorrupt
			}
			fin = byte(code)
			out = append(out, fin)
			old = code
			continue
		}
		in := code
		sp := 0
		if code >= free {
			if code > free {
				return out, lzh.ErrCorrupt
			}
			stack[sp] = fin
			sp++
			code = old
		}
		for code > 255 {
			if sp >= max-1 {
				return out, lzh.ErrCorrupt
			}
			stack[sp] = suffix[code]
			sp++
			code = int(prefix[code])
		}
		fin = byte(code)
		stack[sp] = fin
		sp++
		for sp > 0 && int64(len(out)) < want {
			sp--
			out = append(out, stack[sp])
		}
		if free < max {
			prefix[free] = int32(old)
			suffix[free] = fin
			free++
			if free >= 1<<bits && bits < 13 {
				bits++
			}
		}
		old = in
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

func crc16(b []byte) uint16 {
	var c uint16
	for _, x := range b {
		c = crcTable[byte(c)^x] ^ c>>8
	}
	return c
}
