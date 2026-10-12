// Package lzx reads Amiga LZX archives in pure Go. It is a port of the
// classic unlzx.c 1.1 (Oliver Gantert, Erik Meusel; public domain), kept close
// to the original so it unpacks exactly what unlzx does.
//
// LZX packs several files into one "merged" stream: to read a file, the
// stream is unpacked from the start of its group up to the end of the file.
package lzx

import (
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"time"
	"unicode/utf8"
)

// File is one member of an archive.
type File struct {
	Name    string // path inside the archive, '/' separated, UTF-8
	Comment string
	Size    int64
	CRC     uint32
	Mode    int // pack mode of the group: 0 stored, 2 normal
	Time    time.Time

	group  *group
	offset int64 // where this file starts in the group's unpacked stream
}

// group is a run of files packed into one stream.
type group struct {
	dataOffset int64
	packedSize int64
	mode       int
	files      []*File
}

// Reader lists and unpacks the members of an archive.
type Reader struct {
	r     io.ReaderAt
	size  int64
	Files []*File
}

// ErrFormat means the data is not an LZX archive.
var ErrFormat = errors.New("lzx: not an lzx archive")

// NewReader reads the member list. A damaged archive returns the members
// read before the damage.
func NewReader(r io.ReaderAt, size int64) (*Reader, error) {
	info := make([]byte, 10)
	if _, err := r.ReadAt(info, 0); err != nil || string(info[:3]) != "LZX" {
		return nil, ErrFormat
	}
	rd := &Reader{r: r, size: size}
	off := int64(10)
	var pending []*File
	var unpacked int64
	for off+31 <= size {
		h := make([]byte, 31)
		if _, err := r.ReadAt(h, off); err != nil {
			break
		}
		nameLen, commentLen := int(h[30]), int(h[14])
		rest := make([]byte, nameLen+commentLen)
		if _, err := r.ReadAt(rest, off+31); err != nil && !(err == io.EOF && len(rest) == 0) {
			break
		}
		headerCRC := binary.LittleEndian.Uint32(h[26:])
		h[26], h[27], h[28], h[29] = 0, 0, 0, 0
		sum := crc32.ChecksumIEEE(append(append([]byte{}, h...), rest...))
		if sum != headerCRC {
			break
		}
		f := &File{
			Name:    toUTF8(rest[:nameLen]),
			Comment: toUTF8(rest[nameLen:]),
			Size:    int64(binary.LittleEndian.Uint32(h[2:])),
			CRC:     binary.LittleEndian.Uint32(h[22:]),
			Time:    date(binary.BigEndian.Uint32(h[18:])),
			offset:  unpacked,
		}
		unpacked += f.Size
		packed := int64(binary.LittleEndian.Uint32(h[6:]))
		off += 31 + int64(nameLen+commentLen)
		pending = append(pending, f)
		rd.Files = append(rd.Files, f)
		if packed > 0 {
			// The packed data of the whole group follows the last header.
			g := &group{dataOffset: off, packedSize: packed, mode: int(h[11]), files: pending}
			for _, pf := range pending {
				pf.group = g
				pf.Mode = g.mode
			}
			pending, unpacked = nil, 0
			off += packed
		}
	}
	if len(rd.Files) == 0 {
		return nil, ErrFormat
	}
	return rd, nil
}

// date reads LZX's packed date: day 5 bits, month 4 (from 0), year 6 (from
// 1970), hour 5, minute 6, second 6. LZX itself wrote 2000 to 2005 as 2028
// to 2033 (as xadmaster reads them). Local wall clock, given as UTC.
func date(v uint32) time.Time {
	if v == 0 {
		return time.Time{}
	}
	sec, mi, h := int(v&63), int(v>>6&63), int(v>>12&31)
	y, mo, d := 1970+int(v>>17&63), int(v>>23&15)+1, int(v>>27)
	if y >= 2028 {
		y -= 28
	}
	if mo > 12 || d < 1 || h > 23 || mi > 59 || sec > 59 {
		return time.Time{}
	}
	return time.Date(y, time.Month(mo), d, h, mi, sec, 0, time.UTC)
}

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
		if r := recover(); r != nil {
			out, err = nil, fmt.Errorf("lzx: corrupt data in %s: %v", f.Name, r)
		}
	}()
	g := f.group
	if f.Size == 0 {
		return []byte{}, nil // empty files and directory entries
	}
	if g == nil {
		return nil, fmt.Errorf("lzx: no data for %s", f.Name)
	}
	want := f.Size
	partial := limit > 0 && limit < want
	if partial {
		want = limit
	}
	n := g.packedSize
	if g.dataOffset+n > rd.size {
		n = rd.size - g.dataOffset
	}
	if n < 0 {
		return nil, io.ErrUnexpectedEOF
	}
	packed := make([]byte, n)
	if _, err := rd.r.ReadAt(packed, g.dataOffset); err != nil && err != io.EOF {
		return nil, err
	}
	switch g.mode {
	case 0:
		if int64(len(packed)) < f.offset+want {
			if int64(len(packed)) > f.offset {
				return packed[f.offset:], io.ErrUnexpectedEOF
			}
			return nil, io.ErrUnexpectedEOF
		}
		out = packed[f.offset : f.offset+want]
	case 2:
		if out, err = decrunch(packed, f.offset, want); err != nil {
			return out, fmt.Errorf("%w in %s", err, f.Name) // the part before the damage
		}
	default:
		return nil, fmt.Errorf("lzx: unknown pack mode %d", g.mode)
	}
	if !partial && crc32.ChecksumIEEE(out) != f.CRC {
		return out, fmt.Errorf("lzx: CRC mismatch in %s", f.Name)
	}
	return out, nil
}
