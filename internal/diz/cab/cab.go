// Package cab reads Microsoft Cabinet files (.cab) in pure Go: the member
// list, and the members of folders that are stored or MSZIP-packed (each
// data block a deflate stream that may refer back to the previous block).
// Quantum and LZX folders are listed but not unpacked. In a set of
// cabinets, members carried over from the previous cabinet are left out.
//
// Written for BBX from Microsoft's Cabinet format description; corrupt
// input returns an error, never a panic or a hang.
package cab

import (
	"bytes"
	"compress/flate"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/creep-ltx/amiscan/internal/diz/stamp"
)

// ErrFormat means the data is not a cabinet.
var ErrFormat = errors.New("cab: not a cabinet")

// Compression types (the low 4 bits of a folder's type).
const (
	None    = 0
	MSZIP   = 1
	Quantum = 2
	LZX     = 3
)

// maxFolder caps how much of a folder is unpacked to reach a member.
const maxFolder = 256 << 20

// IsCabinet reports whether b starts with a cabinet header.
func IsCabinet(b []byte) bool {
	return len(b) >= 36 && bytes.HasPrefix(b, []byte("MSCF\x00\x00\x00\x00")) &&
		b[25] == 1 && binary.LittleEndian.Uint32(b[8:]) >= 36
}

// File is one member.
type File struct {
	Name   string // as stored ('\\' separated; UTF-8 when UTF8 is set)
	UTF8   bool
	Size   int64
	Offset int64 // in its folder's unpacked data
	Folder int
	Time   time.Time // MS-DOS time
}

type folder struct {
	start  int64 // first data block
	blocks int
	method int
}

// Reader is an open cabinet.
type Reader struct {
	Files   []*File
	folders []folder
	r       io.ReaderAt
	size    int64
	dataRes int // reserved bytes in each data block header
}

// NewReader reads the member list.
func NewReader(r io.ReaderAt, size int64) (*Reader, error) {
	h := make([]byte, 36+4)
	if n, _ := r.ReadAt(h, 0); n < 36 || !IsCabinet(h) {
		return nil, ErrFormat
	}
	rd := &Reader{r: r, size: size}
	le := binary.LittleEndian
	filesAt := int64(le.Uint32(h[16:]))
	nFolders := int(le.Uint16(h[26:]))
	nFiles := int(le.Uint16(h[28:]))
	flags := le.Uint16(h[30:])
	off := int64(36)
	folderRes := 0
	if flags&4 != 0 {
		headerRes := int64(le.Uint16(h[36:]))
		folderRes = int(h[38])
		rd.dataRes = int(h[39])
		off = 40 + headerRes
	}
	for _, f := range []uint16{1, 2} { // previous and next cabinet names
		if flags&f != 0 {
			for k := 0; k < 2; k++ {
				_, n, err := cstring(r, off, 256)
				if err != nil {
					return nil, ErrFormat
				}
				off += n
			}
		}
	}
	for i := 0; i < nFolders; i++ {
		var b [8]byte
		if _, err := r.ReadAt(b[:], off); err != nil {
			return nil, ErrFormat
		}
		rd.folders = append(rd.folders, folder{
			start:  int64(le.Uint32(b[0:])),
			blocks: int(le.Uint16(b[4:])),
			method: int(le.Uint16(b[6:]) & 15),
		})
		off += 8 + int64(folderRes)
	}
	off = filesAt
	for i := 0; i < nFiles; i++ {
		var b [16]byte
		if _, err := r.ReadAt(b[:], off); err != nil {
			break
		}
		name, n, err := cstring(r, off+16, 1024)
		if err != nil {
			break
		}
		off += 16 + n
		f := &File{
			Name:   name,
			Size:   int64(le.Uint32(b[0:])),
			Offset: int64(le.Uint32(b[4:])),
			Folder: int(le.Uint16(b[8:])),
			Time:   stamp.DOS(le.Uint16(b[10:]), le.Uint16(b[12:])),
			UTF8:   le.Uint16(b[14:])&0x80 != 0,
		}
		switch f.Folder {
		case 0xfffd, 0xffff:
			continue // begins in the previous cabinet
		case 0xfffe:
			f.Folder = len(rd.folders) - 1 // goes on in the next cabinet
		}
		if f.Folder < 0 || f.Folder >= len(rd.folders) {
			continue
		}
		rd.Files = append(rd.Files, f)
	}
	if len(rd.Files) == 0 && nFiles > 0 {
		return nil, ErrFormat
	}
	return rd, nil
}

// cstring reads a NUL-terminated string at off; n counts the NUL.
func cstring(r io.ReaderAt, off int64, max int) (string, int64, error) {
	b := make([]byte, max)
	n, _ := r.ReadAt(b, off)
	i := bytes.IndexByte(b[:n], 0)
	if i < 0 {
		return "", 0, ErrFormat
	}
	return string(b[:i]), int64(i + 1), nil
}

// ReadFile unpacks a member, at most limit bytes when limit > 0.
func (rd *Reader) ReadFile(f *File, limit int64) (out []byte, err error) {
	defer func() {
		if r := recover(); r != nil {
			out, err = nil, fmt.Errorf("cab: corrupt data in %s: %v", f.Name, r)
		}
	}()
	want := f.Size
	if limit > 0 && limit < want {
		want = limit
	}
	fo := rd.folders[f.Folder]
	if fo.method != None && fo.method != MSZIP {
		return nil, fmt.Errorf("cab: %s: compression %d not supported", f.Name, fo.method)
	}
	end := f.Offset + want
	if end > maxFolder || f.Offset < 0 {
		return nil, fmt.Errorf("cab: %s lies too deep in its folder", f.Name)
	}
	data, err := rd.unpack(fo, end)
	if int64(len(data)) < end {
		if err == nil {
			err = io.ErrUnexpectedEOF
		}
		if int64(len(data)) <= f.Offset {
			return nil, err
		}
		return data[f.Offset:], err
	}
	return data[f.Offset:end], nil
}

// unpack returns the folder's data from its start, at least upto bytes
// (fewer on error or at the folder's end).
func (rd *Reader) unpack(fo folder, upto int64) ([]byte, error) {
	var out []byte
	off := fo.start
	le := binary.LittleEndian
	for i := 0; i < fo.blocks && int64(len(out)) < upto; i++ {
		var h [8]byte
		if _, err := rd.r.ReadAt(h[:], off); err != nil {
			return out, err
		}
		packed := int64(le.Uint16(h[4:]))
		plain := int(le.Uint16(h[6:]))
		off += 8 + int64(rd.dataRes)
		if off+packed > rd.size {
			return out, io.ErrUnexpectedEOF
		}
		b := make([]byte, packed)
		if _, err := rd.r.ReadAt(b, off); err != nil {
			return out, err
		}
		off += packed
		switch fo.method {
		case None:
			out = append(out, b...)
		case MSZIP:
			if !bytes.HasPrefix(b, []byte("CK")) {
				return out, errors.New("cab: MSZIP block without CK")
			}
			dict := out[max(0, len(out)-32768):]
			z := flate.NewReaderDict(bytes.NewReader(b[2:]), dict)
			blk, err := io.ReadAll(io.LimitReader(z, int64(max(plain, 1))))
			z.Close()
			out = append(out, blk...)
			if err != nil {
				return out, err
			}
		}
	}
	return out, nil
}
