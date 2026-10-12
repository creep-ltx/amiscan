// Package stream lists tar archives, plain or compressed with gzip, bzip2
// or xz, and single compressed files (a bare .gz of a text file), for the
// FILE_ID.DIZ reader. A compressed stream can only be read from its start,
// so listing it keeps the first bytes of every member (within a budget)
// and reading any other member decompresses again up to it. Decompressed
// reading is capped, so a huge or hostile stream costs bounded time and
// memory.
package stream

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/bzip2"
	"compress/gzip"
	"errors"
	"io"
	"strconv"
	"time"

	"github.com/ulikunitz/xz"
)

// Kind is a compression.
type Kind int

const (
	None Kind = iota
	Gzip
	Bzip2
	XZ
)

const (
	// MaxList is how much decompressed data a listing reads at most.
	MaxList = 256 << 20
	// KeepEach is how much of each member a listing keeps.
	KeepEach = 64 << 10
	// KeepTotal is the most a listing keeps in all.
	KeepTotal = 16 << 20
	// xzDict is the xz window; xz -9 uses 64 MB.
	xzDict = 64 << 20
)

// ErrFormat means the data is not of the expected kind.
var ErrFormat = errors.New("stream: not a recognised stream")

// Member is one file, or a folder (Dir, no Read) of a tar.
type Member struct {
	Name string
	Size int64     // -1 when unknown
	Time time.Time // zero when unknown
	Dir  bool
	Read func(limit int64) ([]byte, error)
}

// Detect names the compression from the first bytes.
func Detect(h []byte) Kind {
	switch {
	case len(h) >= 3 && h[0] == 0x1f && h[1] == 0x8b && h[2] == 8:
		return Gzip
	case len(h) >= 10 && bytes.HasPrefix(h, []byte("BZh")) && h[3] >= '1' && h[3] <= '9' &&
		(bytes.Equal(h[4:10], []byte("1AY&SY")) || bytes.Equal(h[4:10], []byte("\x17rE8P\x90"))):
		return Bzip2
	case bytes.HasPrefix(h, []byte("\xfd7zXZ\x00")):
		return XZ
	}
	return None
}

// IsTar reports whether h (at least 512 bytes) starts with a tar header: a
// "ustar" magic, or an old-style header whose checksum is right.
func IsTar(h []byte) bool {
	if len(h) < 512 {
		return false
	}
	if bytes.Equal(h[257:262], []byte("ustar")) {
		return true
	}
	if h[0] == 0 {
		return false
	}
	field := bytes.TrimRight(bytes.TrimLeft(h[148:156], " \x00"), " \x00")
	want, err := strconv.ParseUint(string(field), 8, 32)
	if err != nil || len(field) == 0 {
		return false
	}
	var sum uint64
	for i, c := range h[:512] {
		if i >= 148 && i < 156 {
			c = ' '
		}
		sum += uint64(c)
	}
	return sum == want
}

// Decompress wraps r in the decompressor for k.
func Decompress(k Kind, r io.Reader) (io.Reader, error) {
	switch k {
	case Gzip:
		z, err := gzip.NewReader(r)
		if err != nil {
			return nil, err
		}
		return z, nil
	case Bzip2:
		return bzip2.NewReader(r), nil
	case XZ:
		return xz.ReaderConfig{DictCap: xzDict}.NewReader(r)
	}
	return r, nil
}

// Peek decompresses the start of a stream (up to n bytes), for detection.
func Peek(k Kind, h []byte, n int) []byte {
	defer func() { _ = recover() }()
	d, err := Decompress(k, bytes.NewReader(h))
	if err != nil {
		return nil
	}
	b, _ := io.ReadAll(io.LimitReader(d, int64(n)))
	return b
}

func readLimited(r io.Reader, limit int64) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(r, limit))
	if err != nil && len(b) == 0 {
		return nil, err
	}
	return b, nil
}

// OpenTar lists an uncompressed tar archive; members are read in place.
func OpenTar(r io.ReaderAt, size int64) ([]Member, error) {
	sr := io.NewSectionReader(r, 0, size)
	tr := tar.NewReader(sr)
	var ms []Member
	for i := 0; i < 1<<20; i++ {
		h, err := tr.Next()
		if err != nil {
			if !hasFile(ms) {
				return nil, ErrFormat
			}
			break
		}
		if h.Typeflag == tar.TypeDir {
			ms = append(ms, Member{Name: h.Name, Time: h.ModTime, Dir: true})
			continue
		}
		if !regular(h) {
			continue
		}
		at, _ := sr.Seek(0, io.SeekCurrent)
		n := min(h.Size, size-at)
		ms = append(ms, Member{Name: h.Name, Size: h.Size, Time: h.ModTime, Read: func(limit int64) ([]byte, error) {
			return readLimited(io.NewSectionReader(r, at, n), limit)
		}})
	}
	return ms, nil
}

// regular reports whether a tar entry is a plain file with its own data
// (not a folder, a link or a device).
func regular(h *tar.Header) bool {
	return h.Typeflag == tar.TypeReg || h.Typeflag == 0 || h.Typeflag == tar.TypeCont
}

// Open lists a compressed stream: a tar inside it, or else the one file it
// holds (named by the gzip header, or "" when unknown).
func Open(k Kind, r io.ReaderAt, size int64) (ms []Member, isTar bool, err error) {
	open := func() (io.Reader, error) {
		return Decompress(k, bufio.NewReader(io.NewSectionReader(r, 0, size)))
	}
	d, err := open()
	if err != nil {
		return nil, false, err
	}
	br := bufio.NewReaderSize(d, 1024)
	head, _ := br.Peek(512)
	if len(head) == 0 {
		return nil, false, ErrFormat
	}
	if !IsTar(head) {
		name, n, mod := "", int64(-1), time.Time{}
		if z, ok := d.(*gzip.Reader); ok {
			name, n, mod = z.Name, gzipSize(r, size), z.ModTime
			if mod.Unix() <= 0 {
				mod = time.Time{}
			}
		}
		return []Member{{Name: name, Size: n, Time: mod, Read: func(limit int64) ([]byte, error) {
			d, err := open()
			if err != nil {
				return nil, err
			}
			return readLimited(d, limit)
		}}}, false, nil
	}
	ms = listTar(br, open)
	if !hasFile(ms) {
		return nil, true, ErrFormat
	}
	return ms, true, nil
}

// gzipSize reads the unpacked size from a gzip file's last four bytes (the
// size modulo 4 GB, as gzip -l shows it); -1 when they cannot be read.
func gzipSize(r io.ReaderAt, size int64) int64 {
	var b [4]byte
	if size < 18+4 {
		return -1
	}
	if _, err := r.ReadAt(b[:], size-4); err != nil {
		return -1
	}
	return int64(uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16 | uint32(b[3])<<24)
}

func hasFile(ms []Member) bool {
	for _, m := range ms {
		if !m.Dir {
			return true
		}
	}
	return false
}

// listTar reads the tar headers from a stream, keeping the start of each
// member; a member whose start was not kept, or more of which is wanted,
// is read by decompressing again.
func listTar(src io.Reader, open func() (io.Reader, error)) []Member {
	tr := tar.NewReader(io.LimitReader(src, MaxList))
	var ms []Member
	kept := 0
	for i := 0; i < 1<<20; i++ {
		h, err := tr.Next()
		if err != nil {
			break
		}
		if h.Typeflag == tar.TypeDir {
			ms = append(ms, Member{Name: h.Name, Time: h.ModTime, Dir: true})
			continue
		}
		if !regular(h) {
			continue
		}
		var keep []byte
		if kept < KeepTotal {
			keep, _ = io.ReadAll(io.LimitReader(tr, KeepEach))
			kept += len(keep)
		}
		index, size := i, h.Size
		whole := keep != nil && int64(len(keep)) >= size
		ms = append(ms, Member{Name: h.Name, Size: size, Time: h.ModTime, Read: func(limit int64) ([]byte, error) {
			if keep != nil && (whole || int64(len(keep)) >= limit) {
				return keep[:min(int64(len(keep)), limit)], nil
			}
			return readNth(open, index, limit)
		}})
	}
	return ms
}

// readNth decompresses again and reads the index'th tar entry.
func readNth(open func() (io.Reader, error), index int, limit int64) ([]byte, error) {
	d, err := open()
	if err != nil {
		return nil, err
	}
	tr := tar.NewReader(io.LimitReader(d, MaxList))
	for i := 0; ; i++ {
		if _, err := tr.Next(); err != nil {
			return nil, err
		}
		if i == index {
			return readLimited(tr, limit)
		}
	}
}
