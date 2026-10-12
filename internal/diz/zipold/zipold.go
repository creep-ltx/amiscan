// Package zipold unpacks the Zip methods of PKZIP 0.9 and 1.x that Go's
// archive/zip does not know: shrink (1, LZW with partial clearing), reduce
// (2 to 5, follower sets and run-length copies) and implode (6, sliding
// window with Shannon-Fano codes). Most PC BBS files from 1989 to 1993 are
// packed this way, including PKZIP's own self-extractors.
//
// Register hooks them into archive/zip. Written for BBX from PKWARE's
// APPNOTE.TXT; corrupt input returns an error, never a panic or a hang.
package zipold

import (
	"archive/zip"
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sync"
)

// ErrCorrupt means the packed data cannot be valid.
var ErrCorrupt = errors.New("zipold: corrupt compressed data")

// Zip method numbers.
const (
	Shrink  = 1
	Reduce1 = 2 // to Reduce4 = 5
	Implode = 6
)

var once sync.Once

// Register adds the old methods to archive/zip (once per program).
func Register() {
	once.Do(func() {
		zip.RegisterDecompressor(Shrink, func(r io.Reader) io.ReadCloser { return open(r, Shrink) })
		for m := uint16(Reduce1); m <= Reduce1+3; m++ {
			zip.RegisterDecompressor(m, func(r io.Reader) io.ReadCloser { return open(r, m) })
		}
		zip.RegisterDecompressor(Implode, func(r io.Reader) io.ReadCloser { return open(r, Implode) })
	})
}

// open finds the member's flags and size in its local header (archive/zip
// hands a decompressor only the packed data) and starts the decoder.
func open(r io.Reader, method uint16) io.ReadCloser {
	flags, size, ok := localHeader(r)
	if !ok {
		return &reader{err: fmt.Errorf("zipold: method %d: local header not found", method)}
	}
	return NewReader(r, method, flags, size)
}

// localHeader reads the general purpose flags and the unpacked size of the
// member whose data r is (an io.SectionReader of the archive, as
// archive/zip makes it).
func localHeader(r io.Reader) (flags uint16, size int64, ok bool) {
	sr, isSR := r.(*io.SectionReader)
	if !isSR {
		return 0, 0, false
	}
	ra, off, _ := sr.Outer()
	for _, back := range []int64{512, 30 + 2*65535} {
		back = min(back, off)
		buf := make([]byte, back)
		if n, _ := ra.ReadAt(buf, off-back); int64(n) != back {
			return 0, 0, false
		}
		for i := int(back) - 30; i >= 0; i-- {
			h := buf[i:]
			if !bytes.HasPrefix(h, []byte("PK\x03\x04")) {
				continue
			}
			n := int(binary.LittleEndian.Uint16(h[26:]))
			e := int(binary.LittleEndian.Uint16(h[28:]))
			if i+30+n+e != int(back) {
				continue
			}
			flags = binary.LittleEndian.Uint16(h[6:])
			size = int64(binary.LittleEndian.Uint32(h[22:]))
			if flags&8 != 0 {
				size = -1 // in a data descriptor: run to the end of the data
			}
			return flags, size, true
		}
	}
	return 0, 0, false
}

// NewReader unpacks data packed with an old method. flags are the member's
// general purpose flags (implode uses bits 1 and 2), size its unpacked
// size (-1 if unknown).
func NewReader(r io.Reader, method uint16, flags uint16, size int64) io.ReadCloser {
	br, ok := r.(io.ByteReader)
	if !ok {
		br = bufio.NewReader(r)
	}
	if size < 0 {
		size = 1 << 62
	}
	in := &bits{r: br}
	rd := &reader{size: size}
	var err error
	switch {
	case method == Shrink:
		rd.step, rd.window = newUnshrink(in, rd), 0
	case method >= Reduce1 && method <= Reduce1+3:
		rd.step, err = newUnreduce(in, rd, int(method-Reduce1+1))
		rd.window = 4096
	case method == Implode:
		rd.step, err = newExplode(in, rd, flags&2 != 0, flags&4 != 0)
		rd.window = 8192
	default:
		err = fmt.Errorf("zipold: method %d not supported", method)
	}
	if err != nil {
		rd.err = err
	}
	rd.in = in
	return rd
}

// reader hands out what the decoder's steps produce, keeping only as much
// history as the method's window needs.
type reader struct {
	buf    []byte // history and unread output
	r      int    // first unread byte in buf
	window int    // history the method may copy from
	out    int64  // bytes produced so far
	size   int64
	step   func() error
	in     *bits
	err    error
}

func (rd *reader) put(c byte) {
	if rd.out < rd.size {
		rd.buf = append(rd.buf, c)
		rd.out++
	}
}

// copyMatch appends length bytes from dist back; before the start it gives
// zeros, as the PKZIP unpackers' cleared windows do.
func (rd *reader) copyMatch(dist, length int) {
	for k := 0; k < length && rd.out < rd.size; k++ {
		i := len(rd.buf) - dist
		var c byte
		if i >= 0 {
			c = rd.buf[i]
		}
		rd.put(c)
	}
}

func (rd *reader) Read(p []byte) (int, error) {
	for rd.r == len(rd.buf) && rd.err == nil {
		if rd.out >= rd.size {
			rd.err = io.EOF
			break
		}
		if rd.in.past > 8 {
			rd.err = io.ErrUnexpectedEOF
			break
		}
		if rd.r > rd.window+64<<10 {
			keep := rd.buf[rd.r-rd.window:]
			rd.buf = append(rd.buf[:0], keep...)
			rd.r = rd.window
		}
		if err := rd.step(); err != nil {
			rd.err = err
		}
	}
	n := copy(p, rd.buf[rd.r:])
	rd.r += n
	if n > 0 {
		return n, nil
	}
	return 0, rd.err
}

func (rd *reader) Close() error { return nil }

// bits reads bits least significant first; past the end it gives zeros.
type bits struct {
	r    io.ByteReader
	buf  uint64
	n    uint
	past int
}

func (b *bits) get(n uint) int {
	for b.n < n {
		c, err := b.r.ReadByte()
		if err != nil {
			c = 0
			b.past++
		}
		b.buf |= uint64(c) << b.n
		b.n += 8
	}
	v := int(b.buf & (1<<n - 1))
	b.buf >>= n
	b.n -= n
	return v
}

func (b *bits) byte() int { return b.get(8) }
