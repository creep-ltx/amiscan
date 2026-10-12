// Package lzh decodes the static-Huffman LZ77 streams of Haruhiko Okumura's
// ar002 family: LhA's -lh5- (also used by ZOO's method 2) and ARJ's methods
// 1 to 3. Both store blocks of a code-length code, a literal/length code and
// a position code, read most significant bit first.
//
// Written for BBX from the format as described in ar002 and the ARJ and LhA
// technical notes; corrupt input returns an error, never a panic or a hang.
package lzh

import (
	"errors"
	"io"
)

// ErrCorrupt means the compressed data cannot be valid.
var ErrCorrupt = errors.New("lzh: corrupt compressed data")

// BitReader reads bits most significant first from a byte stream. Past the
// end of the data it returns zero bits; Overrun tells when it has gone well
// past, which only corrupt data does.
type BitReader struct {
	r    io.ByteReader
	buf  uint64
	n    uint
	past int
}

// NewBitReader reads bits from r.
func NewBitReader(r io.ByteReader) *BitReader { return &BitReader{r: r} }

func (b *BitReader) fill() {
	for b.n <= 56 {
		c, err := b.r.ReadByte()
		if err != nil {
			c = 0
			b.past++
		}
		b.buf |= uint64(c) << (56 - b.n)
		b.n += 8
	}
}

// Bits returns the next n bits (n <= 32).
func (b *BitReader) Bits(n uint) int {
	if n == 0 {
		return 0
	}
	if b.n < n {
		b.fill()
	}
	v := int(b.buf >> (64 - n))
	b.buf <<= n
	b.n -= n
	return v
}

// Bit returns the next bit.
func (b *BitReader) Bit() int { return b.Bits(1) }

// Overrun reports whether far more bits were read than the data has.
func (b *BitReader) Overrun() bool { return b.past > 64 }

// Params are the stream's sizes.
type Params struct {
	NP   int  // number of position codes (dictionary bits + 1)
	PBit uint // bits that give the position-code count
	Fill byte // what the window holds before the first byte (LhA: ' ')
}

var (
	// LH5 is LhA's -lh5- (8 KB window), also ZOO method 2.
	LH5 = Params{NP: 14, PBit: 4, Fill: ' '}
	// ARJ is ARJ's methods 1 to 3 (26 KB window, positions up to 64 KB).
	ARJ = Params{NP: 17, PBit: 5}
)

const (
	nc        = 256 + 256 + 2 - 3 // literals and match lengths 3..256
	nt        = 16 + 3            // code-length code
	tBit      = 5
	cBit      = 9
	threshold = 3
	maxLen    = 16
)

// huffman is a canonical code decoded one bit at a time.
type huffman struct {
	count  [maxLen + 1]int
	syms   []int
	single int // the only symbol when no bits are used, else -1
}

func newHuffman(lengths []int) (*huffman, error) {
	h := &huffman{single: -1}
	for _, l := range lengths {
		if l < 0 || l > maxLen {
			return nil, ErrCorrupt
		}
		h.count[l]++
	}
	h.count[0] = 0
	var offs [maxLen + 2]int
	for i := 1; i <= maxLen; i++ {
		offs[i+1] = offs[i] + h.count[i]
	}
	h.syms = make([]int, offs[maxLen+1])
	for s, l := range lengths {
		if l != 0 {
			h.syms[offs[l]] = s
			offs[l]++
		}
	}
	return h, nil
}

func (h *huffman) decode(b *BitReader) (int, error) {
	if h.single >= 0 {
		return h.single, nil
	}
	code, first, index := 0, 0, 0
	for l := 1; l <= maxLen; l++ {
		code |= b.Bit()
		c := h.count[l]
		if code-first < c {
			return h.syms[index+code-first], nil
		}
		index += c
		first = (first + c) << 1
		code <<= 1
	}
	return 0, ErrCorrupt
}

type decoder struct {
	b     *BitReader
	p     Params
	pt, c *huffman
	pos   *huffman
	left  int // symbols left in this block
}

// Decode unpacks want bytes from r.
func Decode(r io.ByteReader, want int64, p Params) (out []byte, err error) {
	if want < 0 {
		return nil, ErrCorrupt
	}
	d := &decoder{b: NewBitReader(r), p: p}
	out = make([]byte, 0, min(want, 1<<20))
	for int64(len(out)) < want {
		if d.left == 0 {
			if err := d.readBlock(); err != nil {
				return out, err
			}
		}
		d.left--
		c, err := d.c.decode(d.b)
		if err != nil {
			return out, err
		}
		if c < 256 {
			out = append(out, byte(c))
		} else {
			length := c - 256 + threshold
			j, err := d.pos.decode(d.b)
			if err != nil {
				return out, err
			}
			if j != 0 {
				j = 1<<(j-1) + d.b.Bits(uint(j-1))
			}
			from := len(out) - j - 1
			for k := 0; k < length && int64(len(out)) < want; k++ {
				if from+k < 0 {
					out = append(out, p.Fill)
				} else {
					out = append(out, out[from+k])
				}
			}
		}
		if d.b.Overrun() {
			return out, ErrCorrupt
		}
	}
	return out, nil
}

func (d *decoder) readBlock() error {
	d.left = d.b.Bits(16)
	if d.b.Overrun() {
		return io.ErrUnexpectedEOF
	}
	var err error
	if d.pt, err = d.readPtLen(nt, tBit, 3); err != nil {
		return err
	}
	if d.c, err = d.readCLen(); err != nil {
		return err
	}
	if d.pos, err = d.readPtLen(d.p.NP, d.p.PBit, -1); err != nil {
		return err
	}
	if d.left == 0 {
		// A zero block size would be 65536 in the original, which
		// nothing writes; treat it as corrupt to stay safe.
		return ErrCorrupt
	}
	return nil
}

func (d *decoder) readPtLen(nn int, nbit uint, special int) (*huffman, error) {
	n := d.b.Bits(nbit)
	if n == 0 {
		c := d.b.Bits(nbit)
		if c >= nn {
			return nil, ErrCorrupt
		}
		return &huffman{single: c}, nil
	}
	if n > nn {
		return nil, ErrCorrupt
	}
	lens := make([]int, nn)
	for i := 0; i < n; {
		c := d.b.Bits(3)
		if c == 7 {
			for d.b.Bit() == 1 {
				c++
				if c > maxLen {
					return nil, ErrCorrupt
				}
			}
		}
		lens[i] = c
		i++
		if i == special {
			z := d.b.Bits(2)
			if i+z > nn {
				return nil, ErrCorrupt
			}
			i += z // those lengths stay 0
		}
	}
	return newHuffman(lens)
}

func (d *decoder) readCLen() (*huffman, error) {
	n := d.b.Bits(cBit)
	if n == 0 {
		c := d.b.Bits(cBit)
		if c >= nc {
			return nil, ErrCorrupt
		}
		return &huffman{single: c}, nil
	}
	if n > nc {
		return nil, ErrCorrupt
	}
	lens := make([]int, nc)
	for i := 0; i < n; {
		c, err := d.pt.decode(d.b)
		if err != nil {
			return nil, err
		}
		if c <= 2 {
			switch c {
			case 0:
				c = 1
			case 1:
				c = d.b.Bits(4) + 3
			default:
				c = d.b.Bits(cBit) + 20
			}
			if i+c > nc {
				return nil, ErrCorrupt
			}
			i += c
		} else {
			lens[i] = c - 2
			i++
		}
		if d.b.Overrun() {
			return nil, ErrCorrupt
		}
	}
	return newHuffman(lens)
}
