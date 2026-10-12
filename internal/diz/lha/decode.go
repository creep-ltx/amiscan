package lha

import "errors"

var errCorrupt = errors.New("lha: corrupt compressed data")

// bitReader reads bits most significant first. Past the end it returns
// zeros, as LhA itself does; the callers stop on the output size.
type bitReader struct {
	data []byte
	pos  int
	buf  uint64
	n    uint
}

func (b *bitReader) fill() {
	for b.n <= 56 {
		var c byte
		if b.pos < len(b.data) {
			c = b.data[b.pos]
		}
		b.pos++
		b.buf |= uint64(c) << (56 - b.n)
		b.n += 8
	}
}

func (b *bitReader) bits(n uint) int {
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

func (b *bitReader) bit() int { return b.bits(1) }

// overrun reports whether we have read far past the end of the data, which
// only happens with corrupt input.
func (b *bitReader) overrun() bool { return b.pos > len(b.data)+64 }

// huffman is a canonical Huffman code, decoded one bit at a time. Codes are
// given in order of length, then symbol, as LhA's make_table does.
type huffman struct {
	count  [17]int
	syms   []int
	single int // the only symbol when the table has no codes, else -1
}

func newHuffman(lengths []int) (*huffman, error) {
	h := &huffman{single: -1}
	for _, l := range lengths {
		if l > 16 || l < 0 {
			return nil, errCorrupt
		}
		h.count[l]++
	}
	h.count[0] = 0
	var offs [17]int
	for i := 1; i < 16; i++ {
		offs[i+1] = offs[i] + h.count[i]
	}
	h.syms = make([]int, offs[16]+h.count[16])
	for s, l := range lengths {
		if l != 0 {
			h.syms[offs[l]] = s
			offs[l]++
		}
	}
	return h, nil
}

func fixedSymbol(s int) *huffman { return &huffman{single: s} }

func (h *huffman) decode(b *bitReader) (int, error) {
	if h.single >= 0 {
		return h.single, nil
	}
	code, first, index := 0, 0, 0
	for l := 1; l <= 16; l++ {
		code |= b.bit()
		c := h.count[l]
		if code-first < c {
			return h.syms[index+code-first], nil
		}
		index += c
		first += c
		first <<= 1
		code <<= 1
	}
	return 0, errCorrupt
}

// window is the LZ77 sliding dictionary. It starts filled with spaces, as in
// LhA, because the packers may refer to that.
type window struct {
	buf  []byte
	mask int
	pos  int
	out  []byte
	want int64
}

func newWindow(dicbit uint, want int64) *window {
	w := &window{buf: make([]byte, 1<<dicbit), mask: 1<<dicbit - 1, want: want}
	for i := range w.buf {
		w.buf[i] = ' '
	}
	w.out = make([]byte, 0, min(want, 16<<20))
	return w
}

func (w *window) done() bool { return int64(len(w.out)) >= w.want }

func (w *window) put(c byte) {
	w.buf[w.pos] = c
	w.pos = (w.pos + 1) & w.mask
	w.out = append(w.out, c)
}

// copyMatch copies length bytes starting dist+1 bytes back.
func (w *window) copyMatch(dist, length int) {
	from := (w.pos - dist - 1) & w.mask
	for k := 0; k < length && !w.done(); k++ {
		w.put(w.buf[(from+k)&w.mask])
	}
}

// Static Huffman methods -lh4- to -lh7- (LHA's huf.c).
const (
	numC  = 510 // 256 literals + match lengths 3..256
	cBits = 9
	numT  = 19
	tBits = 5
)

type staticDecoder struct {
	br        *bitReader
	np, pbit  uint
	blockSize int
	c, p      *huffman
}

func decodeStatic(packed []byte, want int64, dicbit uint) ([]byte, error) {
	d := &staticDecoder{br: &bitReader{data: packed}}
	switch dicbit {
	case 12, 13:
		d.np, d.pbit = 14, 4
	case 15:
		d.np, d.pbit = 16, 5
	default:
		d.np, d.pbit = 17, 5
	}
	w := newWindow(dicbit, want)
	for !w.done() {
		if d.br.overrun() {
			return nil, errCorrupt
		}
		if d.blockSize == 0 {
			if err := d.readBlock(); err != nil {
				return nil, err
			}
		}
		d.blockSize--
		c, err := d.c.decode(d.br)
		if err != nil {
			return nil, err
		}
		if c < 256 {
			w.put(byte(c))
			continue
		}
		p, err := d.p.decode(d.br)
		if err != nil {
			return nil, err
		}
		if p > 1 {
			p = 1<<(p-1) + d.br.bits(uint(p-1))
		}
		w.copyMatch(p, c-253)
	}
	return w.out, nil
}

func (d *staticDecoder) readBlock() error {
	d.blockSize = d.br.bits(16)
	if d.blockSize == 0 {
		// LhA treats this as 65536 in practice; a zero block never ends.
		d.blockSize = 1 << 16
	}
	t, err := d.readPtLen(numT, tBits, 3)
	if err != nil {
		return err
	}
	if d.c, err = d.readCLen(t); err != nil {
		return err
	}
	d.p, err = d.readPtLen(int(d.np), d.pbit, -1)
	return err
}

func (d *staticDecoder) readPtLen(nn int, nbit uint, special int) (*huffman, error) {
	n := d.br.bits(nbit)
	if n == 0 {
		return fixedSymbol(d.br.bits(nbit)), nil
	}
	if n > nn {
		return nil, errCorrupt
	}
	lens := make([]int, nn)
	i := 0
	for i < n {
		c := d.br.bits(3)
		if c == 7 {
			for d.br.bit() == 1 {
				c++
				if c > 16 {
					return nil, errCorrupt
				}
			}
		}
		lens[i] = c
		i++
		if i == special {
			z := d.br.bits(2)
			for ; z > 0 && i < nn; z-- {
				lens[i] = 0
				i++
			}
		}
	}
	return newHuffman(lens)
}

func (d *staticDecoder) readCLen(t *huffman) (*huffman, error) {
	n := d.br.bits(cBits)
	if n == 0 {
		return fixedSymbol(d.br.bits(cBits)), nil
	}
	if n > numC {
		return nil, errCorrupt
	}
	lens := make([]int, numC)
	i := 0
	for i < n {
		c, err := t.decode(d.br)
		if err != nil {
			return nil, err
		}
		if c <= 2 {
			switch c {
			case 0:
				c = 1
			case 1:
				c = d.br.bits(4) + 3
			default:
				c = d.br.bits(cBits) + 20
			}
			for ; c > 0 && i < numC; c-- {
				lens[i] = 0
				i++
			}
		} else {
			lens[i] = c - 2
			i++
		}
	}
	return newHuffman(lens)
}
