package dms

import "errors"

var errBad = errors.New("bad packed data")

// bits reads the packed stream MSB first, as xDMS's GETBITS/DROPBITS: buf
// holds cnt bits (16..23 after every drop). Reading past the end gives
// zeros; too far past it marks the stream bad.
type bits struct {
	in  []byte
	pos int
	buf uint32
	cnt uint
	bad bool
}

func (b *bits) init(in []byte) {
	b.in, b.pos, b.buf, b.cnt, b.bad = in, 0, 0, 0, false
	b.drop(0)
}

func (b *bits) get(n uint) uint16 { return uint16(b.buf >> (b.cnt - n)) }

func (b *bits) drop(n uint) {
	if n > b.cnt {
		b.bad = true
		n = b.cnt
	}
	b.cnt -= n
	b.buf &= 1<<b.cnt - 1
	for b.cnt < 16 {
		var c byte
		if b.pos < len(b.in) {
			c = b.in[b.pos]
		} else if b.pos > len(b.in)+8 {
			b.bad = true
		}
		b.pos++
		b.buf = b.buf<<8 | uint32(c)
		b.cnt += 8
	}
}

const (
	// DEEP (LZHUF with a 16 KB window)
	nChar    = 256 - 2 + 60
	tSize    = nChar*2 - 1
	root     = tSize - 1
	maxFreq  = 0x8000
	thresh   = 2
	heavyNC  = 510
	heavyNPT = 20
)

// decoder is xDMS's global state: the shared text window and each mode's
// position in it, the DEEP tree and the HEAVY tables, all of which carry
// over from one track to the next unless a track says otherwise.
type decoder struct {
	text      [32000]byte
	quickLoc  uint16
	mediumLoc uint16
	heavyLoc  uint16
	deepLoc   uint16
	initDeep  bool
	br        bits

	freq [tSize + 1]uint16
	prnt [tSize + nChar]uint16
	son  [tSize]uint16

	left    [2*heavyNC - 1]uint16
	right   [2*heavyNC - 1 + 9]uint16
	cLen    [heavyNC]byte
	ptLen   [heavyNPT]byte
	cTable  [4096]uint16
	ptTable [256]uint16
	lastLen uint16
	np      uint16
	mt      makeTable
}

func newDecoder() *decoder {
	d := &decoder{}
	d.reinit()
	return d
}

// reinit is xDMS's Init_Decrunchers.
func (d *decoder) reinit() {
	d.quickLoc = 251
	d.mediumLoc = 0x3fbe
	d.heavyLoc = 0
	d.deepLoc = 0x3fc4
	d.initDeep = true
	clear(d.text[:0x3fc8])
}

// track unpacks one track's data (Unpack_Track).
func (d *decoder) track(in []byte, pk2, unpk int, mode, flags byte) ([]byte, error) {
	var out []byte
	var err error
	switch mode {
	case 0:
		if len(in) < unpk {
			return nil, errBad
		}
		out = append([]byte(nil), in[:unpk]...)
	case 1:
		out, err = rle(in, unpk)
	case 2, 3, 4:
		tmp := make([]byte, pk2+slack)
		switch mode {
		case 2:
			err = d.quick(in, tmp, pk2)
		case 3:
			err = d.medium(in, tmp, pk2)
		case 4:
			err = d.deep(in, tmp, pk2)
		}
		if err == nil {
			out, err = rle(tmp, unpk)
		}
	case 5, 6:
		f := flags & 7
		if mode == 6 {
			f = flags | 8
		}
		tmp := make([]byte, max(pk2, unpk)+slack)
		if err = d.heavy(in, tmp, f, pk2); err == nil {
			if flags&4 != 0 {
				out, err = rle(tmp, unpk)
			} else {
				out = tmp[:unpk]
			}
		}
	default:
		return nil, errors.New("unknown packing mode")
	}
	if err != nil {
		return nil, err
	}
	if flags&1 == 0 {
		d.reinit()
	}
	return out, nil
}

// rle undoes the run-length stage: 0x90 0 is a literal 0x90; 0x90 n c is n
// times c; 0x90 0xFF c hi lo is (hi<<8|lo) times c.
func rle(in []byte, size int) ([]byte, error) {
	out := make([]byte, 0, size)
	i := 0
	next := func() (byte, bool) {
		if i >= len(in) {
			return 0, false
		}
		i++
		return in[i-1], true
	}
	for len(out) < size {
		a, ok := next()
		if !ok {
			return nil, errBad
		}
		if a != 0x90 {
			out = append(out, a)
			continue
		}
		b, ok := next()
		if !ok {
			return nil, errBad
		}
		if b == 0 {
			out = append(out, a)
			continue
		}
		c, ok := next()
		if !ok {
			return nil, errBad
		}
		n := int(b)
		if b == 0xff {
			hi, ok1 := next()
			lo, ok2 := next()
			if !ok1 || !ok2 {
				return nil, errBad
			}
			n = int(hi)<<8 | int(lo)
		}
		if len(out)+n > size {
			return nil, errBad
		}
		for ; n > 0; n-- {
			out = append(out, c)
		}
	}
	return out, nil
}

// quick: LZ77 with a 256-byte window.
func (d *decoder) quick(in, out []byte, size int) error {
	b := &d.br
	b.init(in)
	o := 0
	for o < size {
		if b.bad {
			return errBad
		}
		if b.get(1) != 0 {
			b.drop(1)
			c := byte(b.get(8))
			b.drop(8)
			d.text[d.quickLoc&0xff] = c
			d.quickLoc++
			out[o] = c
			o++
		} else {
			b.drop(1)
			j := int(b.get(2)) + 2
			b.drop(2)
			i := d.quickLoc - b.get(8) - 1
			b.drop(8)
			for ; j > 0; j-- {
				c := d.text[i&0xff]
				i++
				d.text[d.quickLoc&0xff] = c
				d.quickLoc++
				out[o] = c
				o++
			}
		}
	}
	d.quickLoc = (d.quickLoc + 5) & 0xff
	return nil
}

// medium: LZ77 with a 16 KB window, positions coded as in LZHUF.
func (d *decoder) medium(in, out []byte, size int) error {
	b := &d.br
	b.init(in)
	o := 0
	for o < size {
		if b.bad {
			return errBad
		}
		if b.get(1) != 0 {
			b.drop(1)
			c := byte(b.get(8))
			b.drop(8)
			d.text[d.mediumLoc&0x3fff] = c
			d.mediumLoc++
			out[o] = c
			o++
		} else {
			b.drop(1)
			c := b.get(8)
			b.drop(8)
			j := int(dCode[c]) + 3
			u := uint(dLen[c])
			c = ((c << u) | b.get(u)) & 0xff
			b.drop(u)
			u = uint(dLen[c])
			c = uint16(dCode[c])<<8 | (((c << u) | b.get(u)) & 0xff)
			b.drop(u)
			i := d.mediumLoc - c - 1
			for ; j > 0; j-- {
				x := d.text[i&0x3fff]
				i++
				d.text[d.mediumLoc&0x3fff] = x
				d.mediumLoc++
				out[o] = x
				o++
			}
		}
	}
	d.mediumLoc = (d.mediumLoc + 66) & 0x3fff
	return nil
}

// deep: LZHUF (Yoshizaki) with adaptive Huffman codes and a 16 KB window.
func (d *decoder) deep(in, out []byte, size int) error {
	b := &d.br
	b.init(in)
	if d.initDeep {
		d.deepTabs()
	}
	o := 0
	for o < size {
		if b.bad {
			return errBad
		}
		c := d.decodeChar()
		if c < 256 {
			d.text[d.deepLoc&0x3fff] = byte(c)
			d.deepLoc++
			out[o] = byte(c)
			o++
		} else {
			j := int(c) - 255 + thresh
			i := d.deepLoc - d.decodePosition() - 1
			for ; j > 0; j-- {
				x := d.text[i&0x3fff]
				i++
				d.text[d.deepLoc&0x3fff] = x
				d.deepLoc++
				out[o] = x
				o++
			}
		}
	}
	d.deepLoc = (d.deepLoc + 60) & 0x3fff
	return nil
}

func (d *decoder) deepTabs() {
	for i := 0; i < nChar; i++ {
		d.freq[i] = 1
		d.son[i] = uint16(i + tSize)
		d.prnt[i+tSize] = uint16(i)
	}
	i, j := 0, nChar
	for j <= root {
		d.freq[j] = d.freq[i] + d.freq[i+1]
		d.son[j] = uint16(i)
		d.prnt[i], d.prnt[i+1] = uint16(j), uint16(j)
		i += 2
		j++
	}
	d.freq[tSize] = 0xffff
	d.prnt[root] = 0
	d.initDeep = false
}

func (d *decoder) decodeChar() uint16 {
	b := &d.br
	c := d.son[root]
	for c < tSize {
		c = d.son[c+b.get(1)]
		b.drop(1)
	}
	c -= tSize
	d.update(c)
	return c
}

func (d *decoder) decodePosition() uint16 {
	b := &d.br
	i := b.get(8)
	b.drop(8)
	c := uint16(dCode[i]) << 8
	j := uint(dLen[i])
	i = ((i << j) | b.get(j)) & 0xff
	b.drop(j)
	return c | i
}

func (d *decoder) reconst() {
	j := 0
	for i := 0; i < tSize; i++ {
		if d.son[i] >= tSize {
			d.freq[j] = (d.freq[i] + 1) / 2
			d.son[j] = d.son[i]
			j++
		}
	}
	for i, j := 0, nChar; j < tSize; i, j = i+2, j+1 {
		f := d.freq[i] + d.freq[i+1]
		d.freq[j] = f
		k := j - 1
		for f < d.freq[k] {
			k--
		}
		k++
		copy(d.freq[k+1:j+1], d.freq[k:j])
		d.freq[k] = f
		copy(d.son[k+1:j+1], d.son[k:j])
		d.son[k] = uint16(i)
	}
	for i := 0; i < tSize; i++ {
		if k := d.son[i]; k >= tSize {
			d.prnt[k] = uint16(i)
		} else {
			d.prnt[k], d.prnt[k+1] = uint16(i), uint16(i)
		}
	}
}

func (d *decoder) update(c uint16) {
	if d.freq[root] == maxFreq {
		d.reconst()
	}
	c = d.prnt[c+tSize]
	for {
		d.freq[c]++
		k := d.freq[c]
		if l := c + 1; k > d.freq[l] {
			for {
				l++
				if !(k > d.freq[l]) {
					break
				}
			}
			l--
			d.freq[c] = d.freq[l]
			d.freq[l] = k
			i := d.son[c]
			d.prnt[i] = l
			if i < tSize {
				d.prnt[i+1] = l
			}
			j := d.son[l]
			d.son[l] = i
			d.prnt[j] = c
			if j < tSize {
				d.prnt[j+1] = c
			}
			d.son[c] = j
			c = l
		}
		c = d.prnt[c]
		if c == 0 {
			break
		}
	}
}

// heavy: LZH (as LHA's -lh5-) with a 4 KB (HEAVY1) or 8 KB (HEAVY2)
// window; flags&2 means new code tables come first, otherwise the last
// track's tables are used again.
func (d *decoder) heavy(in, out []byte, flags byte, size int) error {
	b := &d.br
	var mask uint16
	if flags&8 != 0 {
		d.np, mask = 15, 0x1fff
	} else {
		d.np, mask = 14, 0x0fff
	}
	b.init(in)
	if flags&2 != 0 {
		if !d.readTreeC() || !d.readTreeP() {
			return errBad
		}
	}
	o := 0
	for o < size {
		if b.bad {
			return errBad
		}
		c, ok := d.decodeC()
		if !ok {
			return errBad
		}
		if c < 256 {
			d.text[d.heavyLoc&mask] = byte(c)
			d.heavyLoc++
			out[o] = byte(c)
			o++
		} else {
			j := int(c) - 253
			p, ok := d.decodeP()
			if !ok {
				return errBad
			}
			i := d.heavyLoc - p - 1
			if o+j > len(out) {
				return errBad
			}
			for ; j > 0; j-- {
				x := d.text[i&mask]
				i++
				d.text[d.heavyLoc&mask] = x
				d.heavyLoc++
				out[o] = x
				o++
			}
		}
	}
	return nil
}

func (d *decoder) decodeC() (uint16, bool) {
	b := &d.br
	j := d.cTable[b.get(12)]
	if j < heavyNC {
		b.drop(uint(d.cLen[j]))
		return j, true
	}
	b.drop(12)
	i := b.get(16)
	m := uint16(0x8000)
	for {
		if m == 0 || int(j) >= len(d.left) {
			return 0, false
		}
		if i&m != 0 {
			j = d.right[j]
		} else {
			j = d.left[j]
		}
		m >>= 1
		if j < heavyNC {
			break
		}
	}
	if d.cLen[j] < 12 {
		return 0, false
	}
	b.drop(uint(d.cLen[j]) - 12)
	return j, true
}

func (d *decoder) decodeP() (uint16, bool) {
	b := &d.br
	j := d.ptTable[b.get(8)]
	if j < d.np {
		if int(j) >= len(d.ptLen) {
			return 0, false
		}
		b.drop(uint(d.ptLen[j]))
	} else {
		b.drop(8)
		i := b.get(16)
		m := uint16(0x8000)
		for {
			if m == 0 || int(j) >= len(d.left) {
				return 0, false
			}
			if i&m != 0 {
				j = d.right[j]
			} else {
				j = d.left[j]
			}
			m >>= 1
			if j < d.np {
				break
			}
		}
		if d.ptLen[j] < 8 {
			return 0, false
		}
		b.drop(uint(d.ptLen[j]) - 8)
	}
	if j != d.np-1 {
		if j > 0 {
			n := uint(j - 1)
			j = b.get(n) | 1<<n
			b.drop(n)
		}
		d.lastLen = j
	}
	return d.lastLen, true
}

func (d *decoder) readTreeC() bool {
	b := &d.br
	n := int(b.get(9))
	b.drop(9)
	if n > 0 {
		if n > heavyNC {
			return false
		}
		for i := 0; i < n; i++ {
			d.cLen[i] = byte(b.get(5))
			b.drop(5)
		}
		clear(d.cLen[n:])
		return d.mt.make(heavyNC, d.cLen[:], 12, d.cTable[:], d)
	}
	n = int(b.get(9))
	b.drop(9)
	clear(d.cLen[:])
	for i := range d.cTable {
		d.cTable[i] = uint16(n)
	}
	return true
}

func (d *decoder) readTreeP() bool {
	b := &d.br
	n := int(b.get(5))
	b.drop(5)
	if n > 0 {
		if n > int(d.np) {
			return false
		}
		for i := 0; i < n; i++ {
			d.ptLen[i] = byte(b.get(4))
			b.drop(4)
		}
		clear(d.ptLen[n:d.np])
		return d.mt.make(int(d.np), d.ptLen[:], 8, d.ptTable[:], d)
	}
	n = int(b.get(5))
	b.drop(5)
	clear(d.ptLen[:d.np])
	for i := range d.ptTable {
		d.ptTable[i] = uint16(n)
	}
	return true
}

// makeTable is xDMS's make_table (from UNIX LHA by Masaru Oki): a lookup
// table for codes up to tablebits long, a tree in left/right for longer ones.
type makeTable struct {
	c                                    int
	n, tblsiz, len, depth, maxdepth, avl int
	codeword, bit                        int
	tbl                                  []uint16
	blen                                 []byte
	err                                  bool
	d                                    *decoder
}

func (t *makeTable) make(nchar int, bitlen []byte, tablebits uint, table []uint16, d *decoder) bool {
	*t = makeTable{n: nchar, avl: nchar, blen: bitlen, tbl: table, d: d}
	t.tblsiz = 1 << tablebits
	t.bit = t.tblsiz / 2
	t.maxdepth = int(tablebits) + 1
	t.depth, t.len = 1, 1
	t.c = -1
	t.mk()
	if t.err {
		return false
	}
	t.mk()
	if t.err {
		return false
	}
	return t.codeword == t.tblsiz
}

func (t *makeTable) mk() uint16 {
	var i int
	if t.err {
		return 0
	}
	if t.len == t.depth {
		for t.c++; t.c < t.n; t.c++ {
			if int(t.blen[t.c]) == t.len {
				i = t.codeword
				t.codeword += t.bit
				if t.codeword > t.tblsiz {
					t.err = true
					return 0
				}
				for ; i < t.codeword; i++ {
					t.tbl[i] = uint16(t.c)
				}
				return uint16(t.c)
			}
		}
		t.c = -1
		t.len++
		t.bit >>= 1
	}
	t.depth++
	if t.depth < t.maxdepth {
		t.mk()
		t.mk()
	} else if t.depth > 32 {
		t.err = true
		return 0
	} else {
		i = t.avl
		t.avl++
		if i >= 2*t.n-1 {
			t.err = true
			return 0
		}
		l := t.mk()
		r := t.mk()
		t.d.left[i] = l
		t.d.right[i] = r
		if t.codeword >= t.tblsiz {
			t.err = true
			return 0
		}
		if t.depth == t.maxdepth {
			t.tbl[t.codeword] = uint16(i)
			t.codeword++
		}
	}
	t.depth--
	return uint16(i)
}

// dCode and dLen are LZHUF's position tables (the upper 6 bits of a
// position and the number of extra bits after the first 8).
var dCode, dLen = func() (code, ln [256]byte) {
	i := 0
	put := func(count, codes int, start byte, bitsLen byte) {
		for c := 0; c < codes; c++ {
			for k := 0; k < count; k++ {
				code[i] = start + byte(c)
				ln[i] = bitsLen
				i++
			}
		}
	}
	// code values
	put(32, 1, 0x00, 0)
	put(16, 3, 0x01, 0)
	put(8, 8, 0x04, 0)
	put(4, 12, 0x0c, 0)
	put(2, 24, 0x18, 0)
	put(1, 16, 0x30, 0)
	// lengths
	lens := []struct{ n, l int }{{32, 3}, {48, 4}, {64, 5}, {48, 6}, {48, 7}, {16, 8}}
	i = 0
	for _, x := range lens {
		for k := 0; k < x.n; k++ {
			ln[i] = byte(x.l)
			i++
		}
	}
	return
}()
