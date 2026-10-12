package arc

import (
	"errors"
	"io"

	"github.com/creep-ltx/amiscan/internal/diz/lzh"
)

var errCorrupt = errors.New("arc: corrupt compressed data")

// lsb reads bits least significant first; past the end it gives zeros.
type lsb struct {
	r    io.ByteReader
	buf  uint64
	n    uint
	past int
}

func (b *lsb) bits(n uint) int {
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

func (b *lsb) bit() int { return b.bits(1) }

func (b *lsb) overrun() bool { return b.past > 8 }

// unsqueeze decodes method 4: a Huffman tree of at most 256 nodes (pairs of
// 16-bit children, negative = leaf -(symbol+1)), symbol 256 ends the data.
func unsqueeze(src io.ByteReader, o *output) error {
	b := &lsb{r: src}
	n := b.bits(16)
	if n > 256 {
		return errCorrupt
	}
	tree := make([]int16, 2*n+2)
	tree[0], tree[1] = -257, -257 // an empty tree is just the end
	for i := 0; i < 2*n; i++ {
		tree[i] = int16(b.bits(16))
	}
	if b.overrun() {
		return io.ErrUnexpectedEOF
	}
	for !o.full() {
		node := 0
		for depth := 0; ; depth++ {
			if depth > 256 || b.overrun() {
				return errCorrupt
			}
			v := int(tree[2*node+b.bit()])
			if v < 0 {
				sym := -(v + 1)
				if sym == 256 {
					return nil
				}
				if sym > 256 {
					return errCorrupt
				}
				o.put(byte(sym))
				break
			}
			if v >= n {
				return errCorrupt
			}
			node = v
		}
	}
	return nil
}

// uncrunchOld decodes methods 5 to 7: 12-bit LZW codes, most significant
// bit first, whose table slots are found by hashing (ARC before 5.0).
func uncrunchOld(src io.ByteReader, o *output, fast bool) error {
	type entry struct {
		used   bool
		next   int
		parent int
		c      byte
	}
	var tab [4096]entry
	hash := func(parent int, c byte) int {
		k := (parent + int(c)) & 0xffff
		if fast {
			return k * 15073 & 0xfff
		}
		k = (k | 0x800) & 0xffff
		return int(uint64(k)*uint64(k)>>6) & 0xfff
	}
	free := 4096
	add := func(parent int, c byte) {
		i := hash(parent, c)
		if tab[i].used {
			for k := 0; tab[i].next != 0 && k < 4096; k++ {
				i = tab[i].next
			}
			j := (i + 101) & 0xfff
			for k := 0; tab[j].used && k < 4096; k++ {
				j = (j + 1) & 0xfff
			}
			tab[i].next = j
			i = j
		}
		tab[i] = entry{used: true, parent: parent, c: c}
		free--
	}
	for c := 0; c < 256; c++ {
		add(-1, byte(c))
	}
	b := lzh.NewBitReader(src)
	var stack [4096]byte
	code := b.Bits(12)
	if !tab[code].used {
		return errCorrupt
	}
	last, lastByte := code, tab[code].c
	o.put(lastByte)
	for !o.full() {
		if b.Overrun() {
			return io.ErrUnexpectedEOF
		}
		code = b.Bits(12)
		sp := 0
		e := code
		if !tab[e].used {
			e = last
			stack[sp] = lastByte
			sp++
		}
		for tab[e].parent != -1 {
			if sp >= len(stack)-1 || !tab[e].used {
				return errCorrupt
			}
			stack[sp] = tab[e].c
			sp++
			e = tab[e].parent
		}
		first := tab[e].c
		stack[sp] = first
		sp++
		if free > 0 {
			add(last, first)
		}
		last, lastByte = code, first
		for sp > 0 {
			sp--
			o.put(stack[sp])
		}
	}
	return nil
}

// uncompress decodes methods 8 and 9: Unix compress style LZW, 9 bits
// growing to maxBits, code 256 clears; codes come in groups of eight and
// the rest of a group is skipped when the code size changes.
func uncompress(src io.ByteReader, o *output, maxBits int) error {
	const first = 257
	maxMax := 1 << maxBits
	prefix := make([]uint16, maxMax)
	suffix := make([]byte, maxMax)
	for i := 0; i < 256; i++ {
		suffix[i] = byte(i)
	}
	var (
		buf     [16]byte
		offset  int // bit offset in buf
		size    int // usable bits in buf
		nBits   = 9
		maxCode = 1<<9 - 1
		freeEnt = first
		clear   bool
	)
	getCode := func() int {
		if clear || offset >= size || freeEnt > maxCode {
			if freeEnt > maxCode {
				nBits++
				if nBits >= maxBits {
					nBits = maxBits
					maxCode = maxMax
				} else {
					maxCode = 1<<nBits - 1
				}
			}
			if clear {
				nBits = 9
				maxCode = 1<<9 - 1
				clear = false
			}
			n := 0
			for ; n < nBits; n++ {
				c, err := src.ReadByte()
				if err != nil {
					break
				}
				buf[n] = c
			}
			if n == 0 {
				return -1
			}
			offset = 0
			size = n*8 - (nBits - 1)
			if size <= 0 {
				return -1
			}
		}
		code := 0
		for i := 0; i < nBits; i++ {
			bit := offset + i
			code |= int(buf[bit>>3]>>(bit&7)&1) << i
		}
		offset += nBits
		return code
	}

	stack := make([]byte, 0, maxMax)
	oldCode := getCode()
	if oldCode < 0 {
		return nil
	}
	if oldCode > 255 {
		return errCorrupt
	}
	finChar := byte(oldCode)
	o.put(finChar)
	for !o.full() {
		code := getCode()
		if code < 0 {
			return nil
		}
		if code == 256 {
			clear = true
			freeEnt = first - 1
			if code = getCode(); code < 0 {
				return nil
			}
		}
		in := code
		stack = stack[:0]
		if code >= freeEnt {
			if code > freeEnt {
				return errCorrupt
			}
			stack = append(stack, finChar)
			code = oldCode
		}
		for code >= 256 {
			if len(stack) >= maxMax {
				return errCorrupt
			}
			stack = append(stack, suffix[code])
			code = int(prefix[code])
		}
		finChar = suffix[code]
		stack = append(stack, finChar)
		for i := len(stack) - 1; i >= 0; i-- {
			o.put(stack[i])
		}
		if freeEnt < maxMax {
			prefix[freeEnt] = uint16(oldCode)
			suffix[freeEnt] = finChar
			freeEnt++
		}
		oldCode = in
	}
	return nil
}

// uncrush decodes PAK's method 10: LZW up to 13 bits whose codes switch
// between a literal-flag form and a plain form by how many recent codes
// were strings, and which, once full, reuses its least recently used
// entries. Following The Unarchiver's description of PAK 2.5.
func uncrush(src io.ByteReader, o *output) error {
	const max = 8192
	var (
		parent [max]int32
		chr    [max]byte
		usage  [max]int
		ring   [500]bool
		buf    [max]byte
	)
	for i := 0; i < 256; i++ {
		parent[i] = -1
		chr[i] = byte(i)
	}
	firstByte := func(s int) (byte, bool) {
		for k := 0; parent[s] >= 0; k++ {
			if k >= max {
				return 0, false
			}
			s = int(parent[s])
		}
		return chr[s], true
	}
	b := &lsb{r: src}
	num, prev := 257, -1
	size, bump, litBit := uint(1), 2, true
	recent, ringAt, usageAt := 0, 0, 0x101
	for !o.full() {
		if b.overrun() || size > 16 {
			return io.ErrUnexpectedEOF
		}
		var sym int
		if litBit {
			if b.bit() == 1 {
				sym = b.bits(size) + 256
			} else {
				sym = b.bits(8)
			}
		} else {
			sym = b.bits(size)
			if sym < 256 {
				sym ^= 0xff
			}
		}
		if sym == 256 {
			return nil // end of data
		}
		if sym >= max {
			return errCorrupt
		}
		for m, k := sym, 0; m >= 0 && k < max; m, k = int(parent[m]), k+1 {
			usage[m] = 4
		}
		if ring[ringAt] {
			recent--
		}
		ring[ringAt] = sym >= 256
		if sym >= 256 {
			recent++
		}
		ringAt = (ringAt + 1) % len(ring)
		if many := recent < 375; many != litBit {
			litBit = many
			bump = 1 << size
			if !litBit {
				bump -= 0x100
			}
		}
		if num < max {
			if prev < 0 {
				if sym >= num {
					return errCorrupt
				}
			} else {
				var post byte
				var ok bool
				switch {
				case sym < num:
					post, ok = firstByte(sym)
				case sym == num:
					post, ok = firstByte(prev)
				}
				if !ok {
					return errCorrupt
				}
				parent[num] = int32(prev)
				chr[num] = post
				num++
			}
			prev = sym
			usage[num-1] = 2
		} else {
			minAt, minUse := 0, int(^uint(0)>>1)
			i := usageAt
			for {
				i++
				if i == max {
					i = 0x101
				}
				if usage[i] < minUse {
					minAt, minUse = i, usage[i]
				}
				usage[i]--
				if usage[i] == 0 || i == usageAt {
					break
				}
			}
			usageAt = i
			if prev < 0 {
				return errCorrupt
			}
			parent[minAt] = int32(prev)
			c, ok := firstByte(sym)
			if !ok {
				return errCorrupt
			}
			chr[minAt] = c
			prev = sym
			usage[minAt] = 2
		}
		n := 0
		for s := prev; s >= 0; s = int(parent[s]) {
			if n >= max {
				return errCorrupt
			}
			buf[n] = chr[s]
			n++
		}
		for n > 0 {
			n--
			o.put(buf[n])
		}
		if num-257 >= bump {
			size++
			bump = 1 << size
			if !litBit {
				bump -= 0x100
			}
		}
	}
	return nil
}

// Distill (PAK method 11) position codes, least significant bit first.
var distillLen = [64]uint8{
	3, 4, 4, 4, 5, 5, 5, 5, 5, 5, 5, 5, 6, 6, 6, 6,
	6, 6, 6, 6, 6, 6, 6, 6, 7, 7, 7, 7, 7, 7, 7, 7,
	7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
	8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8,
}

var distillCode = [64]uint8{
	0x00, 0x02, 0x04, 0x0c, 0x01, 0x06, 0x0a, 0x0e,
	0x11, 0x16, 0x1a, 0x1e, 0x05, 0x09, 0x0d, 0x15,
	0x19, 0x1d, 0x25, 0x29, 0x2d, 0x35, 0x39, 0x3d,
	0x03, 0x07, 0x0b, 0x13, 0x17, 0x1b, 0x23, 0x27,
	0x2b, 0x33, 0x37, 0x3b, 0x43, 0x47, 0x4b, 0x53,
	0x57, 0x5b, 0x63, 0x67, 0x6b, 0x73, 0x77, 0x7b,
	0x0f, 0x1f, 0x2f, 0x3f, 0x4f, 0x5f, 0x6f, 0x7f,
	0x8f, 0x9f, 0xaf, 0xbf, 0xcf, 0xdf, 0xef, 0xff,
}

var distillPos = func() (t [9][256]int8) {
	for l := range t {
		for c := range t[l] {
			t[l][c] = -1
		}
	}
	for i := range distillLen {
		t[distillLen[i]][distillCode[i]] = int8(i)
	}
	return
}()

// undistill decodes PAK's method 11: LZSS over an 8 KB window with a
// Huffman tree for literals and lengths (sent as a node list) and a fixed
// code for the top bits of the position, whose low-bit count grows with
// the output position.
func undistill(src io.ByteReader, o *output) error {
	b := &lsb{r: src}
	n := b.bits(16)
	width := uint(b.bits(8))
	if n < 2 || n > 0x274 || width > 16 {
		return errCorrupt
	}
	nodes := make([]int, n)
	for i := range nodes {
		nodes[i] = b.bits(width)
	}
	for !o.full() {
		if b.overrun() {
			return io.ErrUnexpectedEOF
		}
		node, sym := n-2, -1
		for depth := 0; depth < 64; depth++ {
			if node < 0 || node+1 >= n {
				return errCorrupt
			}
			next := nodes[node+b.bit()]
			if next >= n {
				sym = next - n
				break
			}
			node = next
		}
		switch {
		case sym < 0:
			return errCorrupt
		case sym < 256:
			o.raw(byte(sym))
			continue
		case sym == 256:
			return nil
		}
		length := sym - 0x101 + 3
		ps := -1
		for l, v := uint(1), 0; l <= 8; l++ {
			v |= b.bit() << (l - 1)
			if l >= 3 && distillPos[l][v] >= 0 {
				ps = int(distillPos[l][v])
				break
			}
		}
		if ps < 0 {
			return errCorrupt
		}
		pos := len(o.buf)
		extra := uint(0)
		switch {
		case pos >= 0x1000-0x3c:
			extra = 7
		case pos >= 0x800-0x3c:
			extra = 6
		case pos >= 0x400-0x3c:
			extra = 5
		case pos >= 0x200-0x3c:
			extra = 4
		case pos >= 0x100-0x3c:
			extra = 3
		case pos >= 0x80-0x3c:
			extra = 2
		case pos >= 0x40-0x3c:
			extra = 1
		}
		off := ps<<extra + b.bits(extra) + 1
		from := pos - off
		for k := 0; k < length && !o.full(); k++ {
			if from+k < 0 {
				o.raw(' ') // the window starts filled with spaces
			} else {
				o.raw(o.buf[from+k])
			}
		}
	}
	return nil
}
