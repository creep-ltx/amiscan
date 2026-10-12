package lha

// -lh1- is LHarc's method: Okumura's LZHUF with a 4 KB window, an adaptive
// Huffman code for literals and match lengths, and a fixed code for the top
// six bits of the match position.

const (
	lh1Chars   = 314            // 256 literals + match lengths 3..60
	lh1Tree    = lh1Chars*2 - 1 // nodes in the tree
	lh1Root    = lh1Tree - 1    // index of the root node
	lh1MaxFreq = uint32(0x8000) // rebuild the tree when the root reaches this
)

type dynHuffman struct {
	freq [lh1Tree + 1]uint32
	prnt [lh1Tree + lh1Chars]int // parents; leaves are at lh1Tree+symbol
	son  [lh1Tree]int
}

func newDynHuffman() *dynHuffman {
	d := &dynHuffman{}
	for i := 0; i < lh1Chars; i++ {
		d.freq[i] = 1
		d.son[i] = i + lh1Tree
		d.prnt[i+lh1Tree] = i
	}
	for i, j := 0, lh1Chars; j <= lh1Root; i, j = i+2, j+1 {
		d.freq[j] = d.freq[i] + d.freq[i+1]
		d.son[j] = i
		d.prnt[i] = j
		d.prnt[i+1] = j
	}
	d.freq[lh1Tree] = 0xffff // sentinel
	d.prnt[lh1Root] = 0
	return d
}

func (d *dynHuffman) decode(b *bitReader) int {
	c := d.son[lh1Root]
	for c < lh1Tree {
		c += b.bit()
		c = d.son[c]
	}
	c -= lh1Tree
	d.update(c)
	return c
}

// reconst halves all frequencies and rebuilds the tree.
func (d *dynHuffman) reconst() {
	j := 0
	for i := 0; i < lh1Tree; i++ {
		if d.son[i] >= lh1Tree {
			d.freq[j] = (d.freq[i] + 1) / 2
			d.son[j] = d.son[i]
			j++
		}
	}
	for i, j := 0, lh1Chars; j < lh1Tree; i, j = i+2, j+1 {
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
		d.son[k] = i
	}
	for i := 0; i < lh1Tree; i++ {
		k := d.son[i]
		d.prnt[k] = i
		if k < lh1Tree {
			d.prnt[k+1] = i
		}
	}
}

// update counts one more use of symbol c and keeps the tree ordered.
func (d *dynHuffman) update(c int) {
	if d.freq[lh1Root] == lh1MaxFreq {
		d.reconst()
	}
	c = d.prnt[c+lh1Tree]
	for {
		d.freq[c]++
		k := d.freq[c]
		l := c + 1
		if k > d.freq[l] {
			l++
			for k > d.freq[l] {
				l++
			}
			l--
			d.freq[c] = d.freq[l]
			d.freq[l] = k

			i := d.son[c]
			d.prnt[i] = l
			if i < lh1Tree {
				d.prnt[i+1] = l
			}
			j := d.son[l]
			d.son[l] = i
			d.prnt[j] = c
			if j < lh1Tree {
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

// lh1Position is the fixed code for the top six bits of a position: one code
// of 3 bits, three of 4, eight of 5, twelve of 6, twenty-four of 7, sixteen of 8.
var lh1Position = func() *huffman {
	lens := make([]int, 64)
	for i := range lens {
		switch {
		case i < 1:
			lens[i] = 3
		case i < 4:
			lens[i] = 4
		case i < 12:
			lens[i] = 5
		case i < 24:
			lens[i] = 6
		case i < 48:
			lens[i] = 7
		default:
			lens[i] = 8
		}
	}
	h, _ := newHuffman(lens)
	return h
}()

func decodeLH1(packed []byte, want int64) ([]byte, error) {
	br := &bitReader{data: packed}
	d := newDynHuffman()
	w := newWindow(12, want)
	for !w.done() {
		if br.overrun() {
			return w.out, errCorrupt
		}
		c := d.decode(br)
		if c < 256 {
			w.put(byte(c))
			continue
		}
		hi, err := lh1Position.decode(br)
		if err != nil {
			return w.out, err
		}
		p := hi<<6 | br.bits(6)
		w.copyMatch(p, c-253)
	}
	return w.out, nil
}
