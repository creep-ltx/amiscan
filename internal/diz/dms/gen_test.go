package dms

import (
	"math/rand"
	"os"
	"sort"
	"testing"
)

// The DMS files on hand were all packed in HEAVY2. To test the other modes
// against xDMS, genModes writes tracks in every mode whose packed data is
// random (QUICK, MEDIUM and DEEP accept any bits) or random after valid code
// tables (HEAVY), computing lengths, sums and CRCs with this package's own
// decoder. xDMS must then unpack the file to the same bytes (testdata/disk/
// modes.dms, checked in TestModes). Run with BBX_DMS_GEN=file to rewrite it.

type bitWriter struct {
	out []byte
	acc uint32
	n   uint
}

func (w *bitWriter) put(v uint32, n uint) {
	for i := int(n) - 1; i >= 0; i-- {
		w.acc = w.acc<<1 | (v>>uint(i))&1
		w.n++
		if w.n == 8 {
			w.out = append(w.out, byte(w.acc))
			w.acc, w.n = 0, 0
		}
	}
}

func (w *bitWriter) bytes() []byte {
	if w.n > 0 {
		w.out = append(w.out, byte(w.acc<<(8-w.n)))
		w.acc, w.n = 0, 0
	}
	return w.out
}

// huffLens gives a complete prefix code's lengths for random weights,
// none longer than maxLen.
func huffLens(rng *rand.Rand, n, maxLen int) []byte {
	for {
		type node struct {
			w    int
			syms []int
		}
		var ns []node
		for i := 0; i < n; i++ {
			ns = append(ns, node{rng.Intn(1000) + 1, []int{i}})
		}
		lens := make([]byte, n)
		for len(ns) > 1 {
			sort.Slice(ns, func(i, j int) bool { return ns[i].w < ns[j].w })
			a, b := ns[0], ns[1]
			for _, s := range append(append([]int{}, a.syms...), b.syms...) {
				lens[s]++
			}
			ns = append([]node{{a.w + b.w, append(append([]int{}, a.syms...), b.syms...)}}, ns[2:]...)
		}
		ok := true
		for _, l := range lens {
			if int(l) > maxLen {
				ok = false
			}
		}
		if ok {
			return lens
		}
	}
}

// rleCount is how many bytes the RLE stage makes from all of in; ok is
// false when a run is cut or the result is too big.
func rleCount(in []byte) (int, bool) {
	n := 0
	for i := 0; i < len(in); {
		if in[i] != 0x90 {
			n++
			i++
			continue
		}
		if i+1 >= len(in) {
			return 0, false
		}
		if in[i+1] == 0 {
			n++
			i += 2
			continue
		}
		if in[i+1] == 0xff {
			if i+4 >= len(in) {
				return 0, false
			}
			n += int(in[i+3])<<8 | int(in[i+4])
			i += 5
		} else {
			if i+2 >= len(in) {
				return 0, false
			}
			n += int(in[i+1])
			i += 3
		}
	}
	return n, n > 2048 && n <= bufLen
}

type genTrack struct {
	mode, flags byte
	pk2         int
	heavyTables int // 0 none, 1 Huffman tables, 2 one-symbol tables
}

func genModes(seed int64) []byte {
	rng := rand.New(rand.NewSource(seed))
	tracks := []genTrack{
		{0, 0, 0, 0}, {1, 0, 0, 0},
		{2, 1, 6000, 0}, {2, 0, 7000, 0}, {2, 0, 5000, 0},
		{3, 1, 6000, 0}, {3, 1, 9000, 0}, {3, 0, 5000, 0},
		{4, 1, 6000, 0}, {4, 1, 8000, 0}, {4, 0, 7000, 0}, {4, 0, 3000, 0},
		{5, 1 | 2 | 4, 9000, 1}, {5, 1 | 4, 6000, 0}, {5, 2, 11264, 1},
		{6, 1 | 2 | 4, 9000, 1}, {6, 1, 7000, 0}, {6, 2 | 4, 8000, 1},
		{6, 2, 11264, 2}, {6, 1 | 2, 11264, 1}, {6, 0, 5000, 0},
		{2, 1, 6000, 0}, {3, 1, 6000, 0}, {6, 2 | 4, 9000, 1}, {4, 0, 6000, 0},
	}
	var file []byte
	file = append(file, make([]byte, headLen)...)
	copy(file, "DMS!")
	file[53] = 6 // HEAVY2 "mostly"
	d := newDecoder()
	for num, gt := range tracks {
		for {
			snap := *d
			packed, pk2, unpk, out, ok := genTrack1(rng, d, gt)
			if !ok {
				*d = snap
				continue
			}
			h := make([]byte, trackLen)
			h[0], h[1] = 'T', 'R'
			h[3] = byte(num)
			put16(h[6:], len(packed))
			put16(h[8:], pk2)
			put16(h[10:], unpk)
			h[12] = gt.flags
			h[13] = gt.mode
			put16(h[14:], int(sum16(out)))
			put16(h[16:], int(crc16(packed)))
			put16(h[18:], int(crc16(h[:18])))
			file = append(append(file, h...), packed...)
			break
		}
	}
	put16(file[54:], int(crc16(file[4:54])))
	return file
}

func put16(b []byte, v int) { b[0], b[1] = byte(v>>8), byte(v) }

func genTrack1(rng *rand.Rand, d *decoder, gt genTrack) (packed []byte, pk2, unpk int, out []byte, ok bool) {
	random := func(n int) []byte {
		b := make([]byte, n)
		rng.Read(b)
		return b
	}
	switch gt.mode {
	case 0:
		packed = random(11264)
		out, err := d.track(packed, len(packed), len(packed), 0, gt.flags)
		return packed, len(packed), len(packed), out, err == nil
	case 1:
		packed = random(9000)
		n, ok := rleCount(packed)
		if !ok {
			return nil, 0, 0, nil, false
		}
		out, err := d.track(packed, len(packed), n, 1, gt.flags)
		return packed, len(packed), n, out, err == nil
	}
	in := random(bufLen)
	if gt.mode >= 5 {
		w := &bitWriter{}
		np := 14
		if gt.mode == 6 {
			np = 15
		}
		switch gt.heavyTables {
		case 1:
			w.put(heavyNC, 9)
			for _, l := range huffLens(rng, heavyNC, 16) {
				w.put(uint32(l), 5)
			}
			w.put(uint32(np), 5)
			for _, l := range huffLens(rng, np, 15) {
				w.put(uint32(l), 4)
			}
		case 2:
			w.put(0, 9)
			w.put(uint32(rng.Intn(256)), 9)
			w.put(0, 5)
			w.put(uint32(rng.Intn(np)), 5)
		}
		in = append(w.bytes(), in...)[:bufLen]
	}
	tmp := make([]byte, gt.pk2+slack)
	var err error
	b := &d.br
	switch gt.mode {
	case 2:
		err = d.quick(in, tmp, gt.pk2)
	case 3:
		err = d.medium(in, tmp, gt.pk2)
	case 4:
		err = d.deep(in, tmp, gt.pk2)
	case 5, 6:
		f := gt.flags & 7
		if gt.mode == 6 {
			f = gt.flags | 8
		}
		err = d.heavy(in, tmp, f, gt.pk2)
	}
	if err != nil || b.pos > bufLen {
		return nil, 0, 0, nil, false
	}
	packed = in[:b.pos]
	stage := tmp[:gt.pk2]
	if gt.mode >= 5 && gt.flags&4 == 0 {
		out = append([]byte(nil), stage...)
		unpk = gt.pk2
	} else {
		n, ok := rleCount(stage)
		if !ok {
			return nil, 0, 0, nil, false
		}
		if out, err = rle(tmp, n); err != nil {
			return nil, 0, 0, nil, false
		}
		unpk = n
	}
	if gt.flags&1 == 0 {
		d.reinit()
	}
	return packed, gt.pk2, unpk, out, true
}

func TestGenModes(t *testing.T) {
	path := os.Getenv("BBX_DMS_GEN")
	if path == "" {
		t.Skip("set BBX_DMS_GEN=file to write the generated DMS")
	}
	if err := os.WriteFile(path, genModes(1994), 0o644); err != nil {
		t.Fatal(err)
	}
}
