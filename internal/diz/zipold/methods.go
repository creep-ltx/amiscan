package zipold

// Shrink (method 1): LZW with codes of 9 to 13 bits. Code 256 escapes:
// 256,1 makes codes one bit longer, 256,2 frees every leaf of the string
// tree (a partial clear); freed codes are reused lowest first.
func newUnshrink(in *bits, out *reader) func() error {
	const (
		maxCode = 1 << 13
		free    = -1
		root    = 256 // the parent of a single byte
	)
	parent := make([]int16, maxCode)
	value := make([]byte, maxCode)
	for i := range parent {
		parent[i] = free
	}
	for i := 0; i < 256; i++ {
		parent[i] = root
		value[i] = byte(i)
	}
	stack := make([]byte, 0, maxCode)
	size := uint(9)
	old, last, lastFree, maxUsed := -1, byte(0), 256, 256
	return func() error {
		code := in.get(size)
		if code == 256 {
			switch in.get(size) {
			case 1:
				if size++; size > 13 {
					return ErrCorrupt
				}
			case 2:
				// partial clear: free every code that is no one's parent
				has := make([]bool, maxCode)
				for c := 257; c <= maxUsed; c++ {
					if p := int(parent[c]); p > 256 {
						has[p] = true
					}
				}
				for c := 257; c <= maxUsed; c++ {
					if !has[c] {
						parent[c] = free
					}
				}
				lastFree = 256
			}
			return nil
		}
		if old < 0 {
			if code > 255 {
				return ErrCorrupt
			}
			old, last = code, byte(code)
			out.put(last)
			return nil
		}
		stack = stack[:0]
		cur := code
		if parent[code] == free {
			// KwKwK: the code being defined now
			stack = append(stack, last)
			code = old
		}
		for code != root {
			if len(stack) >= maxCode || code < 0 || parent[code] == free {
				return ErrCorrupt
			}
			stack = append(stack, value[code])
			code = int(parent[code])
		}
		last = stack[len(stack)-1]
		for i := len(stack) - 1; i >= 0; i-- {
			out.put(stack[i])
		}
		c := lastFree + 1
		for c < maxCode && parent[c] != free {
			c++
		}
		if c >= maxCode {
			return ErrCorrupt
		}
		lastFree = c
		maxUsed = max(maxUsed, c)
		value[c] = last
		parent[c] = int16(old)
		old = cur
		return nil
	}
}

// Reduce (methods 2 to 5, factor 1 to 4): bytes come from per-byte
// follower sets, then go through a run-length/copy state machine.
func newUnreduce(in *bits, out *reader, factor int) (func() error, error) {
	var sets [256][]byte
	for x := 255; x >= 0; x-- {
		n := in.get(6)
		if n > 32 {
			return nil, ErrCorrupt
		}
		sets[x] = make([]byte, n)
		for i := range sets[x] {
			sets[x][i] = byte(in.byte())
		}
	}
	bitsFor := func(n int) uint {
		b := uint(1)
		for 1<<b < n {
			b++
		}
		return b
	}
	mask := 0xff >> factor
	var lastChar byte
	state, v, length := 0, 0, 0
	return func() error {
		var c byte
		if s := sets[lastChar]; len(s) == 0 {
			c = byte(in.byte())
		} else if in.get(1) == 1 {
			c = byte(in.byte())
		} else {
			i := in.get(bitsFor(len(s)))
			if i >= len(s) {
				return ErrCorrupt
			}
			c = s[i]
		}
		lastChar = c
		switch state {
		case 0:
			if c != 0x90 {
				out.put(c)
			} else {
				state = 1
			}
		case 1:
			if c == 0 {
				out.put(0x90)
				state = 0
			} else {
				v = int(c)
				length = v & mask
				if length == mask {
					state = 2
				} else {
					state = 3
				}
			}
		case 2:
			length += int(c)
			state = 3
		case 3:
			dist := (v>>(8-factor))*256 + int(c) + 1
			out.copyMatch(dist, length+3)
			state = 0
		}
		return nil
	}, nil
}

// sfCode is a Shannon-Fano code as implode stores it.
type sfCode struct {
	byLen [17]map[int]int // code (read first bit first) -> symbol, per length
}

// readSF reads a code of n symbols: a count byte, then bytes of (repeats-1,
// length-1) nibbles. Codes are assigned from the longest length down, as
// in the APPNOTE (the longest, highest symbol is all zeros).
func readSF(in *bits, n int) (*sfCode, error) {
	groups := in.byte() + 1
	lens := make([]int, 0, n)
	for i := 0; i < groups; i++ {
		v := in.byte()
		for k := 0; k <= v>>4; k++ {
			lens = append(lens, v&15+1)
		}
		if len(lens) > n {
			return nil, ErrCorrupt
		}
	}
	if len(lens) != n {
		return nil, ErrCorrupt
	}
	// symbols in ascending length, then ascending symbol
	order := make([]int, 0, n)
	for l := 1; l <= 16; l++ {
		for s, sl := range lens {
			if sl == l {
				order = append(order, s)
			}
		}
	}
	c := &sfCode{}
	code, inc, lastLen := 0, 0, 0
	for i := n - 1; i >= 0; i-- {
		s := order[i]
		code += inc
		if lens[s] != lastLen {
			lastLen = lens[s]
			inc = 1 << (16 - lastLen)
		}
		if code >= 1<<16 {
			return nil, ErrCorrupt
		}
		if c.byLen[lastLen] == nil {
			c.byLen[lastLen] = map[int]int{}
		}
		c.byLen[lastLen][code>>(16-lastLen)] = s
	}
	return c, nil
}

func (c *sfCode) decode(in *bits) (int, error) {
	v := 0
	for l := 1; l <= 16; l++ {
		v = v<<1 | in.get(1)
		if s, ok := c.byLen[l][v]; ok {
			return s, nil
		}
	}
	return 0, ErrCorrupt
}

// Implode (method 6): literals (coded or plain bytes) and copies whose
// length and distance top bits are Shannon-Fano coded. Flag bit 1: an 8 KB
// window (7 low distance bits, else 4 KB and 6); bit 2: literals are coded
// and the shortest copy is 3 bytes (else plain and 2).
func newExplode(in *bits, out *reader, bigWindow, codedLiterals bool) (func() error, error) {
	var lit *sfCode
	var err error
	if codedLiterals {
		if lit, err = readSF(in, 256); err != nil {
			return nil, err
		}
	}
	lenCode, err := readSF(in, 64)
	if err != nil {
		return nil, err
	}
	distCode, err := readSF(in, 64)
	if err != nil {
		return nil, err
	}
	lowBits := uint(6)
	if bigWindow {
		lowBits = 7
	}
	minMatch := 2
	if codedLiterals {
		minMatch = 3
	}
	return func() error {
		if in.get(1) == 1 {
			if lit == nil {
				out.put(byte(in.byte()))
				return nil
			}
			c, err := lit.decode(in)
			if err != nil {
				return err
			}
			out.put(byte(c))
			return nil
		}
		low := in.get(lowBits)
		high, err := distCode.decode(in)
		if err != nil {
			return err
		}
		length, err := lenCode.decode(in)
		if err != nil {
			return err
		}
		if length == 63 {
			length += in.byte()
		}
		out.copyMatch((high<<lowBits|low)+1, length+minMatch)
		return nil
	}, nil
}
