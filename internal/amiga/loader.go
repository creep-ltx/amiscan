package amiga

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
)

// Hunk types.
const (
	hunkUnit         = 0x3e7
	hunkName         = 0x3e8
	hunkCode         = 0x3e9
	hunkData         = 0x3ea
	hunkBSS          = 0x3eb
	hunkReloc32      = 0x3ec
	hunkSymbol       = 0x3f0
	hunkDebug        = 0x3f1
	hunkEnd          = 0x3f2
	hunkHeader       = 0x3f3
	hunkDRel32       = 0x3f7
	hunkReloc32Short = 0x3fc
)

// LoadSeg loads an Amiga executable into guest memory and returns its
// segment list (a BPTR) and the address of each hunk's data.
func (m *Machine) LoadSeg(data []byte) (seglist uint32, hunks []uint32, err error) {
	pos := 0
	long := func() (uint32, error) {
		if pos+4 > len(data) {
			return 0, errors.New("truncated hunk file")
		}
		v := binary.BigEndian.Uint32(data[pos:])
		pos += 4
		return v, nil
	}
	if v, err := long(); err != nil || v != hunkHeader {
		return 0, nil, errors.New("not an Amiga executable")
	}
	for { // resident library names (unused)
		n, err := long()
		if err != nil {
			return 0, nil, err
		}
		if n == 0 {
			break
		}
		pos += int(n) * 4
	}
	_, _ = long() // table size
	first, err := long()
	if err != nil {
		return 0, nil, err
	}
	last, err := long()
	if err != nil || last < first || last-first > 1000 {
		return 0, nil, errors.New("bad hunk header")
	}
	count := int(last - first + 1)
	sizes := make([]uint32, count)
	for i := range sizes {
		v, err := long()
		if err != nil {
			return 0, nil, err
		}
		if v>>30 == 3 {
			pos += 4 // extended memory flags
		}
		sizes[i] = (v & 0x3fffffff) * 4
	}
	// allocate: [size][next BPTR][data]
	hunks = make([]uint32, count)
	var prev uint32
	for i, sz := range sizes {
		blk := m.Alloc(sz+8, true)
		if blk == 0 {
			return 0, nil, errors.New("out of guest memory")
		}
		m.w32(blk, sz+8)
		hunks[i] = blk + 8
		if i == 0 {
			seglist = (blk + 4) >> 2
		} else {
			m.w32(prev, (blk+4)>>2)
		}
		prev = blk + 4
	}
	cur := -1
	for pos < len(data) {
		typ, _ := long()
		switch typ & 0x3fffffff {
		case hunkCode, hunkData:
			cur++
			n, err := long()
			if err != nil || cur >= count {
				return 0, nil, errors.New("bad code/data hunk")
			}
			n *= 4
			if pos+int(n) > len(data) || n > sizes[cur] {
				return 0, nil, errors.New("hunk larger than declared")
			}
			copy(m.CPU.RAM[hunks[cur]:], data[pos:pos+int(n)])
			pos += int(n)
		case hunkBSS:
			cur++
			pos += 4
		case hunkReloc32:
			for {
				n, err := long()
				if err != nil {
					return 0, nil, err
				}
				if n == 0 {
					break
				}
				target, _ := long()
				if int(target) >= count || cur < 0 {
					return 0, nil, errors.New("bad relocation")
				}
				for ; n > 0; n-- {
					off, err := long()
					if err != nil {
						return 0, nil, err
					}
					a := hunks[cur] + off
					m.w32(a, m.r32(a)+hunks[target])
				}
			}
		case hunkReloc32Short, hunkDRel32:
			word := func() uint32 {
				if pos+2 > len(data) {
					pos = len(data)
					return 0
				}
				v := binary.BigEndian.Uint16(data[pos:])
				pos += 2
				return uint32(v)
			}
			start := pos
			for {
				n := word()
				if n == 0 {
					break
				}
				target := word()
				if int(target) >= count || cur < 0 {
					return 0, nil, errors.New("bad relocation")
				}
				for ; n > 0; n-- {
					a := hunks[cur] + word()
					m.w32(a, m.r32(a)+hunks[target])
				}
			}
			if (pos-start)%4 != 0 {
				pos += 2
			}
		case hunkSymbol:
			for {
				n, err := long()
				if err != nil || n == 0 {
					break
				}
				pos += int(n&0xffffff)*4 + 4
			}
		case hunkDebug, hunkName, hunkUnit:
			n, _ := long()
			pos += int(n) * 4
		case hunkEnd:
		default:
			return 0, nil, fmt.Errorf("unsupported hunk type $%x", typ)
		}
	}
	return seglist, hunks, nil
}

// findRomTag looks for a Resident structure in the loaded hunks.
func (m *Machine) findRomTag(hunks []uint32) uint32 {
	for _, h := range hunks {
		size := m.r32(h-8) - 8
		for a := h; a+SizeofResident <= h+size; a += 2 {
			if m.r16(a) == 0x4afc && m.r32(a+2) == a {
				return a
			}
		}
	}
	return 0
}

// LoadLibrary loads a library file, initialises it and adds it to the
// system, as exec's RAMLIB would. It returns the library base (not opened).
func (m *Machine) LoadLibrary(path string) (uint32, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	seg, hunks, err := m.LoadSeg(data)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", path, err)
	}
	rt := m.findRomTag(hunks)
	if rt == 0 {
		return 0, fmt.Errorf("%s: no RomTag, not a library", path)
	}
	init := m.r32(rt + Resident_rt_Init)
	if m.r8(rt+Resident_rt_Flags)&0x80 == 0 { // not RTF_AUTOINIT
		base, err := m.Call(init, map[string]uint32{"d0": 0, "a0": seg, "a6": m.SysBase}, 500_000_000)
		if err != nil {
			return 0, fmt.Errorf("%s: init: %w", path, err)
		}
		if base == 0 {
			return 0, fmt.Errorf("%s: library refused to start", path)
		}
		return base, nil
	}
	dataSize, vectors, structure, initFn := m.r32(init), m.r32(init+4), m.r32(init+8), m.r32(init+12)
	base := m.makeLibrary(vectors, structure, dataSize)
	if base == 0 {
		return 0, fmt.Errorf("%s: MakeLibrary failed", path)
	}
	if initFn != 0 {
		base, err = m.Call(initFn, map[string]uint32{"d0": base, "a0": seg, "a6": m.SysBase}, 500_000_000)
		if err != nil {
			return 0, fmt.Errorf("%s: init: %w", path, err)
		}
		if base == 0 {
			return 0, fmt.Errorf("%s: library refused to start", path)
		}
	}
	m.Enqueue(m.SysBase+ExecBase_LibList, base)
	return base, nil
}

// OpenLibrary calls a loaded library's Open vector.
func (m *Machine) OpenLibrary(base, version uint32) (uint32, error) {
	if uint32(m.r16(base+Library_lib_Version)) < version {
		return 0, fmt.Errorf("version %d.%d is older than %d", m.r16(base+Library_lib_Version), m.r16(base+Library_lib_Revision), version)
	}
	return m.Call(base-6, map[string]uint32{"d0": version, "a6": base}, 500_000_000)
}

func (m *Machine) makeFunctions(target, vectors, base uint32) uint32 {
	n := uint32(0)
	put := func(fn uint32) {
		n++
		e := target - n*6
		m.w16(e, 0x4ef9) // JMP abs.l
		m.w32(e+2, fn)
	}
	if base != 0 || m.r16(vectors) == 0xffff {
		// relative words
		p := vectors
		if base == 0 {
			base, p = vectors, vectors+2
		}
		for ; m.r16(p) != 0xffff; p += 2 {
			put(base + uint32(int32(int16(m.r16(p)))))
		}
	} else {
		for p := vectors; m.r32(p) != 0xffffffff; p += 4 {
			put(m.r32(p))
		}
	}
	return n * 6
}

func (m *Machine) countVectors(vectors uint32) uint32 {
	n := uint32(0)
	if m.r16(vectors) == 0xffff {
		for p := vectors + 2; m.r16(p) != 0xffff; p += 2 {
			n++
		}
	} else {
		for p := vectors; m.r32(p) != 0xffffffff; p += 4 {
			n++
		}
	}
	return n
}

func (m *Machine) makeLibrary(vectors, structure, dataSize uint32) uint32 {
	neg := (m.countVectors(vectors)*6 + 3) &^ 3
	mem := m.Alloc(neg+dataSize, true)
	if mem == 0 {
		return 0
	}
	base := mem + neg
	m.makeFunctions(base, vectors, 0)
	m.w16(base+Library_lib_NegSize, uint16(neg))
	m.w16(base+Library_lib_PosSize, uint16(dataSize))
	if structure != 0 {
		m.initStruct(structure, base, 0)
	}
	return base
}

// initStruct is exec's InitStruct.
func (m *Machine) initStruct(table, mem, size uint32) {
	if size != 0 {
		ramClear(m.CPU.RAM[mem : mem+size])
	}
	p, dst := table, mem
	align := func() { p = (p + 1) &^ 1 }
	for {
		cmd := m.r8(p)
		if cmd == 0 {
			return
		}
		p++
		kind, sz, cnt := cmd>>6, (cmd>>4)&3, uint32(cmd&15)+1
		switch kind {
		case 2:
			dst = mem + uint32(m.r8(p))
			p++
		case 3:
			dst = mem + (uint32(m.r8(p))<<16 | uint32(m.r16(p+1)))
			p += 3
		}
		width := [4]uint32{4, 2, 1, 0}[sz]
		if width == 0 {
			m.warnf("InitStruct: bad size in $%02x", cmd)
			return
		}
		if width > 1 {
			align()
		}
		for i := uint32(0); i < cnt; i++ {
			switch width {
			case 4:
				m.w32(dst, m.r32(p))
			case 2:
				m.w16(dst, m.r16(p))
			case 1:
				m.w8(dst, m.r8(p))
			}
			dst += width
			if kind != 1 || i == cnt-1 { // kind 1 repeats one source value
				if kind != 1 {
					p += width
				}
			}
		}
		if kind == 1 {
			p += width
		}
		align()
	}
}
