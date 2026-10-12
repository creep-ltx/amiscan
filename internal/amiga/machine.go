// Package amiga is just enough of AmigaOS to run a well-behaved shared
// library (xvs.library and friends) on Linux: a 68000, RAM, an allocator,
// exec lists, LoadSeg, InitResident and a handful of exec and dos calls.
//
// Guest code reaches Go through jump table entries of the form
//
//	ILLEGAL ($4AFC) ; dc.w trap ; RTS
//
// where trap = library index << 10 | LVO/6.
package amiga

import (
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/creep-ltx/amiscan/internal/m68k"
)

// Memory map.
const (
	RAMSize     = 0xbe0000 // below the CIA and custom chip ranges
	vectorStubs = 0x400    // 256 x (ILLEGAL, trap) = 1 KiB
	stopStub    = 0x800    // a guest call returns here
	heapStart   = 0x1000
	stackSize   = 0x10000
	superStack  = RAMSize - stackSize // supervisor stack top
	userStack   = superStack - 0x100  // user stack top
	heapEnd     = RAMSize - 2*stackSize
)

const (
	trapStop      = 0xffff
	trapException = 0xf000 // + vector number
)

// Node types.
const (
	NTTask      = 1
	NTDevice    = 3
	NTMemory    = 10
	NTLibrary   = 9
	NTProcess   = 13
	NTSignalSem = 15
)

// Machine is the emulated Amiga.
type Machine struct {
	CPU     *m68k.CPU
	SysBase uint32
	// LibsDir is where LIBS: points (the folder with xvs.library).
	LibsDir string
	// Log receives warnings (unimplemented calls, crashes). Trace, when
	// set, receives every OS call.
	Log   io.Writer
	Trace bool

	heap    allocator
	libs    []*fakeLib // index = trap library number
	task    uint32
	files   files
	stopped bool
}

// New sets up the machine. Only one Machine may exist per process.
func New(libsDir string) *Machine {
	m := &Machine{LibsDir: libsDir, Log: os.Stderr}
	m.CPU = m68k.New(RAMSize, m68k.CPU68000, m.trap)
	m.heap.init(heapStart, heapEnd)
	m.files.init()
	c := m.CPU
	for v := uint32(0); v < 256; v++ {
		stub := vectorStubs + v*4
		c.Write16(stub, 0x4afc)
		c.Write16(stub+2, uint16(trapException+v))
		c.Write32(v*4, stub)
	}
	c.Write16(stopStub, 0x4afc)
	c.Write16(stopStub+2, trapStop)
	m.libs = append(m.libs, nil) // index 0 unused
	m.setupExec()
	m.setupDos()
	return m
}

func (m *Machine) warnf(format string, args ...any) {
	if m.Log != nil {
		fmt.Fprintf(m.Log, "amiga: "+format+"\n", args...)
	}
}

// ErrCrash is returned when guest code takes an exception.
type ErrCrash struct {
	Vector uint32
	PC     uint32
	Detail string
}

func (e *ErrCrash) Error() string {
	return fmt.Sprintf("68k exception %d (%s) at $%06x", e.Vector, vectorName(e.Vector), e.PC)
}

func vectorName(v uint32) string {
	switch v {
	case 2:
		return "bus error"
	case 3:
		return "address error"
	case 4:
		return "illegal instruction"
	case 5:
		return "division by zero"
	case 8:
		return "privilege violation"
	case 10:
		return "line A"
	case 11:
		return "line F"
	}
	if v >= 32 && v < 48 {
		return fmt.Sprintf("TRAP #%d", v-32)
	}
	return "exception"
}

func (m *Machine) trap(pc uint32, id uint16) bool {
	c := m.CPU
	switch {
	case id == trapStop:
		c.Stop()
		return true
	case id >= trapException && id < trapException+256:
		v := uint32(id - trapException)
		// the stacked PC of the faulting instruction (format 0 frame: SR, PC)
		sp := c.SP()
		e := &ErrCrash{Vector: v, PC: c.Read32(sp + 2)}
		c.Fail(e)
		return true
	}
	lib, lvo := int(id>>10), int(id&0x3ff)*6
	if lib <= 0 || lib >= len(m.libs) || m.libs[lib] == nil {
		return false
	}
	f := m.libs[lib]
	name := fdNames[f.name][lvo]
	if name == "" {
		name = fmt.Sprintf("LVO-%d", lvo)
	}
	if m.Trace {
		m.warnf("%s %s(d0=%08x d1=%08x d2=%08x a0=%08x a1=%08x) from $%06x",
			f.name, name, c.D(0), c.D(1), c.D(2), c.A(0), c.A(1), c.Read32(c.SP()))
	}
	if fn := f.funcs[name]; fn != nil {
		fn()
	} else {
		m.warnf("%s %s not emulated, returning 0", f.name, name)
		c.SetD(0, 0)
	}
	return true
}

// Call runs the guest function at addr with the given registers set
// (keys "d0".."d7", "a0".."a6") and returns D0. Calls do not nest.
func (m *Machine) Call(addr uint32, regs map[string]uint32, maxCycles int64) (uint32, error) {
	c := m.CPU
	// Musashi's SR write does not swap stack pointers: go to user mode
	// first, then the supervisor stack lands in its own slot.
	c.SetSR(0x0000) // user mode, like any Amiga program
	c.SetISP(superStack)
	for k, v := range regs {
		n := int(k[1] - '0')
		if k[0] == 'd' {
			c.SetD(n, v)
		} else {
			c.SetA(n, v)
		}
	}
	c.SetSP(userStack - 4)
	c.Write32(userStack-4, stopStub)
	c.SetPC(addr)
	if err := c.Run(maxCycles); err != nil {
		return 0, err
	}
	return c.D(0), nil
}

// ---- memory helpers

func (m *Machine) r8(a uint32) uint8      { return m.CPU.Read8(a) }
func (m *Machine) r16(a uint32) uint16    { return m.CPU.Read16(a) }
func (m *Machine) r32(a uint32) uint32    { return m.CPU.Read32(a) }
func (m *Machine) w8(a uint32, v uint8)   { m.CPU.Write8(a, v) }
func (m *Machine) w16(a uint32, v uint16) { m.CPU.Write16(a, v) }
func (m *Machine) w32(a uint32, v uint32) { m.CPU.Write32(a, v) }

// CString reads a NUL-terminated string from guest memory.
func (m *Machine) CString(a uint32) string {
	if a == 0 {
		return ""
	}
	var b strings.Builder
	for i := uint32(0); i < 4096; i++ {
		ch := m.r8(a + i)
		if ch == 0 {
			break
		}
		b.WriteByte(ch)
	}
	return b.String()
}

// PutString stores s with a NUL in newly allocated guest memory.
func (m *Machine) PutString(s string) uint32 {
	a := m.Alloc(uint32(len(s)+1), true)
	copy(m.CPU.RAM[a:], s)
	return a
}

// Alloc returns zeroed (if clear) guest memory, 0 when out of memory.
func (m *Machine) Alloc(size uint32, clear bool) uint32 {
	a := m.heap.alloc(size)
	if a != 0 && clear {
		ramClear(m.CPU.RAM[a : a+size])
	}
	return a
}

// Free returns memory from Alloc.
func (m *Machine) Free(a uint32) { m.heap.free(a) }

// Copy puts host bytes into newly allocated guest memory.
func (m *Machine) Copy(b []byte) uint32 {
	a := m.Alloc(uint32(max(len(b), 4)), false)
	if a != 0 {
		copy(m.CPU.RAM[a:], b)
	}
	return a
}

func ramClear(b []byte) { clear(b) }

// ---- allocator: first fit over a sorted free list, 8-byte granules

type span struct{ addr, size uint32 }

type allocator struct {
	spans []span
	used  map[uint32]uint32
}

func (h *allocator) init(lo, hi uint32) {
	h.spans = []span{{lo, hi - lo}}
	h.used = map[uint32]uint32{}
}

func (h *allocator) alloc(size uint32) uint32 {
	size = (max(size, 1) + 7) &^ 7
	for i, s := range h.spans {
		if s.size >= size {
			a := s.addr
			if s.size == size {
				h.spans = append(h.spans[:i], h.spans[i+1:]...)
			} else {
				h.spans[i] = span{s.addr + size, s.size - size}
			}
			h.used[a] = size
			return a
		}
	}
	return 0
}

func (h *allocator) free(a uint32) {
	size, ok := h.used[a]
	if !ok {
		return
	}
	delete(h.used, a)
	i := sort.Search(len(h.spans), func(i int) bool { return h.spans[i].addr > a })
	h.spans = append(h.spans, span{})
	copy(h.spans[i+1:], h.spans[i:])
	h.spans[i] = span{a, size}
	// merge with the next and the previous span
	if i+1 < len(h.spans) && h.spans[i].addr+h.spans[i].size == h.spans[i+1].addr {
		h.spans[i].size += h.spans[i+1].size
		h.spans = append(h.spans[:i+1], h.spans[i+2:]...)
	}
	if i > 0 && h.spans[i-1].addr+h.spans[i-1].size == h.spans[i].addr {
		h.spans[i-1].size += h.spans[i].size
		h.spans = append(h.spans[:i], h.spans[i+1:]...)
	}
}

func (h *allocator) available() (total, largest uint32) {
	for _, s := range h.spans {
		total += s.size
		largest = max(largest, s.size)
	}
	return
}

// Read8, Read16, Read32 and Write32 give packages outside access to guest memory.
func (m *Machine) Read8(a uint32) uint8       { return m.r8(a) }
func (m *Machine) Read16(a uint32) uint16     { return m.r16(a) }
func (m *Machine) Read32(a uint32) uint32     { return m.r32(a) }
func (m *Machine) Write32(a uint32, v uint32) { m.w32(a, v) }

// Bytes returns n bytes of guest memory at a (a view, not a copy).
func (m *Machine) Bytes(a, n uint32) []byte {
	if uint64(a)+uint64(n) > RAMSize {
		return nil
	}
	return m.CPU.RAM[a : a+n]
}

// Latin1String reads a NUL-terminated ISO-8859-1 string (the Amiga's
// character set) and returns it as UTF-8.
func (m *Machine) Latin1String(a uint32) string {
	raw := m.CString(a)
	r := make([]rune, len(raw))
	for i := 0; i < len(raw); i++ {
		r[i] = rune(raw[i])
	}
	return string(r)
}
