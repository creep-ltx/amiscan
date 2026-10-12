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
	"time"

	"github.com/creep-ltx/amiscan/internal/m68k"
)

// Memory map: "chip" RAM below the CIA and custom chip ranges, as on any
// Amiga, and fast RAM from 16 MB up, as on an accelerator card.
const (
	lowEnd      = 0xbe0000
	fastStart   = 0x01000000
	maxFastRAM  = 0x7f000000 // 2 GB
	vectorStubs = 0x400      // 256 x (ILLEGAL, trap) = 1 KiB
	stopStub    = 0x800      // a guest call returns here
	resumeStub  = 0x804      // a nested guest call returns here
	rtsStub     = 0x808      // RTS: ends an OS call that ran guest code
	heapStart   = 0x1000
	stackSize   = 0x10000
	superStack  = lowEnd - stackSize // supervisor stack top
	userStack   = superStack - 0x100 // user stack top
	heapEnd     = lowEnd - 2*stackSize
)

const (
	trapStop      = 0xffff
	trapResume    = 0xfffd
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

	heap  allocator
	libs  []*fakeLib      // index = trap library number
	fake  map[uint32]bool // bases of libraries made in Go
	conts []func(d0 uint32)

	uniqueID uint32

	// AllocLimit, when not 0, is the largest single AllocMem/AllocVec the
	// guest gets: a damaged packed file may ask for gigabytes.
	AllocLimit uint32
	task       uint32
	files      files
	stopped    bool
}

// New sets up the machine. Only one Machine may exist per process.
func New(libsDir string) *Machine {
	m := &Machine{LibsDir: libsDir, Log: os.Stderr}
	// A 68020 (on a 24-bit bus, like an A1200's): runs all 68000 code, and
	// some xfd decrunchers need 020 instructions.
	m.CPU = m68k.New(RAMSize, m68k.CPU68020, m.trap)
	m.heap.init(span{heapStart, heapEnd - heapStart}, span{fastStart, RAMSize - fastStart})
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
	c.Write16(resumeStub, 0x4afc)
	c.Write16(resumeStub+2, trapResume)
	c.Write16(rtsStub, 0x4e75)
	m.libs = append(m.libs, nil) // index 0 unused
	m.fake = map[uint32]bool{}
	m.setupExec()
	m.setupDos()
	// Amiga libraries look for these; every call to them returns 0.
	m.AddFakeDevice("trackdisk.device")
	in := m.AddFakeLibrary("intuition.library", 40)
	in.funcs["CurrentTime"] = func() {
		now := time.Now()
		secs := uint32(now.Unix() - time.Date(1978, 1, 1, 0, 0, 0, 0, time.UTC).Unix())
		m.w32(m.CPU.A(0), secs)
		m.w32(m.CPU.A(1), uint32(now.Nanosecond()/1000))
	}
	m.setupUtility()
	m.AddFakeLibrary("graphics.library", 40)
	// xpkmaster wants these for its password window, which never opens here
	m.AddFakeLibrary("gadtools.library", 40)
	m.AddFakeLibrary("asl.library", 40)
	m.AddFakeLibrary("locale.library", 40)
	return m
}

func (m *Machine) warnf(format string, args ...any) {
	if m.Log != nil {
		fmt.Fprintf(m.Log, "amiga: "+format+"\n", args...)
	}
}

// RAMSize is where guest memory ends. SetFastRAM changes it before New.
var RAMSize uint32 = fastStart + maxFastRAM

// SetFastRAM sets how much fast RAM the next Machine gets (64 MB to 2 GB).
// The host reserves it; on Windows it counts as committed memory.
func SetFastRAM(n uint64) {
	n = min(max(n, 64<<20), maxFastRAM)
	RAMSize = fastStart + uint32(n)
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

func (m *Machine) trap(pc uint32, id uint16) (handled bool) {
	c := m.CPU
	defer func() {
		// a bad pointer from the guest must not take AmiScan down
		if r := recover(); r != nil {
			c.Fail(fmt.Errorf("OS call from $%06x failed: %v", pc, r))
			handled = true
		}
	}()
	switch {
	case id == trapStop:
		c.Stop()
		return true
	case id == trapResume:
		if len(m.conts) == 0 {
			c.Fail(fmt.Errorf("stray return to the resume stub"))
			return true
		}
		k := m.conts[len(m.conts)-1]
		m.conts = m.conts[:len(m.conts)-1]
		k(c.D(0))
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
	m.conts = m.conts[:0]
	c.SetPC(addr)
	if err := c.Run(maxCycles); err != nil {
		return 0, err
	}
	return c.D(0), nil
}

// ---- guest code called from inside an OS call
//
// Musashi cannot be re-entered from a trap, so an OS call that must run
// guest code (a library's init and Open functions) does it in steps:
// guestCall points the CPU at the function with the resume stub as its
// return address, and when it returns the continuation runs; the last
// step calls osReturn, which ends the OS call as its RTS would.

type savedRegs struct{ d, a [8]uint32 }

func (m *Machine) saveRegs() savedRegs {
	var s savedRegs
	for i := 0; i < 8; i++ {
		s.d[i], s.a[i] = m.CPU.D(i), m.CPU.A(i)
	}
	return s
}

// guestCall runs fn with regs set; then calls then with its D0.
func (m *Machine) guestCall(fn uint32, regs map[string]uint32, then func(d0 uint32)) {
	c := m.CPU
	for k, v := range regs {
		n := int(k[1] - '0')
		if k[0] == 'd' {
			c.SetD(n, v)
		} else {
			c.SetA(n, v)
		}
	}
	sp := c.SP() - 4
	c.Write32(sp, resumeStub)
	c.SetSP(sp)
	m.conts = append(m.conts, then)
	c.SetPC(fn)
}

// osReturn finishes an OS call that ran guest code: the caller's registers
// back (the Amiga ABI lets an OS call change only D0, D1, A0 and A1), D0
// set, and an RTS to the caller.
func (m *Machine) osReturn(saved savedRegs, d0 uint32) {
	c := m.CPU
	sp := c.SP()
	for i := 2; i < 8; i++ {
		c.SetD(i, saved.d[i])
	}
	for i := 2; i < 7; i++ {
		c.SetA(i, saved.a[i])
	}
	c.SetSP(sp)
	c.SetD(0, d0)
	c.SetPC(rtsStub)
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
		if size >= 1<<20 {
			m.CPU.Discard(a, size) // fresh zero pages, without touching them
			ramClear(m.CPU.RAM[a : a+min(size, 4096)])
			if size > 4096 {
				end := a + size
				ramClear(m.CPU.RAM[end-min(size, 8192) : end]) // the partial pages at the ends
			}
		} else {
			ramClear(m.CPU.RAM[a : a+size])
		}
	}
	return a
}

// Free returns memory from Alloc. Big blocks go back to the host too.
func (m *Machine) Free(a uint32) {
	if size, ok := m.heap.used[a]; ok && size >= 1<<20 {
		m.CPU.Discard(a, size)
	}
	m.heap.free(a)
}

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

func (h *allocator) init(regions ...span) {
	h.spans = append([]span(nil), regions...)
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
	if uint64(a)+uint64(n) > uint64(RAMSize) {
		return nil
	}
	if uint64(a)+uint64(n) > lowEnd && a < fastStart {
		return nil // runs into the chip ranges
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

// Write16 stores a word in guest memory.
func (m *Machine) Write16(a uint32, v uint16) { m.w16(a, v) }
