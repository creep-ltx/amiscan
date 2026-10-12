// Package m68k wraps the Musashi 68000 emulator (vendored in musashi/).
//
// Musashi keeps its CPU in global C state, so there is one CPU per
// process. Guest code calls into Go by executing the ILLEGAL opcode
// ($4AFC) followed by a 16-bit trap number; see Trap.
package m68k

/*
#cgo CFLAGS: -O2 -w
#cgo LDFLAGS: -lm
#include <stdlib.h>
#include "glue.h"
#include "musashi/m68k.h"
*/
import "C"

import (
	"errors"
	"fmt"
	"sync"
	"unsafe"
)

// Musashi CPU types.
const (
	CPU68000 = C.M68K_CPU_TYPE_68000
	CPU68020 = C.M68K_CPU_TYPE_68020
)

// TrapHandler is called when the guest executes ILLEGAL followed by the
// trap number id. pc is the address of the ILLEGAL opcode. On entry the
// CPU's PC already points past the trap number. Return false to treat the
// opcode as a real illegal instruction.
type TrapHandler func(pc uint32, id uint16) bool

// CPU is the one emulated 68000 and its RAM.
type CPU struct {
	RAM     []byte
	handler TrapHandler
	stopped bool
	err     error
}

var (
	mu      sync.Mutex
	current *CPU
)

// New creates the CPU with ramSize bytes of RAM from address 0. Only one
// CPU may exist; New panics if called twice.
func New(ramSize uint32, cpuType int, h TrapHandler) *CPU {
	mu.Lock()
	defer mu.Unlock()
	if current != nil {
		panic("m68k: only one CPU per process")
	}
	p := C.amiscan_map_ram(C.uint32_t(ramSize))
	if p == nil {
		panic("m68k: cannot reserve guest memory")
	}
	ram := unsafe.Slice((*byte)(unsafe.Pointer(p)), ramSize) // zero, pages made on first touch
	c := &CPU{RAM: ram, handler: h}
	current = c
	C.amiscan_init((*C.uint8_t)(unsafe.Pointer(&ram[0])), C.uint32_t(ramSize), C.int(cpuType))
	return c
}

//export goIllegal
func goIllegal(opcode C.uint) C.int {
	c := current
	if opcode != 0x4afc || c == nil {
		return 0
	}
	pc := c.PC()
	id := c.Read16(pc)
	c.SetPC(pc + 2)
	if !c.handler(pc-2, id) {
		c.SetPC(pc)
		return 0
	}
	return 1
}

// Discard tells the host it may drop the memory of [addr, addr+n): the
// guest reads zeros there afterwards.
func (c *CPU) Discard(addr, n uint32) { C.amiscan_discard(C.uint32_t(addr), C.uint32_t(n)) }

// Stop ends Run after the current instruction.
func (c *CPU) Stop() {
	c.stopped = true
	C.m68k_end_timeslice()
}

// Fail ends Run with an error.
func (c *CPU) Fail(err error) {
	if c.err == nil {
		c.err = err
	}
	c.Stop()
}

// ErrBudget is returned when guest code runs past its cycle budget.
var ErrBudget = errors.New("m68k: cycle budget exhausted")

// Run executes until a trap handler calls Stop or Fail, or until maxCycles
// have been used.
func (c *CPU) Run(maxCycles int64) error {
	c.stopped, c.err = false, nil
	var used int64
	for !c.stopped {
		if used >= maxCycles {
			return ErrBudget
		}
		used += int64(C.amiscan_execute(100000))
	}
	return c.err
}

// BadAccesses returns how many guest accesses fell outside RAM and the last
// such address, and resets the counter.
func (c *CPU) BadAccesses() (n uint32, last uint32) {
	n, last = uint32(C.amiscan_bad_accesses), uint32(C.amiscan_last_bad)
	C.amiscan_bad_accesses = 0
	return
}

func reg(r C.m68k_register_t) uint32       { return uint32(C.m68k_get_reg(nil, r)) }
func setReg(r C.m68k_register_t, v uint32) { C.m68k_set_reg(r, C.uint(v)) }

// D returns data register n.
func (c *CPU) D(n int) uint32 { return reg(C.M68K_REG_D0 + C.m68k_register_t(n)) }

// A returns address register n.
func (c *CPU) A(n int) uint32 { return reg(C.M68K_REG_A0 + C.m68k_register_t(n)) }

// SetD sets data register n.
func (c *CPU) SetD(n int, v uint32) { setReg(C.M68K_REG_D0+C.m68k_register_t(n), v) }

// SetA sets address register n.
func (c *CPU) SetA(n int, v uint32) { setReg(C.M68K_REG_A0+C.m68k_register_t(n), v) }

func (c *CPU) PC() uint32      { return reg(C.M68K_REG_PC) }
func (c *CPU) SetPC(v uint32)  { setReg(C.M68K_REG_PC, v) }
func (c *CPU) SR() uint32      { return reg(C.M68K_REG_SR) }
func (c *CPU) SetSR(v uint32)  { setReg(C.M68K_REG_SR, v) }
func (c *CPU) SP() uint32      { return c.A(7) }
func (c *CPU) SetSP(v uint32)  { c.SetA(7, v) }
func (c *CPU) SetUSP(v uint32) { setReg(C.M68K_REG_USP, v) }
func (c *CPU) SetISP(v uint32) { setReg(C.M68K_REG_ISP, v) }

// Disassemble returns the instruction at pc.
func (c *CPU) Disassemble(pc uint32) string {
	var buf [256]C.char
	n := C.m68k_disassemble(&buf[0], C.uint(pc), C.M68K_CPU_TYPE_68000)
	return fmt.Sprintf("%06x: %-30s (%d bytes)", pc, C.GoString(&buf[0]), n)
}

func (c *CPU) in(a, n uint32) bool {
	return uint64(a)+uint64(n) <= uint64(len(c.RAM)) && !(a >= 0xbf0000 && a < 0xc00000) && !(a >= 0xdf0000 && a < 0xe00000)
}

func (c *CPU) Read8(a uint32) uint8 {
	if !c.in(a, 1) {
		return 0
	}
	return c.RAM[a]
}

func (c *CPU) Read16(a uint32) uint16 {
	if !c.in(a, 2) {
		return 0
	}
	return uint16(c.RAM[a])<<8 | uint16(c.RAM[a+1])
}

func (c *CPU) Read32(a uint32) uint32 {
	if !c.in(a, 4) {
		return 0
	}
	p := c.RAM[a : a+4]
	return uint32(p[0])<<24 | uint32(p[1])<<16 | uint32(p[2])<<8 | uint32(p[3])
}

func (c *CPU) Write8(a uint32, v uint8) {
	if c.in(a, 1) {
		c.RAM[a] = v
	}
}

func (c *CPU) Write16(a uint32, v uint16) {
	if c.in(a, 2) {
		c.RAM[a], c.RAM[a+1] = byte(v>>8), byte(v)
	}
}

func (c *CPU) Write32(a uint32, v uint32) {
	if c.in(a, 4) {
		c.RAM[a], c.RAM[a+1], c.RAM[a+2], c.RAM[a+3] = byte(v>>24), byte(v>>16), byte(v>>8), byte(v)
	}
}
