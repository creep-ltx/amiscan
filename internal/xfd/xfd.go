// Package xfd runs xfdmaster.library (Georg Hörmann and Dirk Stöcker) and
// its decrunchers in LIBS:xfd/ in the emulated Amiga, to unpack crunched
// programs and data files before they are checked for viruses.
package xfd

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/creep-ltx/amiscan/internal/amiga"
)

// LVOs from xfdmaster_lib.fd.
const (
	lvoAllocBufferInfo = 30
	lvoFreeBufferInfo  = 36
	lvoRecogBuffer     = 54
	lvoDecrunchBuffer  = 60
	lvoGetErrorText    = 78
)

// struct xfdBufferInfo offsets (libraries/xfdmaster.h).
const (
	biSourceBuffer     = 0
	biSourceBufLen     = 4
	biPackerName       = 12
	biPackerFlags      = 16
	biError            = 18
	biTargetBuffer     = 20
	biTargetBufMemType = 24
	biTargetBufLen     = 28
	biTargetBufSaveLen = 32
	biFlags            = 48
)

const (
	flagRecogExtern = 1 << 0 // XFDFF_RECOGEXTERN: use the slaves in LIBS:xfd/
	pfPassword      = 1 << 4 // XFDPFF_PASSWORD
	pfKey16         = 1 << 6
	pfKey32         = 1 << 7
	memfPublic      = 1
)

// MaxSize is the largest file handed to xfdmaster (it needs room for the
// unpacked copy too).
const MaxSize = 2 << 20

// Decruncher is a loaded xfdmaster.library.
type Decruncher struct {
	m        *amiga.Machine
	base     uint32
	IDString string
}

// Open loads xfdmaster.library from the machine's LIBS: folder; it loads
// the decrunchers in LIBS:xfd/ itself.
func Open(m *amiga.Machine) (*Decruncher, error) {
	lib, err := m.LoadLibrary(filepath.Join(m.LibsDir, "xfdmaster.library"))
	if err != nil {
		return nil, err
	}
	base, err := m.OpenLibrary(lib, 38)
	if err != nil {
		return nil, fmt.Errorf("xfdmaster.library: %w", err)
	}
	if base == 0 {
		return nil, errors.New("xfdmaster.library: OpenLibrary failed")
	}
	return &Decruncher{m: m, base: base, IDString: strings.TrimSpace(m.Latin1String(m.Read32(base + amiga.Library_lib_IdString)))}, nil
}

func (x *Decruncher) call(lvo uint32, regs map[string]uint32, budget int64) (uint32, error) {
	regs["a6"] = x.base
	return x.m.Call(x.base-lvo, regs, budget)
}

// ErrLocked is returned for a file packed with a password or key.
var ErrLocked = errors.New("packed with a password or key")

// Decrunch unpacks data if a decruncher knows it. packer is "" and out is
// nil when the data is not crunched.
func (x *Decruncher) Decrunch(data []byte) (out []byte, packer string, err error) {
	if len(data) < 16 || len(data) > MaxSize {
		return nil, "", nil
	}
	m := x.m
	src := m.Copy(data)
	if src == 0 {
		return nil, "", errors.New("out of guest memory")
	}
	defer m.Free(src)
	bi, err := x.call(lvoAllocBufferInfo, map[string]uint32{}, 10_000_000)
	if err != nil || bi == 0 {
		return nil, "", fmt.Errorf("xfdAllocBufferInfo: %v", err)
	}
	defer x.call(lvoFreeBufferInfo, map[string]uint32{"a1": bi}, 10_000_000)
	m.Write32(bi+biSourceBuffer, src)
	m.Write32(bi+biSourceBufLen, uint32(len(data)))
	m.Write16(bi+biFlags, flagRecogExtern)
	budget := 200_000_000 + int64(len(data))*500
	ok, err := x.call(lvoRecogBuffer, map[string]uint32{"a0": bi}, budget)
	if err != nil {
		return nil, "", fmt.Errorf("xfdRecogBuffer: %w", err)
	}
	if ok == 0 {
		return nil, "", nil
	}
	packer = m.Latin1String(m.Read32(bi + biPackerName))
	if m.Read16(bi+biPackerFlags)&(pfPassword|pfKey16|pfKey32) != 0 {
		return nil, packer, ErrLocked
	}
	m.Write32(bi+biTargetBufMemType, memfPublic)
	ok, err = x.call(lvoDecrunchBuffer, map[string]uint32{"a0": bi}, budget*20)
	if err != nil {
		return nil, packer, fmt.Errorf("decrunching: %w", err)
	}
	if ok == 0 {
		code := m.Read16(bi + biError)
		text, _ := x.call(lvoGetErrorText, map[string]uint32{"d0": uint32(code)}, 1_000_000)
		if msg := m.Latin1String(text); msg != "" {
			return nil, packer, errors.New(strings.ToLower(msg[:1]) + msg[1:])
		}
		return nil, packer, fmt.Errorf("xfd error %d", code)
	}
	target, n := m.Read32(bi+biTargetBuffer), m.Read32(bi+biTargetBufSaveLen)
	defer m.Free(target)
	b := m.Bytes(target, n)
	if b == nil {
		return nil, packer, errors.New("decrunched file outside memory")
	}
	return append([]byte(nil), b...), packer, nil
}
