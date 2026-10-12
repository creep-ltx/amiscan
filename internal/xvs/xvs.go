// Package xvs runs xvs.library, the eXternal Virus Scanner library by
// Georg Wittmann, in the emulated Amiga. The library itself is not part of
// AmiScan; the user downloads it from the Virus Help Team.
package xvs

import (
	"errors"
	"fmt"
	"path/filepath"

	"github.com/creep-ltx/amiscan/internal/amiga"
)

// LVOs from xvs_lib.fd.
const (
	lvoSelfTest        = 30
	lvoCreateVirusList = 36
	lvoFreeVirusList   = 42
	lvoAllocObject     = 48
	lvoFreeObject      = 54
	lvoCheckBootblock  = 66
	lvoCheckFile       = 96
	lvoRepairFile      = 102
)

// Object types and virus list types.
const (
	objBootInfo = 1
	objFileInfo = 3

	ListBoot = 0x42
	ListData = 0x44
	ListFile = 0x46
	ListLink = 0x4c
)

// File types from xvsCheckFile.
const (
	FileEmpty     = 1
	FileData      = 2
	FileExe       = 3
	FileDataVirus = 4
	FileVirus     = 5
	FileLinkVirus = 6
)

// Bootblock types from xvsCheckBootblock.
const (
	BootUnknown    = 0
	BootNotDOS     = 1
	BootStandard13 = 2
	BootStandard20 = 3
	BootVirus      = 4
)

// MaxFileSize is the largest file checked (set from -max; the emulated
// Amiga needs about twice that in fast RAM, see amiga.SetFastRAM).
var MaxFileSize = 1536 << 20

// Scanner is a loaded and opened xvs.library.
type Scanner struct {
	m        *amiga.Machine
	base     uint32
	Version  string // e.g. "33.49"
	IDString string
}

// Open loads xvs.library from the machine's LIBS: folder. (xvs.library
// refuses to start without trackdisk.device and intuition.library, which
// amiga.New provides.)
func Open(m *amiga.Machine) (*Scanner, error) {
	path := filepath.Join(m.LibsDir, "xvs.library")
	lib, err := m.LoadLibrary(path)
	if err != nil {
		return nil, err
	}
	base, err := m.OpenLibrary(lib, 33)
	if err != nil {
		return nil, fmt.Errorf("xvs.library: %w", err)
	}
	if base == 0 {
		return nil, errors.New("xvs.library: OpenLibrary failed")
	}
	s := &Scanner{m: m, base: base}
	s.Version = fmt.Sprintf("%d.%d", m.Read16(base+amiga.Library_lib_Version), m.Read16(base+amiga.Library_lib_Revision))
	s.IDString = m.CString(m.Read32(base + amiga.Library_lib_IdString))
	return s, nil
}

// Machine gives access to the emulated Amiga (for tracing).
func (s *Scanner) Machine() *amiga.Machine { return s.m }

func (s *Scanner) call(lvo uint32, regs map[string]uint32, budget int64) (uint32, error) {
	regs["a6"] = s.base
	return s.m.Call(s.base-lvo, regs, budget)
}

// SelfTest runs xvsSelfTest; false means the library is damaged.
func (s *Scanner) SelfTest() (bool, error) {
	r, err := s.call(lvoSelfTest, map[string]uint32{}, 200_000_000)
	return r != 0, err
}

// VirusList returns the names of all viruses of one kind (ListBoot etc.).
func (s *Scanner) VirusList(kind uint32) ([]string, error) {
	l, err := s.call(lvoCreateVirusList, map[string]uint32{"d0": kind}, 200_000_000)
	if err != nil || l == 0 {
		return nil, err
	}
	var names []string
	for n := s.m.Read32(l); n != 0 && s.m.Read32(n) != 0; n = s.m.Read32(n) {
		names = append(names, s.m.Latin1String(s.m.Read32(n+amiga.Node_ln_Name)))
	}
	_, err = s.call(lvoFreeVirusList, map[string]uint32{"a1": l}, 50_000_000)
	return names, err
}

// FileResult is what xvsCheckFile says about a file.
type FileResult struct {
	Type uint8  // FileEmpty .. FileLinkVirus
	Name string // virus name, or a description like "Executable file"
}

// Infected reports whether the result names a virus.
func (r FileResult) Infected() bool { return r.Type >= FileDataVirus }

func budgetFor(n int) int64 { return 300_000_000 + int64(n)*2000 }

// CheckFile checks a whole file held in memory.
func (s *Scanner) CheckFile(data []byte) (FileResult, error) {
	if len(data) > MaxFileSize {
		return FileResult{}, fmt.Errorf("file too large (%d bytes, limit %d)", len(data), MaxFileSize)
	}
	buf := s.m.Copy(data)
	if buf == 0 {
		return FileResult{}, errors.New("out of guest memory")
	}
	defer s.m.Free(buf)
	fi, err := s.call(lvoAllocObject, map[string]uint32{"d0": objFileInfo}, 50_000_000)
	if err != nil || fi == 0 {
		return FileResult{}, fmt.Errorf("xvsAllocObject: %v", err)
	}
	defer s.call(lvoFreeObject, map[string]uint32{"a1": fi}, 50_000_000)
	s.m.Write32(fi+0, buf)
	s.m.Write32(fi+4, uint32(len(data)))
	if _, err := s.call(lvoCheckFile, map[string]uint32{"a0": fi}, budgetFor(len(data))); err != nil {
		return FileResult{}, fmt.Errorf("xvsCheckFile: %w", err)
	}
	return FileResult{Type: s.m.Read8(fi + 12), Name: s.m.Latin1String(s.m.Read32(fi + 8))}, nil
}

// RepairFile asks xvs.library to remove a link virus; it returns the fixed
// file, or an error naming why it could not.
func (s *Scanner) RepairFile(data []byte) ([]byte, error) {
	if len(data) > MaxFileSize {
		return nil, fmt.Errorf("file too large")
	}
	buf := s.m.Copy(data)
	if buf == 0 {
		return nil, errors.New("out of guest memory")
	}
	defer s.m.Free(buf)
	fi, err := s.call(lvoAllocObject, map[string]uint32{"d0": objFileInfo}, 50_000_000)
	if err != nil || fi == 0 {
		return nil, fmt.Errorf("xvsAllocObject: %v", err)
	}
	defer s.call(lvoFreeObject, map[string]uint32{"a1": fi}, 50_000_000)
	s.m.Write32(fi+0, buf)
	s.m.Write32(fi+4, uint32(len(data)))
	if _, err := s.call(lvoCheckFile, map[string]uint32{"a0": fi}, budgetFor(len(data))); err != nil {
		return nil, err
	}
	if s.m.Read8(fi+12) != FileLinkVirus {
		return nil, errors.New("not a link virus; delete the file instead")
	}
	ok, err := s.call(lvoRepairFile, map[string]uint32{"a0": fi}, budgetFor(len(data)))
	if err != nil {
		return nil, err
	}
	if ok == 0 {
		return nil, fmt.Errorf("repair failed (xvs error %d)", s.m.Read8(fi+14))
	}
	fixed, n := s.m.Read32(fi+16), s.m.Read32(fi+20)
	return append([]byte(nil), s.m.Bytes(fixed, n)...), nil
}

// BootResult is what xvsCheckBootblock says about a bootblock.
type BootResult struct {
	Type       uint8
	Name       string
	DosType    uint8
	ChecksumOK bool
}

// Infected reports whether the bootblock is a known virus.
func (r BootResult) Infected() bool { return r.Type == BootVirus }

// CheckBootblock checks the first 1024 bytes of a disk.
func (s *Scanner) CheckBootblock(bb []byte) (BootResult, error) {
	if len(bb) < 1024 {
		return BootResult{}, errors.New("bootblock shorter than 1024 bytes")
	}
	buf := s.m.Copy(bb[:1024])
	if buf == 0 {
		return BootResult{}, errors.New("out of guest memory")
	}
	defer s.m.Free(buf)
	bi, err := s.call(lvoAllocObject, map[string]uint32{"d0": objBootInfo}, 50_000_000)
	if err != nil || bi == 0 {
		return BootResult{}, fmt.Errorf("xvsAllocObject: %v", err)
	}
	defer s.call(lvoFreeObject, map[string]uint32{"a1": bi}, 50_000_000)
	s.m.Write32(bi, buf)
	if _, err := s.call(lvoCheckBootblock, map[string]uint32{"a0": bi}, 100_000_000); err != nil {
		return BootResult{}, fmt.Errorf("xvsCheckBootblock: %w", err)
	}
	return BootResult{
		Type:       s.m.Read8(bi + 8),
		Name:       s.m.Latin1String(s.m.Read32(bi + 4)),
		DosType:    s.m.Read8(bi + 9),
		ChecksumOK: s.m.Read8(bi+10) != 0,
	}, nil
}
