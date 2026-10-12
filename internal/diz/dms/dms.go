// Package dms unpacks DiskMasher (DMS) archives to Amiga disk images, in
// memory. It is a port of xDMS 1.3 by Andre Rodrigues de la Rocha (public
// domain): the same track records, CRCs, checksums and the seven packing
// modes (NOCOMP, SIMPLE, QUICK, MEDIUM, DEEP, HEAVY1, HEAVY2), with the
// decoders' shared state carried from track to track as xDMS does.
//
// Unlike xDMS it never reads outside its buffers and never loops without
// end: a corrupt track stops the unpacking with an error, and the tracks
// read before it are kept.
//
// The layout (big-endian): a 56-byte header "DMS!" with a CRC over bytes
// 4..53 in bytes 54..55; then 20-byte track records "TR" (track number,
// packed and unpacked lengths, flags, mode, a 16-bit sum of the unpacked
// bytes, a CRC of the packed bytes, a CRC of the record), each followed by
// its packed data. Track 80 is an attached FILE_ID.DIZ, track 0xFFFF a
// banner text, and a track 0 of 1024 bytes a "fake boot block" (advertising);
// only tracks 0..79 longer than 2048 bytes are part of the disk.
package dms

import (
	"errors"
	"fmt"
)

// Errors returned by Read.
var (
	ErrNotDMS    = errors.New("dms: not a DMS archive")
	ErrHeaderCRC = errors.New("dms: header CRC error")
	ErrFMS       = errors.New("dms: FMS archive (a file, not a disk)")
)

// Mode names, by the mode number in a track record.
var Modes = []string{"NOCOMP", "SIMPLE", "QUICK", "MEDIUM", "DEEP", "HEAVY1", "HEAVY2"}

// General info flags in the header.
const (
	InfoNoZero    = 1
	InfoEncrypted = 2
	InfoAppends   = 4
	InfoBanner    = 8
	InfoHD        = 16
	InfoMSDOS     = 32
	InfoFileID    = 256
)

const (
	headLen  = 56
	trackLen = 20
	bufLen   = 32000 // xDMS's track buffer: no track is longer
	slack    = 512   // matches may run past a track's end, as in xDMS
)

// Track is one unpacked disk track (really a cylinder: both sides).
type Track struct {
	Number int
	Mode   int
	Data   []byte
}

// Archive is a read DMS file.
type Archive struct {
	Info      uint16 // general info flags (Info*)
	DiskType  uint16 // 0/1 OFS, 2 FFS, 3 OFS intl, 4 FFS intl, 5 OFS dircache, 6 FFS dircache
	Mode      uint16 // the packing mode mostly used
	Encrypted bool   // password protected: the disk tracks are not unpacked
	Tracks    []Track
	DIZ       []byte // the attached FILE_ID.DIZ (track 80), nil if none
	Banner    []byte // the attached banner text (track 0xFFFF), nil if none
	// Err is why the unpacking stopped early (a bad track); the tracks
	// before it are in Tracks. Trailing junk after the last track is not
	// an error (xDMS ignores it too).
	Err error
}

// Read unpacks a whole DMS file held in memory.
func Read(b []byte) (*Archive, error) {
	if len(b) < headLen || string(b[:4]) != "DMS!" {
		return nil, ErrNotDMS
	}
	if be16(b[headLen-2:]) != crc16(b[4:headLen-2]) {
		return nil, ErrHeaderCRC
	}
	a := &Archive{
		Info:     be16(b[10:]),
		DiskType: be16(b[50:]),
		Mode:     be16(b[52:]),
	}
	if a.DiskType == 7 {
		return nil, ErrFMS
	}
	a.Encrypted = a.Info&InfoEncrypted != 0
	d := newDecoder()
	pos := headLen
	for pos < len(b) {
		h := b[pos:]
		if len(h) < trackLen {
			a.Err = errors.New("dms: short track record")
			break
		}
		if h[0] != 'T' || h[1] != 'R' {
			break // the end of the tracks; some files carry text or zeros after
		}
		if be16(h[trackLen-2:]) != crc16(h[:trackLen-2]) {
			a.Err = fmt.Errorf("dms: track record CRC error at %d", pos)
			break
		}
		num := int(be16(h[2:]))
		pk1 := int(be16(h[6:]))
		pk2 := int(be16(h[8:]))
		unpk := int(be16(h[10:]))
		flags := h[12]
		mode := h[13]
		usum := be16(h[14:])
		dcrc := be16(h[16:])
		if pk1 > bufLen || pk2 > bufLen || unpk > bufLen {
			a.Err = fmt.Errorf("dms: track %d too big", num)
			break
		}
		pos += trackLen
		if pos+pk1 > len(b) {
			a.Err = fmt.Errorf("dms: track %d cut short", num)
			break
		}
		data := b[pos : pos+pk1]
		pos += pk1
		if crc16(data) != dcrc {
			a.Err = fmt.Errorf("dms: track %d data CRC error", num)
			break
		}
		switch {
		case num == 80:
			// FILE_ID.DIZ: never encrypted, unpacked on its own.
			if out, err := newDecoder().track(data, pk2, unpk, mode, flags); err == nil && sum16(out) == usum {
				a.DIZ = out
			}
		case num == 0xffff:
			if !a.Encrypted {
				if out, err := newDecoder().track(data, pk2, unpk, mode, flags); err == nil && sum16(out) == usum {
					a.Banner = out
				}
			}
		case num < 80 && unpk > 2048 && !a.Encrypted:
			out, err := d.track(data, pk2, unpk, mode, flags)
			if err == nil && sum16(out) != usum {
				err = errors.New("checksum error")
			}
			if err != nil {
				a.Err = fmt.Errorf("dms: track %d (%s): %v", num, modeName(mode), err)
				return a, nil
			}
			a.Tracks = append(a.Tracks, Track{Number: num, Mode: int(mode), Data: out})
		}
	}
	return a, nil
}

func modeName(m byte) string {
	if int(m) < len(Modes) {
		return Modes[m]
	}
	return fmt.Sprintf("mode %d", m)
}

// Concat is the tracks one after the other, as xDMS writes them.
func (a *Archive) Concat() []byte {
	var out []byte
	for _, t := range a.Tracks {
		out = append(out, t.Data...)
	}
	return out
}

// Image is the disk image with every track at its place (missing tracks
// left zero), 80 tracks long. When the tracks differ in length it is the
// same as Concat.
func (a *Archive) Image() []byte {
	if len(a.Tracks) == 0 {
		return nil
	}
	size := len(a.Tracks[0].Data)
	for _, t := range a.Tracks {
		if len(t.Data) != size {
			return a.Concat()
		}
	}
	img := make([]byte, 80*size)
	for _, t := range a.Tracks {
		copy(img[t.Number*size:], t.Data)
	}
	return img
}

func be16(b []byte) uint16 { return uint16(b[0])<<8 | uint16(b[1]) }

func sum16(b []byte) uint16 {
	var s uint16
	for _, c := range b {
		s += uint16(c)
	}
	return s
}

var crcTab = func() (t [256]uint16) {
	// CRC-16/ARC (reflected 0x8005), the table xDMS carries.
	for i := range t {
		c := uint16(i)
		for k := 0; k < 8; k++ {
			if c&1 != 0 {
				c = c>>1 ^ 0xa001
			} else {
				c >>= 1
			}
		}
		t[i] = c
	}
	return
}()

func crc16(b []byte) uint16 {
	var c uint16
	for _, x := range b {
		c = crcTab[(c^uint16(x))&0xff] ^ c>>8
	}
	return c
}
