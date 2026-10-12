package adf

import (
	"errors"
	"fmt"
	"io"
	"strings"
)

// Partition is one partition of a hard disk image, from its Rigid Disk
// Block (RDB) partition list.
type Partition struct {
	Name     string // drive name, e.g. "DH0"
	DOSType  uint32 // e.g. 0x444F5303 (DOS\3); PFS\3 and SFS\0 are not read
	Offset   int64  // byte offset of block 0
	Blocks   int64
	BSize    int
	Reserved int
}

// DOSTypeString is "DOS\3", "PFS\3" and so on.
func (p Partition) DOSTypeString() string {
	b := []byte{byte(p.DOSType >> 24), byte(p.DOSType >> 16), byte(p.DOSType >> 8)}
	return fmt.Sprintf("%s\\%d", strings.Map(func(r rune) rune {
		if r < 0x20 || r > 0x7e {
			return '?'
		}
		return r
	}, string(b)), byte(p.DOSType))
}

// IsDOS reports an OFS/FFS partition, which this package reads.
func (p Partition) IsDOS() bool { return p.DOSType>>8 == 0x444f53 && byte(p.DOSType) <= 7 }

// Open opens the partition's volume.
func (p Partition) Open(r io.ReaderAt) (*Volume, error) {
	return Open(r, p.Offset, p.Blocks, p.BSize, p.Reserved)
}

// ErrNoRDB means no "RDSK" block in the first 16 blocks.
var ErrNoRDB = errors.New("adf: no rigid disk block")

// Partitions reads the RDB of a hard disk image (searched in its first
// 16 blocks) and returns its partitions.
func Partitions(r io.ReaderAt, size int64) ([]Partition, error) {
	blk := make([]byte, 512)
	var rdb []byte
	for i := int64(0); i < 16; i++ {
		if _, err := r.ReadAt(blk, i*512); err != nil {
			break
		}
		if string(blk[:4]) == "RDSK" {
			rdb = append([]byte(nil), blk...)
			break
		}
	}
	if rdb == nil {
		return nil, ErrNoRDB
	}
	bb := int64(be32(rdb[16:])) // rdb_BlockBytes
	if bb < 256 || bb > 65536 {
		bb = 512
	}
	var parts []Partition
	seen := map[uint32]bool{}
	for n := be32(rdb[28:]); n != 0xffffffff && n != 0 && len(parts) < 128; {
		if seen[n] || int64(n)*bb >= size {
			break
		}
		seen[n] = true
		pb := make([]byte, bb)
		if _, err := r.ReadAt(pb, int64(n)*bb); err != nil && err != io.EOF {
			break
		}
		if string(pb[:4]) != "PART" || bb < 128+17*4 {
			break
		}
		env := pb[128:]
		e := func(i int) int64 { return int64(be32(env[4*i:])) }
		nl := int(pb[36])
		if nl > 31 {
			nl = 31
		}
		p := Partition{Name: strings.TrimRight(string(pb[37:37+nl]), "\x00")}
		sizeBlock, surfaces, secPerBlk, bpt := e(1), e(3), e(4), e(5)
		low, high := e(9), e(10)
		if secPerBlk <= 0 {
			secPerBlk = 1
		}
		p.Reserved = int(e(6))
		if e(0) >= 16 {
			p.DOSType = uint32(e(16))
		} else {
			p.DOSType = 0x444f5300
		}
		p.BSize = int(sizeBlock * 4 * secPerBlk)
		cylBytes := surfaces * bpt * sizeBlock * 4
		p.Offset = low * cylBytes
		if p.BSize > 0 {
			p.Blocks = (high - low + 1) * cylBytes / int64(p.BSize)
		}
		if p.Offset+p.Blocks*int64(p.BSize) > size {
			p.Blocks = (size - p.Offset) / max(int64(p.BSize), 1)
		}
		if p.Reserved < 0 || p.Reserved > 1024 {
			p.Reserved = 2
		}
		parts = append(parts, p)
		n = be32(pb[16:]) // pb_Next
	}
	return parts, nil
}
