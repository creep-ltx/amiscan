package lzh

import (
	"bytes"
	"testing"
)

// The decoder is tested on real streams through the arj and zoo packages;
// here: random input must end in an error or a full buffer, never a panic
// or a hang, for both parameter sets.
func TestRandomInput(t *testing.T) {
	for _, p := range []Params{LH5, ARJ} {
		for i := 0; i < 400; i++ {
			b := make([]byte, 20+i*13)
			seed := uint32(i*2654435761 + 5)
			for k := range b {
				seed = seed*1664525 + 1013904223
				b[k] = byte(seed >> 24)
			}
			out, _ := Decode(bytes.NewReader(b), 1<<16, p)
			if len(out) > 1<<16 {
				t.Fatalf("output %d bytes past the limit", len(out))
			}
		}
	}
}

func TestBitReader(t *testing.T) {
	b := NewBitReader(bytes.NewReader([]byte{0xa5, 0x0f}))
	if v := b.Bits(4); v != 0xa {
		t.Errorf("first nibble %x", v)
	}
	if v := b.Bits(8); v != 0x50 {
		t.Errorf("next byte %x", v)
	}
	if v := b.Bits(16); v != 0xf000 {
		t.Errorf("past the end %x", v)
	}
	if b.Overrun() {
		t.Error("overrun after 2 bytes")
	}
}
