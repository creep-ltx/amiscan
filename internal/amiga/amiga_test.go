package amiga

import (
	"encoding/binary"
	"testing"
)

// One Machine per process: the tests share it.
var testMachine *Machine

func machine(t *testing.T) *Machine {
	t.Helper()
	if testMachine == nil {
		testMachine = New(t.TempDir())
		testMachine.Log = nil
	}
	return testMachine
}

func TestAllocateLikeExec(t *testing.T) {
	m := machine(t)
	// a MemHeader managing 256 bytes, set up the way guest code does it
	mh := m.Alloc(SizeofMemHeader, true)
	pool := m.Alloc(256, true)
	m.w32(mh+MemHeader_mh_First, pool)
	m.w32(pool+MemChunk_mc_Next, 0)
	m.w32(pool+MemChunk_mc_Bytes, 256)
	m.w32(mh+MemHeader_mh_Free, 256)

	a := m.allocate(mh, 10) // rounds to 16
	b := m.allocate(mh, 16)
	if a != pool || b != pool+16 {
		t.Fatalf("got %x %x, want %x %x", a, b, pool, pool+16)
	}
	if free := m.r32(mh + MemHeader_mh_Free); free != 224 {
		t.Fatalf("free %d, want 224", free)
	}
	if m.allocate(mh, 300) != 0 {
		t.Fatal("allocated more than there is")
	}
	m.deallocate(mh, a, 10)
	m.deallocate(mh, b, 16)
	// everything merged back into one chunk
	if m.r32(mh+MemHeader_mh_First) != pool || m.r32(pool+MemChunk_mc_Bytes) != 256 || m.r32(pool) != 0 {
		t.Fatalf("not merged: first %x bytes %d next %x", m.r32(mh+MemHeader_mh_First), m.r32(pool+4), m.r32(pool))
	}
}

func TestInitStruct(t *testing.T) {
	m := machine(t)
	// INITBYTE LN_TYPE,9 ; INITLONG LN_NAME,$12345678 ; INITWORD LIB_VERSION,33 ; end
	tab := []byte{
		0xe0, 0, 0, 8, 9, 0,
		0xc0, 0, 0, 10, 0x12, 0x34, 0x56, 0x78,
		0xd0, 0, 0, 20, 0, 33,
		0,
	}
	src := m.Copy(tab)
	dst := m.Alloc(64, true)
	m.initStruct(src, dst, 0)
	if m.r8(dst+8) != 9 || m.r32(dst+10) != 0x12345678 || m.r16(dst+20) != 33 {
		t.Fatalf("got type %d name %x version %d", m.r8(dst+8), m.r32(dst+10), m.r16(dst+20))
	}
}

func TestLoadSegAndCall(t *testing.T) {
	m := machine(t)
	// one code hunk: lea data(pc),a0 is avoided; use an absolute reloc instead:
	//   move.l #<hunk+8>,d0 ; rts ; dc.l $cafebabe
	code := []uint32{0x203c0000, 0x00084e75, 0xcafebabe}
	var b []byte
	put := func(v ...uint32) {
		for _, x := range v {
			b = binary.BigEndian.AppendUint32(b, x)
		}
	}
	put(hunkHeader, 0, 1, 0, 0, uint32(len(code)))
	put(hunkCode, uint32(len(code)))
	put(code...)
	put(hunkReloc32, 1, 0, 2, 0) // relocate the long at offset 2 against hunk 0
	put(hunkEnd)
	seg, hunks, err := m.LoadSeg(b)
	if err != nil {
		t.Fatal(err)
	}
	if seg<<2 != hunks[0]-4 {
		t.Fatalf("seglist %x does not point at hunk %x", seg<<2, hunks[0])
	}
	d0, err := m.Call(hunks[0], map[string]uint32{}, 1000)
	if err != nil {
		t.Fatal(err)
	}
	if d0 != hunks[0]+8 || m.r32(d0) != 0xcafebabe {
		t.Fatalf("d0 %x, want %x", d0, hunks[0]+8)
	}
}

func TestCrashIsReported(t *testing.T) {
	m := machine(t)
	code := m.Copy([]byte{0x4e, 0x40}) // TRAP #0
	_, err := m.Call(code, map[string]uint32{}, 1000)
	crash, ok := err.(*ErrCrash)
	if !ok || crash.Vector != 32 || crash.PC != code+2 {
		t.Fatalf("got %v", err)
	}
}

func TestRunawayIsStopped(t *testing.T) {
	m := machine(t)
	code := m.Copy([]byte{0x60, 0xfe}) // bra.s *
	if _, err := m.Call(code, map[string]uint32{}, 1_000_000); err == nil {
		t.Fatal("endless loop not stopped")
	}
}
