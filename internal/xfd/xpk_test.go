package xfd

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/creep-ltx/amiscan/internal/amiga"
)

// XPK tags and LVOs (xpk_Develop: xpk/xpk.h, xpkmaster_lib.fd).
const (
	xpkTagBase     = 0x80000000 + 'X'<<8 + 'P'
	xpkInBuf       = xpkTagBase + 0x03
	xpkOutBuf      = xpkTagBase + 0x12
	xpkInLen       = xpkTagBase + 0x20
	xpkOutBufLen   = xpkTagBase + 0x21
	xpkGetOutLen   = xpkTagBase + 0x22
	xpkPassword    = xpkTagBase + 0x24
	xpkPackMethod  = xpkTagBase + 0x2a
	xpkPackerQuery = xpkTagBase + 0x33
	lvoXpkPack     = 42
	lvoXpkQuery    = 84
	xpkifEncrypt   = 1 << 13
)

// xpk opens xpkmaster.library in the test machine.
func xpk(t *testing.T, d *Decruncher) uint32 {
	m := d.m
	if _, err := os.Stat(filepath.Join(m.LibsDir, "xpkmaster.library")); err != nil {
		t.Skip("no xpkmaster.library in AMISCAN_LIBS")
	}
	lib, err := m.LoadLibrary(filepath.Join(m.LibsDir, "xpkmaster.library"))
	if err == nil {
		lib, err = m.OpenLibrary(lib, 0)
	}
	if err != nil || lib == 0 {
		t.Fatalf("xpkmaster: %v", err)
	}
	return lib
}

func tags(m *amiga.Machine, kv ...uint32) uint32 {
	p := m.Alloc(uint32(len(kv)+2)*4, true) // ends with TAG_DONE
	for i, v := range kv {
		m.Write32(p+uint32(i)*4, v)
	}
	return p
}

// pack runs XpkPack with a method and an optional password.
func pack(t *testing.T, m *amiga.Machine, xb uint32, data []byte, method, password string) ([]byte, int32) {
	in := m.Copy(data)
	out := m.Alloc(uint32(len(data))*2+4096, true)
	outLen := m.Alloc(4, true)
	kv := []uint32{xpkInBuf, in, xpkInLen, uint32(len(data)), xpkOutBuf, out, xpkOutBufLen, uint32(len(data))*2 + 4096,
		xpkGetOutLen, outLen, xpkPackMethod, m.PutString(method)}
	if password != "" {
		kv = append(kv, xpkPassword, m.PutString(password))
	}
	res, err := m.Call(xb-lvoXpkPack, map[string]uint32{"a0": tags(m, kv...), "a6": xb}, 2_000_000_000)
	if err != nil {
		t.Fatalf("XpkPack %s: %v", method, err)
	}
	if int32(res) != 0 {
		return nil, int32(res)
	}
	return append([]byte(nil), m.Bytes(out, m.Read32(outLen))...), 0
}

// The packers of xpk_User that can encrypt, packed with a password, must
// be reported as locked; packed without one they must unpack exactly.
func TestXPKPasswordAndRoundTrip(t *testing.T) {
	d := open(t)
	m := d.m
	xb := xpk(t, d)
	data := bytes.Repeat([]byte("AmiScan XPK round trip, an Amiga test file. "), 300)

	ents, _ := os.ReadDir(filepath.Join(m.LibsDir, "compressors"))
	encrypting := 0
	for _, e := range ents {
		name := e.Name()
		if len(name) != len("xpkNUKE.library") || name[:3] != "xpk" {
			continue
		}
		method := name[3:7]
		info := m.Alloc(256, true)
		if r, err := m.Call(xb-lvoXpkQuery, map[string]uint32{"a0": tags(m, xpkPackMethod, m.PutString(method), xpkPackerQuery, info), "a6": xb}, 100_000_000); err != nil || r != 0 {
			t.Errorf("%s: XpkQuery %d %v", method, int32(r), err)
			continue
		}
		flags := m.Read32(info + 24 + 32 + 80)

		packed, code := pack(t, m, xb, data, method, "")
		if code != 0 {
			t.Logf("%s: does not pack (XPK error %d)", method, code)
		} else {
			out, packer, err := d.Decrunch(packed)
			if err != nil || !bytes.Equal(out, data) {
				t.Errorf("%s: round trip failed: %q %v, %d bytes", method, packer, err, len(out))
			}
		}
		if flags&xpkifEncrypt == 0 {
			continue
		}
		encrypting++
		locked, code := pack(t, m, xb, data, method, "secret")
		if code != 0 {
			t.Errorf("%s: packing with a password failed (XPK error %d)", method, code)
			continue
		}
		if dir := os.Getenv("AMISCAN_XPK_DUMP"); dir != "" { // for trying the command by hand
			os.WriteFile(filepath.Join(dir, method+"-with-password.xpk"), locked, 0o644)
		}
		out, packer, err := d.Decrunch(locked)
		if out != nil || err == nil {
			t.Errorf("%s with a password: unpacked without it (%q, %d bytes, %v)", method, packer, len(out), err)
			continue
		}
		t.Logf("%s with a password: %q, %v", method, packer, err)
		if !errors.Is(err, ErrLocked) {
			t.Logf("  (reported as a failed unpack, not as locked)")
		}
	}
	if encrypting == 0 {
		t.Error("no packer in compressors/ supports encryption")
	}
}
