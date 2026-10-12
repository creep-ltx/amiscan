package xfd

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/creep-ltx/amiscan/internal/amiga"
)

// Needs a libs folder with xfdmaster.library and xfd/ in AMISCAN_LIBS.
var dec *Decruncher

func open(t *testing.T) *Decruncher {
	t.Helper()
	dir := os.Getenv("AMISCAN_LIBS")
	if dir == "" {
		t.Skip("AMISCAN_LIBS not set")
	}
	if _, err := os.Stat(filepath.Join(dir, "xfdmaster.library")); err != nil {
		t.Skip("no xfdmaster.library in AMISCAN_LIBS")
	}
	if dec == nil {
		m := amiga.New(dir)
		m.Log = nil
		d, err := Open(m)
		if err != nil {
			t.Fatal(err)
		}
		dec = d
	}
	return dec
}

func TestNotCrunched(t *testing.T) {
	d := open(t)
	out, packer, err := d.Decrunch(bytes.Repeat([]byte("plain text, nothing packed here\n"), 50))
	if out != nil || packer != "" || err != nil {
		t.Fatalf("plain text: %d bytes, %q, %v", len(out), packer, err)
	}
}

// A crunched program from the virus collection and the same program
// unpacked by its collector (AMISCAN_SAMPLES).
func TestDecrunchMatchesOriginal(t *testing.T) {
	d := open(t)
	dir := os.Getenv("AMISCAN_SAMPLES")
	if dir == "" {
		t.Skip("AMISCAN_SAMPLES not set")
	}
	packed, err := os.ReadFile(filepath.Join(dir, "VIRUSCOLLECTIE/C/CHKMNT_TEST"))
	if err != nil {
		t.Fatal(err)
	}
	want, err := os.ReadFile(filepath.Join(dir, "VIRUSCOLLECTIE/C/CHKMNT_TEST.UNPACKED"))
	if err != nil {
		t.Fatal(err)
	}
	out, packer, err := d.Decrunch(packed)
	t.Logf("%s: %d -> %d bytes (original %d)", packer, len(packed), len(out), len(want))
	if err != nil || out == nil {
		t.Fatalf("not decrunched: %q %v", packer, err)
	}
	if !bytes.Equal(out, want) {
		t.Errorf("decrunched file differs from the original")
	}
}

// An XPK (NUKE) file through xfdmaster and xpkmaster: AMISCAN_XPK_SAMPLE
// names one; its header says how long the unpacked file is.
func TestXPK(t *testing.T) {
	d := open(t)
	path := os.Getenv("AMISCAN_XPK_SAMPLE")
	if path == "" {
		t.Skip("AMISCAN_XPK_SAMPLE not set")
	}
	packed, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(packed[:4]) != "XPKF" {
		t.Fatal("not an XPK file")
	}
	want := int(packed[12])<<24 | int(packed[13])<<16 | int(packed[14])<<8 | int(packed[15])
	out, packer, err := d.Decrunch(packed)
	if err != nil || len(out) != want {
		t.Fatalf("%s: %d bytes, %v; header says %d", packer, len(out), err, want)
	}
	if out[0] != 0 || out[1] != 0 || out[2] != 3 || out[3] != 0xf3 {
		t.Errorf("unpacked file is not an Amiga program")
	}
	t.Logf("%s (%s): %d -> %d bytes", packer, packed[8:12], len(packed), len(out))
}
