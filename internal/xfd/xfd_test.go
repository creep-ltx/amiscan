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
