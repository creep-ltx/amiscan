package update

import (
	"os"
	"testing"
)

// Needs the unpacked xvslibrary.lha: AMISCAN_XVS_ARCHIVE=<folder holding xvs/>.
func TestGeorgSignsXvs(t *testing.T) {
	dir := os.Getenv("AMISCAN_XVS_ARCHIVE")
	if dir == "" {
		t.Skip("AMISCAN_XVS_ARCHIVE not set")
	}
	lib, err := os.ReadFile(dir + "/xvs/libs/xvs.library")
	if err != nil {
		t.Fatal(err)
	}
	sig, err := os.ReadFile(dir + "/xvs/libs/xvs.library.sig")
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyPGP2(Georg, lib, sig); err != nil {
		t.Fatalf("genuine library rejected: %v", err)
	}
	lib[1000] ^= 1
	if err := VerifyPGP2(Georg, lib, sig); err == nil {
		t.Fatal("changed library accepted")
	}
}
