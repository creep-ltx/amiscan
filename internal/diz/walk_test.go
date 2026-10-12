package diz

import (
	"os"
	"path/filepath"
	"testing"
)

// The header decides, not the name, as on AmigaOS.
func TestWalkByContentNotName(t *testing.T) {
	lim := Limits{Depth: 4, Total: 1 << 30, File: 1 << 28}
	walk := func(name string, data []byte) (items int, warnings []string) {
		Walk(name, data, lim, func(Item) error { items++; return nil },
			func(p string, err error, _ bool) { warnings = append(warnings, p+": "+err.Error()) })
		return
	}
	if n, w := walk("History.lha", []byte("\n   This is the history of a door.\n")); n != 1 || len(w) != 0 {
		t.Errorf("text named .lha: %d items, warnings %v", n, w)
	}
	if n, w := walk("Strip_lzx", []byte("LZX a -r ram:x work:\n")); n != 1 || len(w) != 0 {
		t.Errorf("script starting with LZX: %d items, warnings %v", n, w)
	}
	lhaPath := filepath.Join("testdata", "quicksketch.lha")
	if !present(lhaPath) {
		t.Logf("%s is not published, skipped", lhaPath)
		return
	}
	lhaData, err := os.ReadFile(lhaPath)
	if err != nil {
		t.Fatal(err)
	}
	if n, _ := walk("readme.txt", lhaData); n < 3 {
		t.Errorf("LhA archive named .txt was not opened (%d items)", n)
	}
}
