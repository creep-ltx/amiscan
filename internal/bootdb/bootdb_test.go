package bootdb

import (
	"os"
	"path/filepath"
	"testing"
)

func TestMatchKinds(t *testing.T) {
	dir := t.TempDir()
	boot := make([]byte, 1024)
	copy(boot, "DOS\x00")
	copy(boot[100:], "A touch of STARCOM virus! ")
	var main string = `<?xml version="1.0" encoding="utf-8"?><Bootblocks>`
	for i := 0; i < 120; i++ { // a brain file needs 100+ entries
		main += `<Bootblock><Name>Filler</Name><Recog /><Class>u</Class><CRC>1</CRC></Bootblock>`
	}
	main += `<Bootblock><Name>Seven</Name><Recog>0,68,1,79,2,83,100,65,101,32,102,116,103,111</Recog><Class>l</Class></Bootblock></Bootblocks>`
	search := `<?xml version="1.0" encoding="Windows-1252" standalone="yes"?><SBBootblocks>
<Bootblock><Name>Starcom Virus</Name><Recog>QSB0b3VjaCBvZiBTVEFSQ09NIHZpcnVzISA=</Recog><Class>v</Class><CRC>---</CRC></Bootblock></SBBootblocks>`
	os.WriteFile(filepath.Join(dir, BrainFile), []byte(main), 0o644)
	db, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if e := db.Match(boot); e == nil || e.Name != "Seven" {
		t.Fatalf("pairs: %+v", e)
	}
	os.WriteFile(filepath.Join(dir, SearchFile), []byte(search), 0o644)
	db, _ = Load(dir)
	if e := db.Match(boot); e == nil || e.Name != "Starcom Virus" || !e.IsVirus() {
		t.Fatalf("search list before pairs: %+v", e)
	}
	if e := db.Match(make([]byte, 1024)); e != nil {
		t.Fatalf("empty block matched %q", e.Name)
	}
}

// Against the real files (AMISCAN_LIBS with abr-brainfile.xml).
func TestRealBrainFile(t *testing.T) {
	dir := os.Getenv("AMISCAN_LIBS")
	if dir == "" {
		t.Skip("AMISCAN_LIBS not set")
	}
	if _, err := os.Stat(filepath.Join(dir, BrainFile)); err != nil {
		t.Skip("no brain file")
	}
	db, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if db.Size() < 3000 {
		t.Fatalf("only %d boot blocks", db.Size())
	}
}
