package update

import (
	"context"
	"encoding/binary"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/creep-ltx/amiscan/internal/diz/lha"
)

// lhaStored builds an LhA archive (level 0 headers, -lh0- stored).
func lhaStored(files map[string][]byte, order ...string) []byte {
	var out []byte
	for _, name := range order {
		data := files[name]
		h := []byte("-lh0-")
		h = binary.LittleEndian.AppendUint32(h, uint32(len(data)))
		h = binary.LittleEndian.AppendUint32(h, uint32(len(data)))
		h = binary.LittleEndian.AppendUint32(h, 0x5a000000) // DOS date
		h = append(h, 0x20, 0, byte(len(name)))
		h = append(h, name...)
		h = binary.LittleEndian.AppendUint16(h, lha.CRC16(data))
		var sum byte
		for _, b := range h {
			sum += b
		}
		out = append(out, byte(len(h)), sum)
		out = append(out, h...)
		out = append(out, data...)
	}
	return append(out, 0)
}

// server serves whatever *body holds at /x.lha and /key.lha.
func server(t *testing.T, bodies map[string]*[]byte, hits map[string]int) *httptest.Server {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits[r.URL.Path]++
		b, ok := bodies[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Write(*b)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func versionFile(dir string) (string, error) {
	b, err := os.ReadFile(filepath.Join(dir, "db.library"))
	if err != nil {
		return "", err
	}
	if !strings.HasPrefix(string(b), "DB ") {
		return "", os.ErrInvalid
	}
	if _, err := os.Stat(filepath.Join(dir, "db.key")); err != nil {
		return "", err // the library does not work without its key
	}
	return strings.TrimPrefix(string(b), "DB "), nil
}

func TestKeyFileFetchedWhenMissingAndDowngradeRefused(t *testing.T) {
	db := lhaStored(map[string][]byte{"db/libs/db.library": []byte("DB 1.2")}, "db/libs/db.library")
	key := lhaStored(map[string][]byte{"db.key": []byte("free key")}, "db.key")
	hits := map[string]int{}
	srv := server(t, map[string]*[]byte{"/db.lha": &db, "/key.lha": &key}, hits)
	keySrc := &Source{Name: "db key", URL: srv.URL + "/key.lha", Files: map[string]string{"db.key": "db.key"}}
	src := &Source{Name: "db.library", URL: srv.URL + "/db.lha",
		Files: map[string]string{"DB/LIBS/db.library": "db.library"}, // any case
		Needs: []*Source{keySrc}, Version: versionFile}
	dir := t.TempDir()
	u := &Updater{Dir: dir}

	res, err := u.Update(context.Background(), src, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(res) != 2 || res[0].Source != "db key" || res[1].Action != "installed" || res[1].Version != "1.2" {
		t.Fatalf("first run: %v", res)
	}

	// the key is there now: only the library is checked again
	res, err = u.Update(context.Background(), src, false)
	if err != nil || len(res) != 1 || hits["/key.lha"] != 1 {
		t.Fatalf("second run: %v %v, key fetched %d times", res, err, hits["/key.lha"])
	}

	// a newer library replaces the old, which is kept in old/
	db = lhaStored(map[string][]byte{"db/libs/db.library": []byte("DB 1.10")}, "db/libs/db.library")
	res, err = u.Update(context.Background(), src, false)
	if err != nil || res[0].Action != "updated" || res[0].Old != "1.2" || res[0].Version != "1.10" {
		t.Fatalf("update: %v %v", res, err)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "old", "db.library")); string(b) != "DB 1.2" {
		t.Fatalf("old copy: %q", b)
	}

	// an older one on the server is refused
	db = lhaStored(map[string][]byte{"db/libs/db.library": []byte("DB 1.9")}, "db/libs/db.library")
	if _, err := u.Update(context.Background(), src, false); err == nil || !strings.Contains(err.Error(), "older") {
		t.Fatalf("downgrade: %v", err)
	}
	if v, _ := versionFile(dir); v != "1.10" {
		t.Fatalf("installed after refused downgrade: %s", v)
	}

	// a broken one is refused and the working one stays
	db = lhaStored(map[string][]byte{"db/libs/db.library": []byte("garbage")}, "db/libs/db.library")
	if _, err := u.Update(context.Background(), src, false); err == nil {
		t.Fatal("broken library installed")
	}
	if v, _ := versionFile(dir); v != "1.10" {
		t.Fatalf("installed after refused download: %s", v)
	}

	// a deleted key file comes back
	os.Remove(filepath.Join(dir, "db.key"))
	db = lhaStored(map[string][]byte{"db/libs/db.library": []byte("DB 1.10")}, "db/libs/db.library")
	if _, err := u.Update(context.Background(), src, false); err != nil || hits["/key.lha"] != 2 {
		t.Fatalf("key not fetched again: %v, %d", err, hits["/key.lha"])
	}
}

func TestUnsignedOrTamperedRefused(t *testing.T) {
	dir := os.Getenv("AMISCAN_XVS_ARCHIVE") // the unpacked real xvslibrary.lha
	if dir == "" {
		t.Skip("AMISCAN_XVS_ARCHIVE not set")
	}
	lib, _ := os.ReadFile(dir + "/xvs/libs/xvs.library")
	sig, _ := os.ReadFile(dir + "/xvs/libs/xvs.library.sig")
	src := *XVS
	files := map[string][]byte{"xvs/libs/xvs.library": lib, "xvs/libs/xvs.library.sig": sig}

	good := lhaStored(files, "xvs/libs/xvs.library", "xvs/libs/xvs.library.sig")
	bad := append([]byte(nil), lib...)
	bad[5000] ^= 0x40
	tampered := lhaStored(map[string][]byte{"xvs/libs/xvs.library": bad, "xvs/libs/xvs.library.sig": sig},
		"xvs/libs/xvs.library", "xvs/libs/xvs.library.sig")
	unsigned := lhaStored(files, "xvs/libs/xvs.library")

	for _, c := range []struct {
		name string
		body []byte
		ok   bool
	}{{"tampered", tampered, false}, {"unsigned", unsigned, false}, {"genuine", good, true}} {
		body := c.body
		srv := server(t, map[string]*[]byte{"/xvslibrary.lha": &body}, map[string]int{})
		src.URL = srv.URL + "/xvslibrary.lha"
		out := t.TempDir()
		_, err := (&Updater{Dir: out}).Update(context.Background(), &src, true)
		_, statErr := os.Stat(filepath.Join(out, "xvs.library"))
		if c.ok != (err == nil) || c.ok != (statErr == nil) {
			t.Errorf("%s: err %v, installed %v", c.name, err, statErr == nil)
		}
	}
}

func TestFolderInstalledAndReplaced(t *testing.T) {
	arc := lhaStored(map[string][]byte{
		"pkg/Libs/main.library": []byte("main"),
		"pkg/Libs/mods/A":       []byte("a"),
		"pkg/Libs/mods/B":       []byte("b"),
		"pkg/Libs/mods/sub/C":   []byte("not installed"),
		"pkg/Docs/readme":       []byte("not installed"),
	}, "pkg/Libs/main.library", "pkg/Libs/mods/A", "pkg/Libs/mods/B", "pkg/Libs/mods/sub/C", "pkg/Docs/readme")
	srv := server(t, map[string]*[]byte{"/p.lha": &arc}, map[string]int{})
	src := &Source{Name: "pkg", URL: srv.URL + "/p.lha",
		Files: map[string]string{"pkg/libs/main.library": "main.library"},
		Dirs:  map[string]string{"PKG/Libs/Mods": "mods"}}
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "mods"), 0o755)
	os.WriteFile(filepath.Join(dir, "mods", "Stale"), []byte("old"), 0o644)
	if _, err := (&Updater{Dir: dir}).Update(context.Background(), src, true); err != nil {
		t.Fatal(err)
	}
	ents, _ := os.ReadDir(filepath.Join(dir, "mods"))
	var names []string
	for _, e := range ents {
		names = append(names, e.Name())
	}
	if strings.Join(names, ",") != "A,B" {
		t.Fatalf("mods/ holds %v, want A,B", names)
	}
	if _, err := os.Stat(filepath.Join(dir, "old", "mods", "Stale")); err != nil {
		t.Fatal("previous folder not kept in old/")
	}
}
