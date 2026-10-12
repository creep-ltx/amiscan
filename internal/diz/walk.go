package diz

// AmiScan's addition: every file inside an archive or disk image, nested,
// plus each floppy's boot block, for a virus scanner.

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"path"
	"strings"

	"github.com/creep-ltx/amiscan/internal/diz/dms"
)

// Item is one thing to check.
type Item struct {
	Path string // outer file, then members joined with '/', e.g. "disk.dms/c/dir"
	Data []byte
	Boot bool // Data is a floppy boot block (1024 bytes), not a file
	// Damaged says why the archive could not give the whole file; Data is
	// then the part that unpacked (what LhA itself would write out).
	Damaged string
}

// Limits bound how far Walk unpacks, against archive bombs.
type Limits struct {
	Depth int   // archives inside archives, e.g. 4
	Total int64 // bytes unpacked in all, e.g. 512 MiB
	File  int64 // largest single member, e.g. 64 MiB
}

// Walk calls fn for data itself and, when data is an archive or disk image
// it can read, for its boot block and every file inside, recursively.
// Problems inside go to warn: damaged is true when nobody can read the part
// in question (a broken archive), false when Walk chose not to (a limit).
// Walk itself stops only when fn returns an error.
func Walk(name string, data []byte, lim Limits, fn func(Item) error, warn func(path string, err error, damaged bool)) error {
	w := &walker{lim: lim, fn: fn, warn: warn}
	return w.walk(name, data, 0, "")
}

type walker struct {
	lim   Limits
	total int64
	fn    func(Item) error
	warn  func(string, error, bool)
}

func (w *walker) walk(name string, data []byte, depth int, damaged string) (err error) {
	if err := w.fn(Item{Path: name, Data: data, Damaged: damaged}); err != nil {
		return err
	}
	// a boot block saved as a file (a virus collection's, or a .bb backup)
	if len(data) == 1024 && bytes.HasPrefix(data, []byte("DOS")) {
		if err := w.fn(Item{Path: name + " (as boot block)", Data: data, Boot: true}); err != nil {
			return err
		}
		return nil
	}
	head := data[:min(len(data), headSize)]
	ext := strings.ToLower(strings.TrimPrefix(path.Ext(name), "."))
	f := detectContent(head, int64(len(data)), ext)
	if f == nil || f.name == "amigaexe" {
		return nil
	}
	if depth >= w.lim.Depth {
		w.warn(name, fmt.Errorf("%s inside %d archives: not unpacked", f.name, depth), false)
		return nil
	}
	defer func() {
		if r := recover(); r != nil { // a decoder bug on strange data must not stop the scan
			w.warn(name, fmt.Errorf("%s is damaged: %v", f.name, r), true)
		}
	}()
	if boot := bootBlock(f.name, data); boot != nil {
		if err := w.fn(Item{Path: name + "/(boot block)", Data: boot, Boot: true}); err != nil {
			return err
		}
	}
	ms, _, ok := listAll(bytes.NewReader(data), int64(len(data)), f)
	if !ok {
		// The file itself was checked; its header said archive but the rest
		// is broken. A program that looks like a self-extractor or a disk
		// without AmigaDOS files is not a problem.
		if f.name != "adf" && f.name != "adz" && f.name != "dms" && f.name != "sfx" && f.name != "hdf" {
			w.warn(name, fmt.Errorf("starts like %s but its contents cannot be read", f.name), true)
		}
		return nil
	}
	for _, m := range ms {
		if m.dir || m.read == nil || m.name == "." || m.name == "" {
			continue
		}
		limit := min(w.lim.File, w.lim.Total-w.total)
		if limit <= 0 {
			w.warn(name, fmt.Errorf("more than %d MB unpacked: the rest is not checked", w.lim.Total>>20), false)
			return nil
		}
		b, rerr := m.read(limit + 1)
		damaged := ""
		if rerr != nil {
			if len(b) == 0 {
				w.warn(name+"/"+m.name, rerr, true)
				continue
			}
			damaged = rerr.Error() // check the part that unpacked
		}
		if int64(len(b)) > limit {
			w.warn(name+"/"+m.name, fmt.Errorf("bigger than %d MB: not checked", limit>>20), false)
			continue
		}
		w.total += int64(len(b))
		if err := w.walk(name+"/"+m.name, b, depth+1, damaged); err != nil {
			return err
		}
	}
	return nil
}

// detectContent names the format from the file's own header, as AmigaOS
// does: a text called History.lha is a text. The name only chooses between
// formats that share a header (a gzipped disk image is still gzip).
func detectContent(head []byte, size int64, ext string) *format {
	f := detect(head, size, ext)
	if f == nil || f.magic == nil || !f.magic(head, size) {
		// detect fell back on the name; a gzip header with an .adz name is fine
		if f != nil && f.name == "adz" && isGzip(head, size) {
			return f
		}
		return nil
	}
	if f.name == "lzx" && (len(head) < 4 || head[3] != 0) {
		return nil // "LZX" then a zero byte; a script starting with the word LZX is a text
	}
	return f
}

// bootBlock returns the first 1024 bytes of a floppy image, or nil.
func bootBlock(format string, data []byte) []byte {
	switch format {
	case "adf":
		if len(data) >= 1024 {
			return data[:1024]
		}
	case "adz":
		z, err := gzip.NewReader(bytes.NewReader(data))
		if err != nil {
			return nil
		}
		b := make([]byte, 1024)
		if _, err := io.ReadFull(z, b); err == nil {
			return b
		}
	case "dms":
		if len(data) > dmsLimit {
			return nil
		}
		a, err := dms.Read(data)
		if err != nil || a.Encrypted || len(a.Tracks) == 0 || a.Tracks[0].Number != 0 {
			return nil
		}
		if img := a.Image(); len(img) >= 1024 {
			return img[:1024]
		}
	}
	return nil
}
