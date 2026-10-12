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
}

// Limits bound how far Walk unpacks, against archive bombs.
type Limits struct {
	Depth int   // archives inside archives, e.g. 4
	Total int64 // bytes unpacked in all, e.g. 512 MiB
	File  int64 // largest single member, e.g. 64 MiB
}

// Walk calls fn for data itself and, when data is an archive or disk image
// it can read, for its boot block and every file inside, recursively.
// Problems inside (a damaged archive, a limit reached) go to warn; Walk
// itself stops only when fn returns an error.
func Walk(name string, data []byte, lim Limits, fn func(Item) error, warn func(path string, err error)) error {
	w := &walker{lim: lim, fn: fn, warn: warn}
	return w.walk(name, data, 0)
}

type walker struct {
	lim   Limits
	total int64
	fn    func(Item) error
	warn  func(string, error)
}

func (w *walker) walk(name string, data []byte, depth int) (err error) {
	if err := w.fn(Item{Path: name, Data: data}); err != nil {
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
	f := detect(head, int64(len(data)), ext)
	if f == nil || f.name == "amigaexe" {
		return nil
	}
	if depth >= w.lim.Depth {
		w.warn(name, fmt.Errorf("%s inside %d archives: not unpacked", f.name, depth))
		return nil
	}
	defer func() {
		if r := recover(); r != nil { // a decoder bug on strange data must not stop the scan
			w.warn(name, fmt.Errorf("%s is damaged: %v", f.name, r))
		}
	}()
	if boot := bootBlock(f.name, data); boot != nil {
		if err := w.fn(Item{Path: name + "/(boot block)", Data: boot, Boot: true}); err != nil {
			return err
		}
	}
	ms, _, ok := listAll(bytes.NewReader(data), int64(len(data)), f)
	if !ok {
		// a program that only looks like a self-extractor, or a disk without
		// AmigaDOS files, is not a problem: the file itself was checked
		if f.name != "adf" && f.name != "adz" && f.name != "dms" && f.name != "sfx" && f.name != "hdf" {
			w.warn(name, fmt.Errorf("cannot read it as %s", f.name))
		}
		return nil
	}
	for _, m := range ms {
		if m.dir || m.read == nil || m.name == "." || m.name == "" {
			continue
		}
		limit := min(w.lim.File, w.lim.Total-w.total)
		if limit <= 0 {
			w.warn(name, fmt.Errorf("more than %d MB unpacked: the rest is not checked", w.lim.Total>>20))
			return nil
		}
		b, rerr := m.read(limit + 1)
		if rerr != nil {
			w.warn(name+"/"+m.name, rerr)
			continue
		}
		if int64(len(b)) > limit {
			w.warn(name+"/"+m.name, fmt.Errorf("bigger than %d MB: not checked", limit>>20))
			continue
		}
		w.total += int64(len(b))
		if err := w.walk(name+"/"+m.name, b, depth+1); err != nil {
			return err
		}
	}
	return nil
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
