package main

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/creep-ltx/amiscan/internal/bootdb"
	"github.com/creep-ltx/amiscan/internal/diz"
	"github.com/creep-ltx/amiscan/internal/xfd"
	"github.com/creep-ltx/amiscan/internal/xvs"
)

// What became of one file or boot block.
const (
	resVirus     = "virus"
	resDamaged   = "damaged"   // broken; checked as far as it goes
	resUnchecked = "unchecked" // could not be checked (or not all of it)
	resClean     = "clean"
)

// finding is one checked file, boot block or problem.
type finding struct {
	Top    string `json:"file"`             // the file on disk
	Path   string `json:"path"`             // the file on disk, then where inside it
	Kind   string `json:"kind"`             // "file" or "boot"
	Result string `json:"result"`           // resVirus, resDamaged, resUnchecked, resClean
	Virus  string `json:"virus,omitempty"`  // virus name
	Type   string `json:"type,omitempty"`   // "boot virus", "link virus", ...; for clean items what it is
	Reason string `json:"reason,omitempty"` // why damaged or not checked
	// FoundBy is "xvs" or "bootblock database" for a virus.
	FoundBy string `json:"found_by,omitempty"`
}

// scanner checks files and hands every finding to the reporter.
type scanner struct {
	s   *xvs.Scanner
	dec *xfd.Decruncher // nil without xfdmaster.library
	bdb *bootdb.DB      // nil without the boot block database
	r   *reporter
	top string // the file on disk being checked
}

// maxLayers is how many times a file packed inside a packed file is unpacked.
const maxLayers = 5

var limits = diz.Limits{Depth: 8, Total: 8 << 30, File: xvs.MaxFileSize}

const maxTopFile = 8 << 30 // a hard disk image; its files are checked one by one

func (sc *scanner) add(f finding) {
	f.Top = sc.top
	sc.r.add(f)
}

// scanPath checks a file, or every file in a folder.
func (sc *scanner) scanPath(arg string) {
	err := filepath.WalkDir(arg, func(p string, d fs.DirEntry, err error) error {
		sc.top = p
		if err != nil {
			sc.add(finding{Path: p, Kind: "file", Result: resUnchecked, Reason: err.Error()})
			return nil
		}
		if d.IsDir() || !d.Type().IsRegular() {
			return nil
		}
		sc.r.begin(p)
		defer sc.r.end(p)
		if info, err := d.Info(); err == nil && info.Size() > maxTopFile {
			sc.add(finding{Path: p, Kind: "file", Result: resUnchecked, Reason: "bigger than 8 GB"})
			return nil
		}
		data, err := os.ReadFile(p)
		if err != nil {
			sc.add(finding{Path: p, Kind: "file", Result: resUnchecked, Reason: err.Error()})
			return nil
		}
		diz.Walk(p, data, limits, sc.check, func(path string, err error, damaged bool) {
			res := resUnchecked
			if damaged {
				res = resDamaged
			}
			sc.add(finding{Path: path, Kind: "file", Result: res, Reason: err.Error()})
		})
		return nil
	})
	if err != nil {
		sc.top = arg
		sc.add(finding{Path: arg, Kind: "file", Result: resUnchecked, Reason: err.Error()})
	}
}

var fileTypes = map[uint8]string{
	xvs.FileEmpty: "empty file", xvs.FileData: "data file", xvs.FileExe: "program",
	xvs.FileDataVirus: "data virus", xvs.FileVirus: "file virus", xvs.FileLinkVirus: "link virus",
}

func (sc *scanner) check(it diz.Item) error {
	if it.Boot {
		sc.add(sc.checkBoot(it))
		return nil
	}
	f := sc.checkFile(it.Path, it.Data, it.Damaged)
	sc.add(f)
	if f.Result != resUnchecked {
		sc.unpack(it, 0, f.Result == resVirus)
	}
	return nil
}

func (sc *scanner) checkBoot(it diz.Item) finding {
	res, err := sc.s.CheckBootblock(it.Data)
	f := finding{Path: it.Path, Kind: "boot"}
	var known *bootdb.Entry
	if sc.bdb != nil {
		known = sc.bdb.Match(it.Data)
	}
	switch {
	case err != nil:
		f.Result, f.Reason = resUnchecked, err.Error()
	case res.Infected():
		f.Result, f.Virus, f.Type, f.FoundBy = resVirus, res.Name, "boot virus", "xvs"
	case known != nil && known.IsVirus():
		// xvs does not know it; the database does
		f.Result, f.Virus, f.Type, f.FoundBy = resVirus, known.Name, "boot virus", "bootblock database"
	case known != nil:
		f.Result, f.Type = resClean, known.Name+" ("+known.ClassName()+")"
	default:
		f.Result, f.Type = resClean, res.Name
	}
	return f
}

// checkFile asks xvs.library about one file. damaged is why the archive
// could not give all of it, if so.
func (sc *scanner) checkFile(path string, data []byte, damaged string) finding {
	f := finding{Path: path, Kind: "file"}
	if len(data) > xvs.MaxFileSize {
		f.Result, f.Reason = resUnchecked, fmt.Sprintf("bigger than %d MB, too big for the emulated Amiga", xvs.MaxFileSize>>20)
		return f
	}
	res, err := sc.s.CheckFile(data)
	switch {
	case err != nil:
		f.Result, f.Reason = resUnchecked, err.Error()
	case res.Infected():
		f.Result, f.Virus, f.Type = resVirus, res.Name, fileTypes[res.Type]
		if damaged != "" {
			f.Reason = "also damaged: " + damaged
		}
	case damaged != "" && uniform(data):
		// Nothing in it: BBS adverts are archive entries whose name is the
		// advert and whose few bytes of "data" claim megabytes of nothing.
		f.Result, f.Type = resClean, "no contents: a fake archive entry, as BBS adverts use ("+damaged+")"
	case damaged != "":
		f.Result, f.Type, f.Reason = resDamaged, fileTypes[res.Type], damaged
	default:
		f.Result, f.Type = resClean, fileTypes[res.Type]
	}
	return f
}

// uniform reports whether data is empty or one byte value repeated.
func uniform(data []byte) bool {
	for _, b := range data {
		if b != data[0] {
			return false
		}
	}
	return true
}

// unpack decrunches a packed file with xfdmaster and checks what is inside.
func (sc *scanner) unpack(it diz.Item, layer int, infected bool) {
	if sc.dec == nil || layer >= maxLayers {
		return
	}
	out, packer, err := sc.dec.Decrunch(it.Data)
	if err != nil && (infected || it.Damaged != "") {
		// a link virus usually breaks the packing, and a file cut short by
		// a damaged archive cannot unpack: both are reported already
		return
	}
	inside := it.Path + " (packed contents)"
	var xe *xfd.Error
	switch {
	case errors.Is(err, xfd.ErrLocked):
		sc.add(finding{Path: inside, Kind: "file", Result: resUnchecked, Reason: packer + " needs a password to unpack"})
		return
	case errors.As(err, &xe) && xe.Corrupt():
		sc.add(finding{Path: inside, Kind: "file", Result: resDamaged, Reason: packer + " data is broken (" + err.Error() + "); the packed file itself was checked"})
		return
	case err != nil:
		sc.add(finding{Path: inside, Kind: "file", Result: resUnchecked, Reason: packer + " will not unpack here: " + err.Error()})
		return
	case out == nil:
		return
	}
	sc.r.unpacked++
	inner := diz.Item{Path: it.Path + " (unpacked " + packer + ")", Data: out, Damaged: it.Damaged}
	f := sc.checkFile(inner.Path, out, it.Damaged)
	sc.add(f)
	sc.unpack(inner, layer+1, f.Result == resVirus)
}
