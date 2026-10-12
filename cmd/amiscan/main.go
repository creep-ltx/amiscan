// AmiScan checks Amiga files, disk images and archives for Amiga viruses,
// using xvs.library (by Georg Wittmann, Virus Help Team) in a built-in 68000.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/creep-ltx/amiscan/internal/amiga"
	"github.com/creep-ltx/amiscan/internal/bootdb"
	"github.com/creep-ltx/amiscan/internal/diz"
	"github.com/creep-ltx/amiscan/internal/update"
	"github.com/creep-ltx/amiscan/internal/xfd"
	"github.com/creep-ltx/amiscan/internal/xvs"
)

const version = "0.1b1"

const xvsURL = "https://www.vht-dk.dk/amiga/xvs/xvs.htm"

// Exit codes.
const (
	exitClean   = 0
	exitVirus   = 1
	exitTrouble = 2
)

func usage() {
	fmt.Fprintf(os.Stderr, `AmiScan %s - checks Amiga files, disks and archives for Amiga viruses

usage: amiscan [options] FILE|FOLDER ...
       amiscan -update        fetch the newest xvs.library (the virus database)
       amiscan -list          show every virus xvs.library knows

Disk images (ADF, ADZ, DMS, HDF) and archives (LhA, LZX, Zip, 7z, RAR, ...) are
opened, also inside each other, and every file and boot block in them is checked.

Exit status: 0 nothing found, 1 virus found, 2 something could not be checked.

options:
`, version)
	flag.PrintDefaults()
	fmt.Fprintf(os.Stderr, `
AmiScan needs xvs.library, the virus database, from the Virus Help Team
(%s). "amiscan -update" fetches it into
%s (or the folder named with -libs or AMISCAN_LIBS).
`, xvsURL, defaultLibs()[0])
}

func main() {
	libs := flag.String("libs", "", "folder with xvs.library")
	jsonOut := flag.Bool("json", false, "one JSON object per line, for programs (BBX)")
	verbose := flag.Bool("v", false, "list every file checked, not only problems")
	list := flag.Bool("list", false, "list the viruses xvs.library knows")
	trace := flag.Bool("trace", false, "log every Amiga OS call (debugging)")
	showVersion := flag.Bool("version", false, "show the versions")
	doUpdate := flag.Bool("update", false, "download the newest xvs.library (and any key files it needs)")
	force := flag.Bool("force", false, "with -update: download even when nothing changed")
	checkLib := flag.String("check-library", "", "") // internal: load one library from -libs, print its version
	flag.Usage = usage
	flag.Parse()

	if *checkLib != "" {
		os.Exit(checkLibrary(*libs, *checkLib))
	}
	if *doUpdate {
		os.Exit(runUpdate(*libs, *force))
	}
	dir, err := findLibs(*libs)
	if err != nil {
		fmt.Fprintln(os.Stderr, "amiscan:", err)
		fmt.Fprintln(os.Stderr, `Run "amiscan -update" to download it.`)
		os.Exit(exitTrouble)
	}
	m := amiga.New(dir)
	s, err := xvs.Open(m)
	if err != nil {
		fmt.Fprintln(os.Stderr, "amiscan:", err)
		os.Exit(exitTrouble)
	}
	s.Machine().Trace = *trace
	if ok, err := s.SelfTest(); !ok || err != nil {
		fmt.Fprintf(os.Stderr, "amiscan: xvs.library failed its self test (%v); download it again from %s\n", err, xvsURL)
		os.Exit(exitTrouble)
	}
	// xfdmaster.library is optional: without it packed programs are checked
	// as they are
	var dec *xfd.Decruncher
	xfdNote := ""
	if _, err := os.Stat(filepath.Join(dir, "xfdmaster.library")); err == nil {
		if dec, err = xfd.Open(m); err != nil {
			fmt.Fprintln(os.Stderr, "amiscan: xfdmaster.library:", err)
			os.Exit(exitTrouble)
		}
	} else {
		xfdNote = `xfdmaster.library not installed: packed programs are not unpacked ("amiscan -update" fetches it)`
	}
	// the Amiga Bootblock Reader database is optional too
	var bdb *bootdb.DB
	if _, err := os.Stat(filepath.Join(dir, bootdb.BrainFile)); err == nil {
		if bdb, err = bootdb.Load(dir); err != nil {
			fmt.Fprintln(os.Stderr, "amiscan: boot block database:", err)
			os.Exit(exitTrouble)
		}
	}
	switch {
	case *showVersion:
		fmt.Printf("AmiScan %s\n%s in %s\n", version, s.IDString, dir)
		if dec != nil {
			fmt.Println(dec.IDString)
		} else {
			fmt.Println(xfdNote)
		}
		if bdb != nil {
			fmt.Printf("Amiga Bootblock Reader database: %d boot blocks\n", bdb.Size())
		} else {
			fmt.Println(`boot block database not installed ("amiscan -update" fetches it)`)
		}
		return
	case *list:
		os.Exit(listViruses(s))
	}
	if flag.NArg() == 0 {
		usage()
		os.Exit(exitTrouble)
	}
	r := &reporter{s: s, dec: dec, bdb: bdb, json: *jsonOut, verbose: *verbose, start: time.Now()}
	if !r.json {
		fmt.Printf("AmiScan %s with %s\n", version, s.IDString)
		if xfdNote != "" {
			fmt.Fprintln(os.Stderr, "amiscan: "+xfdNote)
		}
		if t := update.LastChecked(dir, update.XVS.Name); !t.IsZero() && time.Since(t) > 30*24*time.Hour {
			fmt.Fprintf(os.Stderr, "amiscan: no update check for %d days; run \"amiscan -update\"\n", int(time.Since(t).Hours()/24))
		}
	}
	for _, arg := range flag.Args() {
		r.scanPath(arg)
	}
	os.Exit(r.finish())
}

// runUpdate fetches xvs.library into the libs folder: the one named, else
// the one in use, else the first default.
func runUpdate(flagDir string, force bool) int {
	dir := flagDir
	if dir == "" {
		if found, err := findLibs(""); err == nil && update.Writable(found) == nil {
			dir = found
		} else {
			dir = defaultLibs()[0]
		}
	}
	if err := update.Writable(dir); err != nil {
		fmt.Fprintf(os.Stderr, "amiscan: cannot write to %s (%v); name another folder with -libs\n", dir, err)
		return exitTrouble
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	u := &update.Updater{Dir: dir, Log: func(s string) { fmt.Println("  " + s) }}
	update.XVS.Version = libraryVersion("xvs.library")
	update.XFD.Version = libraryVersion("xfdmaster.library")
	update.BootBrain.Version = bootDBVersion(false)
	update.BootSearch.Version = bootDBVersion(true)
	fmt.Printf("Updating %s\n", dir)
	code := exitClean
	for _, src := range []*update.Source{update.XVS, update.XFD, update.BootBrain, update.BootSearch} {
		results, err := u.Update(ctx, src, force)
		for _, r := range results {
			fmt.Println(r)
		}
		if err != nil {
			fmt.Fprintln(os.Stderr, "amiscan:", err)
			code = exitTrouble
		}
	}
	return code
}

// bootDBVersion loads the boot block database in dir and counts the brain
// file's entries, or the search list's.
func bootDBVersion(search bool) func(string) (string, error) {
	return func(dir string) (string, error) {
		db, err := bootdb.Load(dir)
		if err != nil {
			return "", err
		}
		brain, list := db.Counts()
		if search {
			if list == 0 {
				return "", errors.New("the search list is empty or unreadable")
			}
			return fmt.Sprintf("%d byte patterns", list), nil
		}
		return fmt.Sprintf("%d boot blocks", brain), nil
	}
}

// checkLibrary loads one library from dir in a fresh emulated Amiga and
// prints its id string; xvs.library must also pass its self test.
func checkLibrary(dir, name string) int {
	m := amiga.New(dir)
	m.Log = nil
	var id string
	switch name {
	case "xvs.library":
		s, err := xvs.Open(m)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return exitTrouble
		}
		if ok, err := s.SelfTest(); !ok || err != nil {
			fmt.Fprintln(os.Stderr, "self test failed", err)
			return exitTrouble
		}
		id = s.IDString
	case "xfdmaster.library":
		d, err := xfd.Open(m)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return exitTrouble
		}
		if out, _, _ := d.Decrunch(make([]byte, 64)); out != nil {
			fmt.Fprintln(os.Stderr, "xfdmaster unpacks zeros: broken")
			return exitTrouble
		}
		id = d.IDString
	default:
		fmt.Fprintln(os.Stderr, "unknown library", name)
		return exitTrouble
	}
	fmt.Println(id)
	return exitClean
}

var idVersionRe = regexp.MustCompile(`\d+\.\d+ \([^)]*\)`)

// libraryVersion checks a library in a second amiscan (one emulated Amiga
// per process) and returns its version, e.g. "33.49 (11.04.2025)".
func libraryVersion(name string) func(dir string) (string, error) {
	return func(dir string) (string, error) {
		exe, err := os.Executable()
		if err != nil {
			return "", err
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		out, err := exec.CommandContext(ctx, exe, "-libs", dir, "-check-library", name).CombinedOutput()
		if err != nil {
			return "", fmt.Errorf("%s", strings.TrimSpace(string(out)))
		}
		v := idVersionRe.FindString(string(out))
		if v == "" {
			return "", fmt.Errorf("no version in %q", out)
		}
		return v, nil
	}
}

// defaultLibs are the folders searched for xvs.library, in order.
func defaultLibs() []string {
	var dirs []string
	if d := os.Getenv("AMISCAN_LIBS"); d != "" {
		dirs = append(dirs, d)
	}
	data := os.Getenv("XDG_DATA_HOME")
	if data == "" {
		if home, err := os.UserHomeDir(); err == nil {
			data = filepath.Join(home, ".local", "share")
		}
	}
	if data != "" {
		dirs = append(dirs, filepath.Join(data, "amiscan", "libs"))
	}
	if exe, err := os.Executable(); err == nil {
		dirs = append(dirs, filepath.Join(filepath.Dir(exe), "libs"))
	}
	return append(dirs, "/usr/local/share/amiscan/libs", "/usr/share/amiscan/libs")
}

func findLibs(flagDir string) (string, error) {
	if flagDir != "" {
		if _, err := os.Stat(filepath.Join(flagDir, "xvs.library")); err != nil {
			return "", fmt.Errorf("no xvs.library in %s", flagDir)
		}
		return flagDir, nil
	}
	for _, d := range defaultLibs() {
		if _, err := os.Stat(filepath.Join(d, "xvs.library")); err == nil {
			return d, nil
		}
	}
	return "", errors.New("xvs.library not found")
}

func listViruses(s *xvs.Scanner) int {
	for _, k := range []struct {
		kind uint32
		name string
	}{{xvs.ListBoot, "Boot viruses"}, {xvs.ListData, "Data viruses"}, {xvs.ListFile, "File viruses"}, {xvs.ListLink, "Link viruses"}} {
		names, err := s.VirusList(k.kind)
		if err != nil {
			fmt.Fprintln(os.Stderr, "amiscan:", err)
			return exitTrouble
		}
		fmt.Printf("%s (%d):\n", k.name, len(names))
		for _, n := range names {
			fmt.Println("  " + n)
		}
	}
	return exitClean
}

// ---- scanning and reporting

type finding struct {
	Path   string `json:"path"`
	Kind   string `json:"kind"`             // "file" or "boot"
	Result string `json:"result"`           // "clean", "virus", "damaged", "skipped", "error"
	Virus  string `json:"virus,omitempty"`  // virus name
	Type   string `json:"type,omitempty"`   // "boot virus", "link virus", ...; for clean items what it is
	Detail string `json:"detail,omitempty"` // why skipped or the error
	// FoundBy is "xvs" or "bootblock database" for a virus; for a boot
	// block the database names, Type holds its name and class.
	FoundBy string `json:"found_by,omitempty"`
	top     string // the file on disk it is in
	// Damaged: the archive could not give the whole file (why); the part
	// that unpacked was checked, which is what LhA itself would write out.
	Damaged string `json:"damaged,omitempty"`
}

type reporter struct {
	s       *xvs.Scanner
	dec     *xfd.Decruncher // nil without xfdmaster.library
	bdb     *bootdb.DB      // nil without the boot block database
	json    bool
	verbose bool
	start   time.Time

	files, boots, unpacked, viruses, skipped, errs, damaged int
	found                                                   []finding // the viruses, for the list at the end
	top                                                     string    // the file on disk being checked
}

// maxLayers is how many times a file packed inside a packed file is unpacked.
const maxLayers = 5

var limits = diz.Limits{Depth: 8, Total: 8 << 30, File: xvs.MaxFileSize}

const maxTopFile = 8 << 30 // a hard disk image; its files are checked one by one

func (r *reporter) scanPath(arg string) {
	err := filepath.WalkDir(arg, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			r.report(finding{Path: p, Kind: "file", Result: "error", Detail: err.Error()})
			return nil
		}
		if d.IsDir() || !d.Type().IsRegular() {
			return nil
		}
		if info, err := d.Info(); err == nil && info.Size() > maxTopFile {
			r.report(finding{Path: p, Kind: "file", Result: "skipped", Detail: "bigger than 8 GB"})
			return nil
		}
		data, err := os.ReadFile(p)
		if err != nil {
			r.report(finding{Path: p, Kind: "file", Result: "error", Detail: err.Error()})
			return nil
		}
		r.top = p
		diz.Walk(p, data, limits, r.check, func(path string, err error, damaged bool) {
			if damaged {
				r.report(finding{Path: path, Kind: "file", Result: "damaged", Detail: err.Error()})
				return
			}
			r.report(finding{Path: path, Kind: "file", Result: "skipped", Detail: err.Error()})
		})
		return nil
	})
	if err != nil {
		r.report(finding{Path: arg, Kind: "file", Result: "error", Detail: err.Error()})
	}
}

var fileTypes = map[uint8]string{
	xvs.FileEmpty: "empty file", xvs.FileData: "data file", xvs.FileExe: "program",
	xvs.FileDataVirus: "data virus", xvs.FileVirus: "file virus", xvs.FileLinkVirus: "link virus",
}

func (r *reporter) check(it diz.Item) error {
	if it.Boot {
		res, err := r.s.CheckBootblock(it.Data)
		f := finding{Path: it.Path, Kind: "boot"}
		var known *bootdb.Entry
		if r.bdb != nil {
			known = r.bdb.Match(it.Data)
		}
		switch {
		case err != nil:
			f.Result, f.Detail = "error", err.Error()
		case res.Infected():
			f.Result, f.Virus, f.Type, f.FoundBy = "virus", res.Name, "boot virus", "xvs"
		case known != nil && known.IsVirus():
			// xvs does not know it; the database does
			f.Result, f.Virus, f.Type, f.FoundBy = "virus", known.Name, "boot virus", "bootblock database"
		case known != nil:
			f.Result, f.Type = "clean", known.Name+" ("+known.ClassName()+")"
		default:
			f.Result, f.Type = "clean", res.Name
		}
		r.report(f)
		return nil
	}
	f := finding{Path: it.Path, Kind: "file", Damaged: it.Damaged}
	if len(it.Data) > xvs.MaxFileSize {
		f.Result, f.Detail = "skipped", fmt.Sprintf("bigger than %d MB, too big for the emulated Amiga", xvs.MaxFileSize>>20)
		r.report(f)
		return nil
	}
	res, err := r.s.CheckFile(it.Data)
	switch {
	case err != nil:
		f.Result, f.Detail = "error", err.Error()
	case res.Infected():
		f.Result, f.Virus, f.Type = "virus", res.Name, fileTypes[res.Type]
	default:
		f.Result, f.Type = "clean", fileTypes[res.Type]
	}
	r.report(f)
	r.unpack(it, 0, f.Result == "virus")
	return nil
}

// unpack decrunches a packed file with xfdmaster and checks what is inside.
// A file already found infected is not reported again when it will not
// unpack: a link virus usually breaks the packed file's structure.
func (r *reporter) unpack(it diz.Item, layer int, infected bool) {
	if r.dec == nil || layer >= maxLayers {
		return
	}
	out, packer, err := r.dec.Decrunch(it.Data)
	if err != nil && infected {
		return
	}
	inside := it.Path + " (packed contents)"
	if err != nil && it.Damaged != "" {
		// a packed file cut short by a damaged archive cannot unpack; it is
		// already counted as damaged and checked as far as it goes
		return
	}
	switch {
	case errors.Is(err, xfd.ErrLocked):
		r.report(finding{Path: inside, Kind: "file", Result: "skipped", Detail: packer + " needs a password to unpack"})
		return
	case err != nil:
		r.report(finding{Path: inside, Kind: "file", Result: "skipped", Detail: packer + " will not unpack: " + err.Error()})
		return
	case out == nil:
		return
	}
	r.unpacked++
	inner := diz.Item{Path: it.Path + " (unpacked " + packer + ")", Data: out, Damaged: it.Damaged}
	f := finding{Path: inner.Path, Kind: "file"}
	res, err := r.s.CheckFile(out)
	switch {
	case err != nil:
		f.Result, f.Detail = "error", err.Error()
	case res.Infected():
		f.Result, f.Virus, f.Type = "virus", res.Name, fileTypes[res.Type]
	default:
		f.Result, f.Type = "clean", fileTypes[res.Type]
	}
	r.report(f)
	r.unpack(inner, layer+1, f.Result == "virus")
}

func (r *reporter) report(f finding) {
	switch {
	case f.Kind == "boot":
		r.boots++
	case f.Result != "skipped" && f.Result != "damaged":
		r.files++
	}
	if f.Damaged != "" || f.Result == "damaged" {
		r.damaged++
	}
	switch f.Result {
	case "virus":
		r.viruses++
		f.top = r.top
		r.found = append(r.found, f)
	case "skipped":
		r.skipped++
	case "error":
		r.errs++
	}
	if r.json {
		b, _ := json.Marshal(f)
		fmt.Println(string(b))
		return
	}
	switch f.Result {
	case "virus":
		by := ""
		if f.FoundBy == "bootblock database" {
			by = ", found by the boot block database"
		}
		fmt.Printf("%s: VIRUS %s (%s%s)\n", f.Path, f.Virus, f.Type, by)
	case "error":
		fmt.Printf("%s: ERROR %s\n", f.Path, f.Detail)
	case "skipped":
		fmt.Printf("%s: NOT CHECKED, %s\n", f.Path, f.Detail)
	case "damaged":
		if r.verbose {
			fmt.Printf("%s: damaged, %s (the file itself was checked)\n", f.Path, f.Detail)
		}
	default:
		if f.Damaged != "" {
			if r.verbose {
				fmt.Printf("%s: ok as far as it unpacks (damaged: %s)\n", f.Path, f.Damaged)
			}
			return
		}
		if r.verbose {
			t := f.Type
			if f.Kind != "boot" {
				t = strings.ToLower(t)
			}
			fmt.Printf("%s: ok (%s)\n", f.Path, t)
		}
	}
}

// listViruses repeats every virus at the end, grouped by the file on disk
// that holds it (the upload to delete), with where inside it was found.
func (r *reporter) listViruses() {
	if len(r.found) == 0 {
		return
	}
	fmt.Printf("\nViruses found:\n")
	last := ""
	for _, f := range r.found {
		if f.top != last {
			fmt.Printf("\n  %s\n", f.top)
			last = f.top
		}
		inside := strings.TrimPrefix(strings.TrimPrefix(f.Path, f.top), "/")
		if inside == "" {
			inside = "(the file itself)"
		}
		fmt.Printf("      %-40s %s (%s)\n", inside, f.Virus, f.Type)
	}
	fmt.Println()
}

func (r *reporter) finish() int {
	took := time.Since(r.start).Round(time.Millisecond)
	code := exitClean
	if r.errs > 0 || r.skipped > 0 {
		code = exitTrouble
	}
	if r.viruses > 0 {
		code = exitVirus
	}
	if r.json {
		b, _ := json.Marshal(map[string]any{
			"summary": true, "files": r.files, "bootblocks": r.boots, "unpacked": r.unpacked, "viruses": r.viruses,
			"skipped": r.skipped, "errors": r.errs, "damaged": r.damaged, "seconds": took.Seconds(), "exit": code,
		})
		fmt.Println(string(b))
		return code
	}
	r.listViruses()
	verdict := "no viruses found"
	if r.viruses == 1 {
		verdict = "1 VIRUS FOUND"
	} else if r.viruses > 1 {
		verdict = fmt.Sprintf("%d VIRUSES FOUND", r.viruses)
	}
	plural := func(n int, one, many string) string {
		if n == 1 {
			return "1 " + one
		}
		return fmt.Sprintf("%d %s", n, many)
	}
	unpacked := ""
	if r.unpacked > 0 {
		unpacked = fmt.Sprintf(" (%d of them unpacked)", r.unpacked)
	}
	fmt.Printf("Checked %s%s and %s in %s: %s", plural(r.files, "file", "files"), unpacked, plural(r.boots, "boot block", "boot blocks"), took, verdict)
	if r.skipped+r.errs > 0 {
		fmt.Printf(", %d not checked", r.skipped+r.errs)
	}
	fmt.Println(".")
	if r.damaged > 0 {
		fmt.Printf("%s damaged in their archives: checked as far as they unpack", plural(r.damaged, "file was", "files were"))
		if !r.verbose {
			fmt.Print(" (-v lists them)")
		}
		fmt.Println(".")
	}
	return code
}
