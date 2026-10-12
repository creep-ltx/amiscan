// AmiScan checks Amiga files, disk images and archives for Amiga viruses,
// using xvs.library (by Georg Wittmann, Virus Help Team) in a built-in 68000.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"runtime/pprof"
	"strings"
	"time"

	"github.com/creep-ltx/amiscan/internal/amiga"
	"github.com/creep-ltx/amiscan/internal/bootdb"
	"github.com/creep-ltx/amiscan/internal/update"
	"github.com/creep-ltx/amiscan/internal/xfd"
	"github.com/creep-ltx/amiscan/internal/xvs"
)

const version = "0.1b1"

const xvsURL = "https://www.vht-dk.dk/amiga/xvs/xvs.htm"

func usage() {
	fmt.Fprintf(os.Stderr, `AmiScan %s - checks Amiga files, disks and archives for Amiga viruses

usage: amiscan [options] FILE|FOLDER ...
       amiscan -update        fetch the newest virus database and unpackers
       amiscan -list          show every virus xvs.library knows
       amiscan -version       show what is installed

Disk images (ADF, ADZ, DMS, HDF) and archives (LhA, LZX, Zip, 7z, RAR, ...) are
opened by their contents, also inside each other; packed programs (PowerPacker,
Imploder, XPK, ...) are unpacked; every file and boot block is checked.

Output (one of):
  (default)  a report at the end: viruses, damaged files and files not checked,
             each with where it is and why
  -bbs       one line per file, for BBS software:  CODE FILE MESSAGE
               0 FILE is clean
               1 FILE is infected with VIRUS[, VIRUS...]
               2 FILE is corrupted: WHERE: WHY
               3 FILE could not be checked: WHERE: WHY
  -json      one JSON object per finding, then a summary object

Exit status: the worst code found (0 clean, 1 virus, 2 corrupted, 3 not
checked). 3 also when AmiScan itself cannot run.

options:
`, version)
	flag.PrintDefaults()
	fmt.Fprintf(os.Stderr, `
AmiScan works with these parts, which "amiscan -update" downloads from where
their authors publish them, into %s
(or the folder named with -libs or AMISCAN_LIBS):

  xvs.library          the virus database (Virus Help Team)      needed
  xfdmaster.library    unpacks packed programs (Aminet)          recommended
  xpkmaster.library    unpacks XPK files (Aminet)                recommended
  boot block database  names boot blocks, knows more boot        recommended
                       viruses (Amiga Bootblock Reader, GitHub)

Without the recommended parts AmiScan still runs, but checks less.
`, defaultLibs()[0])
}

func main() {
	libs := flag.String("libs", "", "folder with xvs.library")
	jsonOut := flag.Bool("json", false, "one JSON object per finding, for programs")
	bbsOut := flag.Bool("bbs", false, "one line per file: code (0 clean, 1 virus, 2 corrupted, 3 not checked), file, message")
	showList := flag.String("show", "virus,damaged,unchecked", "what the report lists: virus, damaged, unchecked, clean, all or none")
	verbose := flag.Bool("v", false, "list the clean files too (same as -show all)")
	quiet := flag.Bool("q", false, "only the summary line (same as -show none)")
	list := flag.Bool("list", false, "list the viruses xvs.library knows")
	trace := flag.Bool("trace", false, "log every Amiga OS call (debugging)")
	showVersion := flag.Bool("version", false, "show the versions")
	doUpdate := flag.Bool("update", false, "download the newest virus database, unpackers and boot block database")
	force := flag.Bool("force", false, "with -update: download even when nothing changed")
	checkLib := flag.String("check-library", "", "") // internal: load one library from -libs, print its version
	flag.Usage = usage
	flag.Parse()
	if p := os.Getenv("AMISCAN_CPUPROFILE"); p != "" { // developers: where the time goes
		if f, err := os.Create(p); err == nil {
			pprof.StartCPUProfile(f)
			defer pprof.StopCPUProfile()
		}
	}

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
		os.Exit(codeUnchecked)
	}
	m := amiga.New(dir)
	s, err := xvs.Open(m)
	if err != nil {
		fmt.Fprintln(os.Stderr, "amiscan:", err)
		os.Exit(codeUnchecked)
	}
	// the emulated Amiga's own notes are for debugging, not for users
	if *trace {
		m.Trace = true
	} else {
		m.Log = nil
	}
	if ok, err := s.SelfTest(); !ok || err != nil {
		fmt.Fprintf(os.Stderr, "amiscan: xvs.library failed its self test (%v); download it again from %s\n", err, xvsURL)
		os.Exit(codeUnchecked)
	}
	// xfdmaster.library is optional: without it packed programs are checked
	// as they are
	var dec *xfd.Decruncher
	xfdNote := ""
	if _, err := os.Stat(filepath.Join(dir, "xfdmaster.library")); err == nil {
		if dec, err = xfd.Open(m); err != nil {
			fmt.Fprintln(os.Stderr, "amiscan: xfdmaster.library:", err)
			os.Exit(codeUnchecked)
		}
	} else {
		xfdNote = `xfdmaster.library not installed: packed programs are not unpacked ("amiscan -update" fetches it)`
	}
	// the Amiga Bootblock Reader database is optional too
	var bdb *bootdb.DB
	if _, err := os.Stat(filepath.Join(dir, bootdb.BrainFile)); err == nil {
		if bdb, err = bootdb.Load(dir); err != nil {
			fmt.Fprintln(os.Stderr, "amiscan: boot block database:", err)
			os.Exit(codeUnchecked)
		}
	}
	switch {
	case *showVersion:
		showVersions(m, dir, s, dec, bdb)
		return
	case *list:
		os.Exit(listViruses(s))
	}
	if flag.NArg() == 0 {
		usage()
		os.Exit(codeUnchecked)
	}
	show, err := parseShow(*showList)
	if err != nil {
		fmt.Fprintln(os.Stderr, "amiscan:", err)
		os.Exit(codeUnchecked)
	}
	if *verbose {
		show, _ = parseShow("all")
	}
	if *quiet {
		show = map[string]bool{}
	}
	mode := outText
	switch {
	case *jsonOut && *bbsOut:
		fmt.Fprintln(os.Stderr, "amiscan: -json and -bbs cannot be used together")
		os.Exit(codeUnchecked)
	case *jsonOut:
		mode = outJSON
	case *bbsOut:
		mode = outBBS
	}
	r := newReporter(mode, show)
	sc := &scanner{s: s, dec: dec, bdb: bdb, r: r}
	if mode == outText {
		fmt.Printf("AmiScan %s with %s\n", version, s.IDString)
	}
	if xfdNote != "" && mode != outJSON {
		fmt.Fprintln(os.Stderr, "amiscan: "+xfdNote)
	}
	if t := update.LastChecked(dir, update.XVS.Name); !t.IsZero() && time.Since(t) > 30*24*time.Hour && mode != outJSON {
		fmt.Fprintf(os.Stderr, "amiscan: no update check for %d days; run \"amiscan -update\"\n", int(time.Since(t).Hours()/24))
	}
	for _, arg := range flag.Args() {
		sc.scanPath(arg)
	}
	code := r.finish()
	pprof.StopCPUProfile()
	os.Exit(code)
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
		return codeUnchecked
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	u := &update.Updater{Dir: dir, Log: func(s string) { fmt.Println("  " + s) }}
	update.XVS.Version = libraryVersion("xvs.library")
	update.XFD.Version = libraryVersion("xfdmaster.library")
	update.XPK.Version = libraryVersion("xpkmaster.library")
	update.BootBrain.Version = bootDBVersion(false)
	update.BootSearch.Version = bootDBVersion(true)
	fmt.Printf("Updating %s\n", dir)
	code := codePass
	for _, src := range []*update.Source{update.XVS, update.XFD, update.XPK, update.BootBrain, update.BootSearch} {
		results, err := u.Update(ctx, src, force)
		for _, r := range results {
			fmt.Println(r)
		}
		if err != nil {
			fmt.Fprintln(os.Stderr, "amiscan:", err)
			code = codeUnchecked
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
			return codeUnchecked
		}
		if ok, err := s.SelfTest(); !ok || err != nil {
			fmt.Fprintln(os.Stderr, "self test failed", err)
			return codeUnchecked
		}
		id = s.IDString
	case "xfdmaster.library":
		d, err := xfd.Open(m)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return codeUnchecked
		}
		if out, _, _ := d.Decrunch(make([]byte, 64)); out != nil {
			fmt.Fprintln(os.Stderr, "xfdmaster unpacks zeros: broken")
			return codeUnchecked
		}
		id = d.IDString
	case "xpkmaster.library":
		lib, err := m.LoadLibrary(filepath.Join(dir, name))
		if err == nil {
			lib, err = m.OpenLibrary(lib, 0)
		}
		if err != nil || lib == 0 {
			fmt.Fprintln(os.Stderr, "xpkmaster.library does not start", err)
			return codeUnchecked
		}
		id = m.Latin1String(m.Read32(lib + amiga.Library_lib_IdString))
	default:
		fmt.Fprintln(os.Stderr, "unknown library", name)
		return codeUnchecked
	}
	fmt.Println(id)
	return codePass
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

// showVersions lists the parts AmiScan works with and what each does.
func showVersions(m *amiga.Machine, dir string, s *xvs.Scanner, dec *xfd.Decruncher, bdb *bootdb.DB) {
	missing := "not installed"
	ver := func(id string) string {
		if v := idVersionRe.FindString(id); v != "" {
			return v
		}
		return id
	}
	fmt.Printf("AmiScan %s\n\nParts in %s:\n", version, dir)
	line := func(name, state, what string) { fmt.Printf("  %-20s %-22s %s\n", name, state, what) }
	line("xvs.library", ver(s.IDString), "the virus database")
	xfdState, xpkState := missing, missing
	if dec != nil {
		xfdState = ver(dec.IDString)
	}
	line("xfdmaster.library", xfdState, "unpacks packed programs")
	if _, err := os.Stat(filepath.Join(dir, "xpkmaster.library")); err == nil {
		lib, err := m.LoadLibrary(filepath.Join(dir, "xpkmaster.library"))
		if err == nil {
			lib, err = m.OpenLibrary(lib, 0)
		}
		if err == nil && lib != 0 {
			xpkState = ver(m.Latin1String(m.Read32(lib + amiga.Library_lib_IdString)))
		} else {
			xpkState = "installed but does not start"
		}
	}
	line("xpkmaster.library", xpkState, "unpacks XPK files")
	if bdb != nil {
		brain, search := bdb.Counts()
		line("boot block database", fmt.Sprintf("%d boot blocks", brain), fmt.Sprintf("names boot blocks (and %d byte patterns)", search))
	} else {
		line("boot block database", missing, "names boot blocks, knows more boot viruses")
	}
	if dec == nil || bdb == nil || xpkState == missing {
		fmt.Println("\nAmiScan checks less without the missing parts; \"amiscan -update\" fetches them.")
	}
}

// parseShow reads the -show list.
func parseShow(list string) (map[string]bool, error) {
	show := map[string]bool{}
	for _, w := range strings.Split(list, ",") {
		switch w = strings.TrimSpace(strings.ToLower(w)); w {
		case "", "none":
		case "all":
			for _, k := range []string{resVirus, resDamaged, resUnchecked, resClean} {
				show[k] = true
			}
		case "virus", "viruses", "infected":
			show[resVirus] = true
		case "damaged", "corrupted", "corrupt":
			show[resDamaged] = true
		case "unchecked", "skipped", "notchecked":
			show[resUnchecked] = true
		case "clean", "ok":
			show[resClean] = true
		default:
			return nil, fmt.Errorf("-show: unknown kind %q (virus, damaged, unchecked, clean, all, none)", w)
		}
	}
	return show, nil
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
			return codeUnchecked
		}
		fmt.Printf("%s (%d):\n", k.name, len(names))
		for _, n := range names {
			fmt.Println("  " + n)
		}
	}
	return codePass
}
