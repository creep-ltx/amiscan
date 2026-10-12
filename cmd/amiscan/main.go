// AmiScan checks Amiga files, disk images and archives for Amiga viruses,
// using xvs.library (by Georg Wittmann, Virus Help Team) in a built-in 68000.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/creep-ltx/amiscan/internal/diz"
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
       amiscan -list          show every virus xvs.library knows

Disk images (ADF, ADZ, DMS, HDF) and archives (LhA, LZX, Zip, 7z, RAR, ...) are
opened, also inside each other, and every file and boot block in them is checked.

Exit status: 0 nothing found, 1 virus found, 2 something could not be checked.

options:
`, version)
	flag.PrintDefaults()
	fmt.Fprintf(os.Stderr, `
AmiScan needs xvs.library, the virus database, from the Virus Help Team:
  %s
Put xvs.library in %s (or name the folder with -libs or AMISCAN_LIBS).
`, xvsURL, defaultLibs()[0])
}

func main() {
	libs := flag.String("libs", "", "folder with xvs.library")
	jsonOut := flag.Bool("json", false, "one JSON object per line, for programs (BBX)")
	verbose := flag.Bool("v", false, "list every file checked, not only problems")
	list := flag.Bool("list", false, "list the viruses xvs.library knows")
	trace := flag.Bool("trace", false, "log every Amiga OS call (debugging)")
	showVersion := flag.Bool("version", false, "show the versions")
	flag.Usage = usage
	flag.Parse()

	dir, err := findLibs(*libs)
	if err != nil {
		fmt.Fprintln(os.Stderr, "amiscan:", err)
		fmt.Fprintf(os.Stderr, "Get xvs.library from %s\nand put it in %s\n", xvsURL, defaultLibs()[0])
		os.Exit(exitTrouble)
	}
	s, err := xvs.Open(dir)
	if err != nil {
		fmt.Fprintln(os.Stderr, "amiscan:", err)
		os.Exit(exitTrouble)
	}
	s.Machine().Trace = *trace
	if ok, err := s.SelfTest(); !ok || err != nil {
		fmt.Fprintf(os.Stderr, "amiscan: xvs.library failed its self test (%v); download it again from %s\n", err, xvsURL)
		os.Exit(exitTrouble)
	}
	switch {
	case *showVersion:
		fmt.Printf("AmiScan %s\n%s in %s\n", version, s.IDString, dir)
		return
	case *list:
		os.Exit(listViruses(s))
	}
	if flag.NArg() == 0 {
		usage()
		os.Exit(exitTrouble)
	}
	r := &reporter{s: s, json: *jsonOut, verbose: *verbose, start: time.Now()}
	if !r.json {
		fmt.Printf("AmiScan %s with %s\n", version, s.IDString)
	}
	for _, arg := range flag.Args() {
		r.scanPath(arg)
	}
	os.Exit(r.finish())
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
	Result string `json:"result"`           // "clean", "virus", "skipped", "error"
	Virus  string `json:"virus,omitempty"`  // virus name
	Type   string `json:"type,omitempty"`   // "boot virus", "link virus", ...; for clean items what it is
	Detail string `json:"detail,omitempty"` // why skipped or the error
}

type reporter struct {
	s       *xvs.Scanner
	json    bool
	verbose bool
	start   time.Time

	files, boots, viruses, skipped, errs int
}

var limits = diz.Limits{Depth: 6, Total: 1 << 30, File: 256 << 20}

const maxTopFile = 1 << 30

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
			r.report(finding{Path: p, Kind: "file", Result: "skipped", Detail: "bigger than 1 GB"})
			return nil
		}
		data, err := os.ReadFile(p)
		if err != nil {
			r.report(finding{Path: p, Kind: "file", Result: "error", Detail: err.Error()})
			return nil
		}
		diz.Walk(p, data, limits, r.check, func(path string, err error) {
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
		switch {
		case err != nil:
			f.Result, f.Detail = "error", err.Error()
		case res.Infected():
			f.Result, f.Virus, f.Type = "virus", res.Name, "boot virus"
		default:
			f.Result, f.Type = "clean", res.Name
		}
		r.report(f)
		return nil
	}
	f := finding{Path: it.Path, Kind: "file"}
	if len(it.Data) > xvs.MaxFileSize {
		f.Result, f.Detail = "skipped", fmt.Sprintf("bigger than %d MB, too big for xvs.library", xvs.MaxFileSize>>20)
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
	return nil
}

func (r *reporter) report(f finding) {
	switch {
	case f.Kind == "boot":
		r.boots++
	case f.Result != "skipped":
		r.files++
	}
	switch f.Result {
	case "virus":
		r.viruses++
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
		fmt.Printf("%s: VIRUS %s (%s)\n", f.Path, f.Virus, f.Type)
	case "error":
		fmt.Printf("%s: ERROR %s\n", f.Path, f.Detail)
	case "skipped":
		fmt.Printf("%s: not checked, %s\n", f.Path, f.Detail)
	default:
		if r.verbose {
			fmt.Printf("%s: ok (%s)\n", f.Path, strings.ToLower(f.Type))
		}
	}
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
			"summary": true, "files": r.files, "bootblocks": r.boots, "viruses": r.viruses,
			"skipped": r.skipped, "errors": r.errs, "seconds": took.Seconds(), "exit": code,
		})
		fmt.Println(string(b))
		return code
	}
	verdict := "no viruses found"
	if r.viruses == 1 {
		verdict = "1 VIRUS FOUND"
	} else if r.viruses > 1 {
		verdict = fmt.Sprintf("%d VIRUSES FOUND", r.viruses)
	}
	fmt.Printf("Checked %d files and %d boot blocks in %s: %s", r.files, r.boots, took, verdict)
	if r.skipped+r.errs > 0 {
		fmt.Printf(", %d not checked", r.skipped+r.errs)
	}
	fmt.Println(".")
	return code
}
