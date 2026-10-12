// Package update fetches the files AmiScan runs on (xvs.library and any
// free key files) from where their authors publish them, checks them and
// puts them in the libs folder.
package update

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/creep-ltx/amiscan/internal/diz/lha"
	_ "golang.org/x/crypto/x509roots/fallback" // HTTPS works even without system certificates
)

// Source is one archive AmiScan keeps up to date.
type Source struct {
	Name string // shown to the user, e.g. "xvs.library"
	URL  string // an LhA archive
	// Files maps an archive member (path, any case) to its name in the libs folder.
	Files map[string]string
	// Dirs maps an archive folder (path, any case) to a folder in the libs
	// folder; its files (not subfolders) are installed there, replacing
	// the whole folder.
	Dirs map[string]string
	// Signed maps a libs file name to the archive member holding its PGP 2
	// signature by Signer. A file listed here is never installed unsigned.
	Signed map[string]string
	Signer *Key
	// Needs are other sources this one cannot work without, such as a free
	// key file. They are fetched when their files are missing, not updated.
	Needs []*Source
	// Version reports the version of the files in dir, and checks they
	// work. nil means no check.
	Version func(dir string) (string, error)
}

// XVS is xvs.library from the Virus Help Team. It needs no key file.
var XVS = &Source{
	Name:   "xvs.library",
	URL:    "https://www.vht-dk.dk/amiga/xvs/xvslibrary.lha",
	Files:  map[string]string{"xvs/libs/xvs.library": "xvs.library"},
	Signed: map[string]string{"xvs.library": "xvs/libs/xvs.library.sig"},
	Signer: Georg,
}

// XFD is xfdmaster.library and its decrunchers from Aminet (no signature
// is published; the code only ever runs inside the emulated Amiga).
var XFD = &Source{
	Name:  "xfdmaster.library",
	URL:   "https://aminet.net/util/pack/xfdmaster.lha",
	Files: map[string]string{"xfd_User/Libs/xfdmaster.library": "xfdmaster.library"},
	Dirs:  map[string]string{"xfd_User/Libs/xfd": "xfd"},
}

// Result says what happened to one source.
type Result struct {
	Source  string
	Action  string // "installed", "updated", "up to date"
	Old     string // version before, if any
	Version string // version now
	Signed  bool   // a signature was checked
}

func (r Result) String() string {
	s := r.Source + ": " + r.Action
	switch {
	case r.Action == "updated" && r.Old != "":
		s += fmt.Sprintf(" from version %s to %s", r.Old, r.Version)
	case r.Version != "":
		s += ", version " + r.Version
	}
	if r.Signed && r.Action != "up to date" {
		s += ", signature checked"
	}
	return s
}

// Updater fetches sources into Dir.
type Updater struct {
	Dir    string
	Client *http.Client
	Log    func(string) // progress messages; may be nil
	// MaxSize limits each download.
	MaxSize int64
}

const stateFile = "amiscan-update.json"

type sourceState struct {
	ETag, LastModified, SHA256, Version string
	Checked                             time.Time
}

func (u *Updater) logf(format string, args ...any) {
	if u.Log != nil {
		u.Log(fmt.Sprintf(format, args...))
	}
}

func (u *Updater) loadState() map[string]*sourceState {
	st := map[string]*sourceState{}
	if b, err := os.ReadFile(filepath.Join(u.Dir, stateFile)); err == nil {
		json.Unmarshal(b, &st)
	}
	return st
}

func (u *Updater) saveState(st map[string]*sourceState) error {
	b, _ := json.MarshalIndent(st, "", "  ")
	return writeAtomic(filepath.Join(u.Dir, stateFile), b)
}

// LastChecked is when an update last reached the internet for name (zero if never).
func LastChecked(dir, name string) time.Time {
	u := &Updater{Dir: dir}
	if s := u.loadState()[name]; s != nil {
		return s.Checked
	}
	return time.Time{}
}

// Update brings src (and what it needs) up to date. force downloads even
// when the server says nothing changed.
func (u *Updater) Update(ctx context.Context, src *Source, force bool) ([]Result, error) {
	if err := os.MkdirAll(u.Dir, 0o755); err != nil {
		return nil, err
	}
	var out []Result
	for _, need := range src.Needs {
		if u.present(need) {
			continue
		}
		u.logf("%s needs %s, which is missing: fetching it", src.Name, need.Name)
		r, err := u.Update(ctx, need, true)
		out = append(out, r...)
		if err != nil {
			return out, fmt.Errorf("%s: %w", need.Name, err)
		}
	}
	r, err := u.one(ctx, src, force || !u.present(src))
	if err != nil {
		return out, fmt.Errorf("%s: %w", src.Name, err)
	}
	return append(out, r), nil
}

func (u *Updater) present(src *Source) bool {
	for _, name := range src.Dirs {
		if st, err := os.Stat(filepath.Join(u.Dir, name)); err != nil || !st.IsDir() {
			return false
		}
	}
	for _, name := range src.Files {
		if _, err := os.Stat(filepath.Join(u.Dir, name)); err != nil {
			return false
		}
	}
	return true
}

func (u *Updater) one(ctx context.Context, src *Source, force bool) (Result, error) {
	res := Result{Source: src.Name}
	states := u.loadState()
	st := states[src.Name]
	if st == nil {
		st = &sourceState{}
		states[src.Name] = st
	}
	installed := ""
	if u.present(src) && src.Version != nil {
		if v, err := src.Version(u.Dir); err == nil {
			installed = v
		}
	}

	u.logf("checking %s", src.URL)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, src.URL, nil)
	if err != nil {
		return res, err
	}
	req.Header.Set("User-Agent", "AmiScan (Amiga virus scanner for Linux)")
	if !force {
		if st.ETag != "" {
			req.Header.Set("If-None-Match", st.ETag)
		}
		if st.LastModified != "" {
			req.Header.Set("If-Modified-Since", st.LastModified)
		}
	}
	client := u.Client
	if client == nil {
		client = &http.Client{Timeout: 2 * time.Minute}
	}
	resp, err := client.Do(req)
	if err != nil {
		return res, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotModified {
		st.Checked = time.Now()
		res.Action, res.Version = "up to date", installed
		return res, u.saveState(states)
	}
	if resp.StatusCode != http.StatusOK {
		return res, fmt.Errorf("%s: %s", src.URL, resp.Status)
	}
	limit := u.MaxSize
	if limit <= 0 {
		limit = 32 << 20
	}
	archive, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return res, err
	}
	if int64(len(archive)) > limit {
		return res, fmt.Errorf("download bigger than %d MB", limit>>20)
	}
	sum := sha256.Sum256(archive)
	hexSum := hex.EncodeToString(sum[:])
	if !force && hexSum == st.SHA256 && installed != "" {
		st.ETag, st.LastModified, st.Checked = resp.Header.Get("ETag"), resp.Header.Get("Last-Modified"), time.Now()
		res.Action, res.Version = "up to date", installed
		return res, u.saveState(states)
	}

	files, signed, err := unpack(src, archive)
	if err != nil {
		return res, err
	}
	res.Signed = signed

	// try the new files in a folder of their own before they replace anything
	tmp, err := os.MkdirTemp(u.Dir, ".update-")
	if err != nil {
		return res, err
	}
	defer os.RemoveAll(tmp)
	for name, data := range files {
		to := filepath.Join(tmp, filepath.FromSlash(name))
		os.MkdirAll(filepath.Dir(to), 0o755)
		if err := os.WriteFile(to, data, 0o644); err != nil {
			return res, err
		}
	}
	version := ""
	if src.Version != nil {
		// the new files are tried together with what is already installed (key files)
		for _, need := range src.Needs {
			for _, name := range need.Files {
				if b, err := os.ReadFile(filepath.Join(u.Dir, name)); err == nil {
					os.WriteFile(filepath.Join(tmp, name), b, 0o644)
				}
			}
		}
		if version, err = src.Version(tmp); err != nil {
			return res, fmt.Errorf("the downloaded files do not work: %w", err)
		}
		if installed != "" && compareVersions(version, installed) < 0 {
			return res, fmt.Errorf("the download (%s) is older than what is installed (%s); keeping %s", version, installed, installed)
		}
	}

	// keep the previous files and the whole archive as published
	var top []string // files and folders directly in the libs folder
	for name := range src.Files {
		top = append(top, src.Files[name])
	}
	for _, dir := range src.Dirs {
		top = append(top, dir)
	}
	for _, name := range top {
		dst := filepath.Join(u.Dir, name)
		if _, err := os.Stat(dst); err == nil {
			old := filepath.Join(u.Dir, "old", name)
			os.MkdirAll(filepath.Dir(old), 0o755)
			os.RemoveAll(old)
			os.Rename(dst, old)
		}
		if err := os.Rename(filepath.Join(tmp, name), dst); err != nil {
			return res, err
		}
	}
	os.MkdirAll(filepath.Join(u.Dir, "archives"), 0o755)
	writeAtomic(filepath.Join(u.Dir, "archives", path.Base(req.URL.Path)), archive)

	*st = sourceState{ETag: resp.Header.Get("ETag"), LastModified: resp.Header.Get("Last-Modified"),
		SHA256: hexSum, Version: version, Checked: time.Now()}
	res.Version, res.Old = version, installed
	switch {
	case installed == "":
		res.Action = "installed"
	case compareVersions(version, installed) == 0:
		res.Action = "up to date"
	default:
		res.Action = "updated"
	}
	return res, u.saveState(states)
}

// unpack takes the wanted files out of the archive and checks signatures.
func unpack(src *Source, archive []byte) (files map[string][]byte, signed bool, err error) {
	a, err := lha.NewReader(bytes.NewReader(archive), int64(len(archive)))
	if err != nil {
		return nil, false, fmt.Errorf("not an LhA archive: %w", err)
	}
	member := func(want string) ([]byte, error) {
		for _, f := range a.Files {
			if !f.Dir && strings.EqualFold(strings.TrimLeft(f.Name, "/"), want) {
				return a.ReadFile(f, 16<<20)
			}
		}
		return nil, fmt.Errorf("%s is not in the archive", want)
	}
	files = map[string][]byte{}
	for m, name := range src.Files {
		if strings.ContainsAny(name, `/\`) || name == "" || name[0] == '.' {
			return nil, false, fmt.Errorf("bad file name %q", name)
		}
		if files[name], err = member(m); err != nil {
			return nil, false, err
		}
	}
	for prefix, dir := range src.Dirs {
		if strings.ContainsAny(dir, `/\`) || dir == "" || dir[0] == '.' {
			return nil, false, fmt.Errorf("bad folder name %q", dir)
		}
		prefix = strings.ToLower(strings.Trim(prefix, "/")) + "/"
		n := 0
		for _, f := range a.Files {
			rel := strings.TrimLeft(f.Name, "/")
			if f.Dir || !strings.HasPrefix(strings.ToLower(rel), prefix) {
				continue
			}
			name := rel[len(prefix):]
			if name == "" || strings.ContainsAny(name, `/\`) || name == "." || name == ".." {
				continue // only the files directly in the folder
			}
			data, err := a.ReadFile(f, 16<<20)
			if err != nil {
				return nil, false, fmt.Errorf("%s: %w", rel, err)
			}
			files[dir+"/"+name] = data
			n++
		}
		if n == 0 {
			return nil, false, fmt.Errorf("%s is not in the archive", prefix)
		}
	}
	for name, sigMember := range src.Signed {
		sig, err := member(sigMember)
		if err != nil {
			return nil, false, fmt.Errorf("no signature: %w", err)
		}
		if err := VerifyPGP2(src.Signer, files[name], sig); err != nil {
			return nil, false, fmt.Errorf("%s is not signed by %s: %w", name, src.Signer.Owner, err)
		}
		signed = true
	}
	return files, signed, nil
}

var versionRe = regexp.MustCompile(`(\d+)\.(\d+)`)

// compareVersions compares "33.49"-style versions.
func compareVersions(a, b string) int {
	pa, pb := versionRe.FindStringSubmatch(a), versionRe.FindStringSubmatch(b)
	if pa == nil || pb == nil {
		return strings.Compare(a, b)
	}
	for i := 1; i <= 2; i++ {
		x, _ := strconv.Atoi(pa[i])
		y, _ := strconv.Atoi(pb[i])
		if x != y {
			if x < y {
				return -1
			}
			return 1
		}
	}
	return 0
}

func writeAtomic(name string, b []byte) error {
	tmp := name + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, name)
}

// ErrNotWritable is returned by Writable.
var ErrNotWritable = errors.New("folder is not writable")

// Writable reports whether dir can be created or written.
func Writable(dir string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, ".write-test-")
	if err != nil {
		return ErrNotWritable
	}
	f.Close()
	return os.Remove(f.Name())
}
