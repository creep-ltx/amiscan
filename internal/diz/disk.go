package diz

import (
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/creep-ltx/amiscan/internal/diz/adf"
	"github.com/creep-ltx/amiscan/internal/diz/dms"
)

// Amiga disk images (ADF, ADZ, DMS, HDF) and bare Amiga programs.
//
// A disk's files become members, so its FILE_ID.DIZ or readme is found as
// in an archive. A DMS file can carry a FILE_ID.DIZ of its own (track 80),
// offered as the member "FILE_ID.DIZ", and a banner text. Each disk also
// gets a "disk" candidate: its name and what is on it, or that it has no
// AmigaDOS files (a game or a bootblock intro) and the text in its boot block.
func init() {
	register(format{name: "dms", magic: prefix("DMS!"), exts: []string{"dms"}, open: openDMS})
	register(format{name: "adf", magic: isADF, exts: []string{"adf"}, open: openADF})
	register(format{name: "adz", magic: isADZ, exts: []string{"adz"}, open: openADZ})
	register(format{name: "hdf", magic: isHDF, exts: []string{"hdf"}, open: openHDF})
	register(format{name: "amigaexe", magic: prefix("\x00\x00\x03\xf3"), open: openAmigaExe})
}

const (
	dmsLimit = 4 << 20 // a DMS file is at most about 2 MB (an HD disk stored)
	exeLimit = 4 << 20 // bytes of a program searched for $VER:
)

func isADF(h []byte, size int64) bool {
	return (size == adf.SizeDD || size == adf.SizeHD) && bytes.HasPrefix(h, []byte("DOS"))
}

// isADZ: a gzip file whose content starts as an AmigaDOS boot block, or
// whose stored name is an .adf.
func isADZ(h []byte, _ int64) bool {
	if len(h) < 10 || h[0] != 0x1f || h[1] != 0x8b || h[2] != 8 {
		return false
	}
	z, err := gzip.NewReader(bytes.NewReader(h))
	if err != nil {
		return false
	}
	if strings.HasSuffix(strings.ToLower(z.Name), ".adf") {
		return true
	}
	b := make([]byte, 3)
	n, _ := io.ReadFull(z, b)
	return n == 3 && string(b) == "DOS"
}

// isHDF: a Rigid Disk Block in the first blocks, or one AmigaDOS volume
// bigger than a floppy.
func isHDF(h []byte, size int64) bool {
	for at := 0; at+4 <= len(h); at += 512 {
		if string(h[at:at+4]) == "RDSK" {
			return true
		}
	}
	return size > adf.SizeHD && size%512 == 0 && bytes.HasPrefix(h, []byte("DOS"))
}

func openADF(r io.ReaderAt, size int64) ([]member, []Candidate, error) {
	return floppy(r, size)
}

func openADZ(r io.ReaderAt, size int64) ([]member, []Candidate, error) {
	z, err := gzip.NewReader(io.NewSectionReader(r, 0, size))
	if err != nil {
		return nil, nil, err
	}
	img, err := io.ReadAll(io.LimitReader(z, adf.SizeHD+1))
	if err != nil && len(img) == 0 {
		return nil, nil, err
	}
	if len(img) > adf.SizeHD {
		return nil, nil, errors.New("adz: bigger than a floppy")
	}
	return floppy(bytes.NewReader(img), int64(len(img)))
}

func openDMS(r io.ReaderAt, size int64) ([]member, []Candidate, error) {
	if size > dmsLimit {
		return nil, nil, errors.New("dms: too big")
	}
	b := make([]byte, size)
	if n, err := r.ReadAt(b, 0); int64(n) < size {
		return nil, nil, err
	}
	a, err := dms.Read(b)
	if err != nil {
		return nil, nil, err
	}
	var ms []member
	var extra []Candidate
	if a.DIZ != nil {
		ms = append(ms, bytesMember("FILE_ID.DIZ", a.DIZ))
	}
	if a.Banner != nil {
		extra = append(extra, Candidate{Source: "DMS banner", Lines: []string{string(a.Banner)}})
	}
	switch {
	case a.Encrypted:
		extra = append(extra, Candidate{Source: "disk", Lines: []string{"Password protected DMS disk (not unpacked)"}})
	case len(a.Tracks) == 0:
		extra = append(extra, Candidate{Source: "disk", Lines: []string{"DMS file without disk tracks"}})
	default:
		img := a.Image()
		dm, dx, _ := floppy(bytes.NewReader(img), int64(len(img)))
		ms = append(ms, dm...)
		extra = append(extra, dx...)
	}
	return ms, extra, nil
}

func bytesMember(name string, b []byte) member {
	return member{name: name, size: int64(len(b)), read: func(limit int64) ([]byte, error) {
		if int64(len(b)) > limit {
			return b[:limit], nil
		}
		return b, nil
	}}
}

// floppy reads a floppy image: its files, or what its boot block says.
func floppy(r io.ReaderAt, size int64) ([]member, []Candidate, error) {
	v, err := adf.OpenFloppy(r, size)
	if err != nil {
		boot := make([]byte, 1024)
		n, _ := r.ReadAt(boot, 0)
		if n == 0 {
			return nil, nil, err
		}
		return nil, noDOS(boot[:n], err), nil
	}
	return volumeMembers(v, ""), []Candidate{diskCandidate(v, "Disk: ")}, nil
}

// noDOS describes a disk without AmigaDOS files.
func noDOS(boot []byte, err error) []Candidate {
	what := "Not an AmigaDOS disk (boot block only)"
	if errors.Is(err, adf.ErrNoRoot) {
		what = "AmigaDOS boot block, but no files"
	}
	out := []Candidate{{Source: "disk", Lines: []string{what}}}
	var text []string
	for _, l := range adf.BootText(boot) {
		text = append(text, wrap(l)...)
	}
	if len(text) > 0 {
		out = append(out, Candidate{Source: "boot block", Lines: text})
	}
	return out
}

func volumeMembers(v *adf.Volume, prefix string) []member {
	var ms []member
	for _, e := range v.Entries {
		if e.Dir {
			ms = append(ms, folder(prefix+e.Path, e.Time))
			continue
		}
		ms = append(ms, member{name: prefix + e.Path, size: e.Size, time: e.Time, read: func(limit int64) ([]byte, error) {
			return v.ReadFile(e, limit)
		}})
	}
	return ms
}

// diskCandidate is "Disk: <name>" and "Contains: ..." with the names at
// the top of the volume (icons left out, directories included).
func diskCandidate(v *adf.Volume, label string) Candidate {
	var top []string
	for _, e := range v.Entries {
		if !strings.Contains(e.Path, "/") && !strings.HasSuffix(strings.ToLower(e.Path), ".info") {
			top = append(top, e.Path)
		}
	}
	sort.SliceStable(top, func(i, j int) bool { return strings.ToLower(top[i]) < strings.ToLower(top[j]) })
	lines := []string{label + v.Name}
	if len(top) == 0 {
		return Candidate{Source: "disk", Lines: append(lines, "(no files)")}
	}
	more := ""
	if len(top) > 12 {
		top, more = top[:12], ", ..."
	}
	return Candidate{Source: "disk", Lines: append(lines, wrap("Contains: "+strings.Join(top, ", ")+more)...)}
}

func openHDF(r io.ReaderAt, size int64) ([]member, []Candidate, error) {
	parts, err := adf.Partitions(r, size)
	if errors.Is(err, adf.ErrNoRDB) {
		v, err := adf.Open(r, 0, size/512, 512, 2)
		if err != nil {
			return nil, nil, err
		}
		return volumeMembers(v, ""), []Candidate{diskCandidate(v, "Hard disk: ")}, nil
	}
	if err != nil {
		return nil, nil, err
	}
	var ms []member
	var extra []Candidate
	var names []string
	for i, p := range parts {
		name := p.Name
		if name == "" {
			name = fmt.Sprintf("part%d", i)
		}
		if !p.IsDOS() {
			names = append(names, name+" ("+p.DOSTypeString()+", not read)")
			continue
		}
		v, err := p.Open(r)
		if err != nil {
			names = append(names, name+" (unreadable)")
			continue
		}
		names = append(names, name+": "+v.Name)
		ms = append(ms, folder(name, time.Time{}))
		ms = append(ms, volumeMembers(v, name+"/")...)
	}
	if len(parts) == 0 {
		return nil, nil, errors.New("hdf: no partitions")
	}
	extra = append(extra, Candidate{Source: "disk", Lines: wrap("Hard disk: " + strings.Join(names, ", "))})
	return ms, extra, nil
}

// openAmigaExe: a bare Amiga program has no files inside; its $VER:
// string (e.g. "MyDemo 1.2 (12.3.94)") is offered when there is one.
func openAmigaExe(r io.ReaderAt, size int64) ([]member, []Candidate, error) {
	n := min(size, exeLimit)
	b := make([]byte, n)
	if got, err := r.ReadAt(b, 0); int64(got) < n {
		if got == 0 {
			return nil, nil, err
		}
		b = b[:got]
	}
	if v := verString(b); v != "" {
		return nil, []Candidate{{Source: "$VER string", Lines: []string{v}}}, nil
	}
	return nil, nil, nil
}

// verString finds "$VER:" and returns the printable text after it.
func verString(b []byte) string {
	for off := 0; ; {
		i := bytes.Index(b[off:], []byte("$VER:"))
		if i < 0 {
			return ""
		}
		i += off + 5
		j := i
		for j < len(b) && j-i < 200 && (b[j] >= 0x20 && b[j] != 0x7f) {
			j++
		}
		if s := strings.TrimSpace(string(b[i:j])); len(s) >= 2 {
			return s
		}
		off = i
	}
}
