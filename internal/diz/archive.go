package diz

import (
	"archive/zip"
	"bytes"
	"io"
	"path"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/bodgit/sevenzip"
	"golang.org/x/text/encoding/charmap"

	"github.com/creep-ltx/amiscan/internal/diz/lha"
	"github.com/creep-ltx/amiscan/internal/diz/lzx"
)

// member is one file or folder inside an archive, with a way to read the
// start of a file. read is nil for folders and for files that cannot be
// read (encrypted, or the rest of a file begun in an earlier volume).
type member struct {
	name string    // '/' separated path
	size int64     // unpacked size, -1 when not known
	time time.Time // zero when not known
	dir  bool
	read func(limit int64) ([]byte, error)
}

// folder is a listed folder: nothing to read.
func folder(name string, t time.Time) member { return member{name: name, time: t, dir: true} }

// readable leaves out folders and what cannot be read.
func readable(ms []member) []member {
	var out []member
	for _, m := range ms {
		if m.read != nil {
			out = append(out, m)
		}
	}
	return out
}

// format is one kind of archive or disk image the reader understands. Formats
// register themselves (see formats.go); a new one is a new file, not an edit here.
type format struct {
	name string
	// magic reports whether the file starts like this format: head is the first
	// headSize bytes (fewer for a small file), size the whole file's size.
	magic func(head []byte, size int64) bool
	// exts are extensions (lower case, no dot) that mean this format when no magic
	// matched, e.g. self-extractors with a program in front.
	exts []string
	// open lists the files. extra are descriptions the format itself carries (a
	// disk's name, a program's $VER string), offered before "Contains: ...".
	open func(r io.ReaderAt, size int64) (members []member, extra []Candidate, err error)
}

// headSize is how much of a file detection may look at.
const headSize = 4096

var formats []format

func register(f format) { formats = append(formats, f) }

// detect names the format: by magic first, in registration order, then by extension.
func detect(head []byte, size int64, ext string) *format {
	for i := range formats {
		if formats[i].magic != nil && formats[i].magic(head, size) {
			// A plain compressed stream says little about what is inside: a gzipped
			// disk image without a stored name looks like any .gz. Let the extension
			// decide then.
			if formats[i].name == "gzip" {
				if byExt := detectExt(ext); byExt != nil {
					return byExt
				}
			}
			return &formats[i]
		}
	}
	return detectExt(ext)
}

func detectExt(ext string) *format {
	for i := range formats {
		for _, e := range formats[i].exts {
			if e == ext {
				return &formats[i]
			}
		}
	}
	return nil
}

// list opens the archive and returns the files that can be read, with clean
// '/' paths. ok is false when the file is not really this format.
func list(r io.ReaderAt, size int64, f *format) (ms []member, extra []Candidate, ok bool) {
	ms, extra, ok = listAll(r, size, f)
	return readable(ms), extra, ok
}

// listAll is list with folders and unreadable files kept; folder names end in '/'.
func listAll(r io.ReaderAt, size int64, f *format) (ms []member, extra []Candidate, ok bool) {
	ms, extra, err := f.open(r, size)
	if err != nil && len(readable(ms)) == 0 && len(extra) == 0 {
		return nil, nil, false
	}
	for i := range ms {
		ms[i].name = strings.TrimLeft(path.Clean(strings.ReplaceAll(ms[i].name, "\\", "/")), "/")
		if ms[i].dir && ms[i].name != "." {
			ms[i].name += "/"
		}
	}
	return ms, extra, true
}

func init() {
	register(format{name: "lzx", magic: prefix("LZX"), open: openLZX})
	register(format{name: "7z", magic: prefix("7z\xbc\xaf\x27\x1c"), open: open7z})
	register(format{name: "zip", magic: func(h []byte, _ int64) bool {
		return bytes.HasPrefix(h, []byte("PK\x03\x04")) || bytes.HasPrefix(h, []byte("PK\x05\x06")) ||
			bytes.HasPrefix(h, []byte("PK\x07\x08"))
	}, exts: []string{"zip"}, open: openZip})
	register(format{name: "lha", magic: func(h []byte, _ int64) bool { return lha.IsHeader(h) },
		exts: []string{"lha", "lzh"}, open: openLHA})
}

// prefix is a magic test for formats that start with fixed bytes.
func prefix(p string) func([]byte, int64) bool {
	return func(h []byte, _ int64) bool { return bytes.HasPrefix(h, []byte(p)) }
}

func openLHA(r io.ReaderAt, size int64) ([]member, []Candidate, error) {
	a, err := lha.NewReader(r, size)
	if err != nil {
		return nil, nil, err
	}
	var ms []member
	for _, f := range a.Files {
		switch {
		case f.Name == "":
		case f.Dir:
			ms = append(ms, folder(f.Name, f.Time))
		default:
			ms = append(ms, member{name: f.Name, size: f.Size, time: f.Time, read: func(limit int64) ([]byte, error) {
				return a.ReadFile(f, limit)
			}})
		}
	}
	return ms, nil, nil
}

func openLZX(r io.ReaderAt, size int64) ([]member, []Candidate, error) {
	a, err := lzx.NewReader(r, size)
	if err != nil {
		return nil, nil, err
	}
	var ms []member
	for _, f := range a.Files {
		switch {
		case f.Name == "":
		case strings.HasSuffix(f.Name, "/"):
			ms = append(ms, folder(f.Name, f.Time))
		default:
			ms = append(ms, member{name: f.Name, size: f.Size, time: f.Time, read: func(limit int64) ([]byte, error) {
				return a.ReadFile(f, limit)
			}})
		}
	}
	return ms, nil, nil
}

func openZip(r io.ReaderAt, size int64) ([]member, []Candidate, error) {
	a, err := zip.NewReader(r, size)
	if err != nil {
		return nil, nil, err
	}
	var ms []member
	for _, f := range a.File {
		if strings.HasSuffix(f.Name, "/") || f.Mode().IsDir() {
			ms = append(ms, folder(pcName(f.Name), f.Modified))
			continue
		}
		ms = append(ms, member{name: pcName(f.Name), size: int64(f.UncompressedSize64), time: f.Modified, read: func(limit int64) ([]byte, error) {
			rc, err := f.Open()
			if err != nil {
				return nil, err
			}
			defer rc.Close()
			return readLimited(rc, limit)
		}})
	}
	return ms, nil, nil
}

func open7z(r io.ReaderAt, size int64) ([]member, []Candidate, error) {
	a, err := sevenzip.NewReader(r, size)
	if err != nil {
		return nil, nil, err
	}
	var ms []member
	for _, f := range a.File {
		if f.FileInfo().IsDir() {
			ms = append(ms, folder(f.Name, f.Modified.Local()))
			continue
		}
		ms = append(ms, member{name: f.Name, size: int64(f.UncompressedSize), time: f.Modified.Local(), read: func(limit int64) ([]byte, error) {
			rc, err := f.Open()
			if err != nil {
				return nil, err
			}
			defer rc.Close()
			return readLimited(rc, limit)
		}})
	}
	return ms, nil, nil
}

func readLimited(r io.Reader, limit int64) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(r, limit))
	if err != nil && len(b) == 0 {
		return nil, err
	}
	return b, nil
}

// pcName reads a zip name that is not UTF-8 as CP437, the zip default.
func pcName(s string) string {
	if utf8.ValidString(s) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		b.WriteRune(charmap.CodePage437.DecodeByte(s[i]))
	}
	return b.String()
}
