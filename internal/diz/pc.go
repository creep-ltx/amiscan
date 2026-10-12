package diz

import (
	"bytes"
	"errors"
	"io"

	"github.com/creep-ltx/amiscan/internal/diz/arc"
	"github.com/creep-ltx/amiscan/internal/diz/arj"
	"github.com/creep-ltx/amiscan/internal/diz/cab"
	"github.com/creep-ltx/amiscan/internal/diz/rardecode"
	"github.com/creep-ltx/amiscan/internal/diz/sfx"
	"github.com/creep-ltx/amiscan/internal/diz/stream"
	"github.com/creep-ltx/amiscan/internal/diz/zipold"
	"github.com/creep-ltx/amiscan/internal/diz/zoo"
)

// PC archives: RAR (1.5 to 5), ARJ, ARC and PAK, ZOO, CAB (stored and
// MSZIP folders), tar (plain, gzip, bzip2, xz), a bare .gz/.bz2/.xz of one
// file, and self-extracting DOS and Windows programs holding any of these
// or a Zip, LhA or 7z. Zip members packed by PKZIP 1.x (shrink, reduce,
// implode) are read too, in every Zip.
func init() {
	zipold.Register() // PKZIP 1.x shrink, reduce and implode, for every Zip
	register(format{name: "rar", magic: isRAR, exts: []string{"rar"}, open: openRAR})
	register(format{name: "arj", magic: func(h []byte, _ int64) bool { return arj.IsHeader(h) && h[10] == 2 },
		exts: []string{"arj"}, open: openARJ})
	register(format{name: "zoo", magic: func(h []byte, _ int64) bool { return zoo.IsArchive(h) },
		exts: []string{"zoo"}, open: openZOO})
	register(format{name: "tar", magic: func(h []byte, _ int64) bool { return stream.IsTar(h) },
		exts: []string{"tar"}, open: openTar})
	register(format{name: "gzip", magic: isGzip, exts: []string{"gz", "tgz"}, open: openStream(stream.Gzip)})
	register(format{name: "bzip2", magic: isKind(stream.Bzip2), exts: []string{"bz2", "tbz", "tbz2"},
		open: openStream(stream.Bzip2)})
	register(format{name: "xz", magic: isKind(stream.XZ), exts: []string{"xz", "txz"}, open: openStream(stream.XZ)})
	register(format{name: "cab", magic: func(h []byte, _ int64) bool { return cab.IsCabinet(h) },
		exts: []string{"cab"}, open: openCAB})
	register(format{name: "arc", magic: func(h []byte, _ int64) bool { return arc.IsHeader(h) },
		exts: []string{"arc", "ark", "pak"}, open: openARC})
	register(format{name: "sfx", magic: func(h []byte, _ int64) bool { return sfx.IsExe(h) }, open: openSFX})
}

var errNoArchive = errors.New("diz: no archive inside the program")

func isRAR(h []byte, _ int64) bool {
	return bytes.HasPrefix(h, []byte("Rar!\x1a\x07\x00")) || bytes.HasPrefix(h, []byte("Rar!\x1a\x07\x01\x00"))
}

// rarMaxDict caps the RAR window: RAR 5 to 7 default to 32 MB. A solid
// archive made with a bigger one is not read (a non-solid member's window
// is never bigger than the member).
const rarMaxDict = 64 << 20

func openRAR(r io.ReaderAt, size int64) ([]member, []Candidate, error) {
	open := func() (*rardecode.Reader, error) {
		return rardecode.NewReader(io.NewSectionReader(r, 0, size), rardecode.MaxDictionarySize(rarMaxDict))
	}
	rr, err := open()
	if errors.Is(err, rardecode.ErrArchiveEncrypted) || errors.Is(err, rardecode.ErrBadVolumeNumber) {
		return nil, nil, nil // a RAR, but names encrypted or a later volume: nothing to read
	}
	if err != nil {
		return nil, nil, err
	}
	var ms []member
	for i := 0; i < 1<<16; i++ {
		h, err := rr.Next()
		if err != nil {
			break // end, the next volume, or damage
		}
		size := h.UnPackedSize
		if h.UnKnownSize {
			size = -1
		}
		if h.IsDir || h.Encrypted {
			m := member{name: pcName(h.Name), size: size, time: h.ModificationTime, dir: h.IsDir}
			ms = append(ms, m) // listed, not read
			continue
		}
		index := i
		ms = append(ms, member{name: pcName(h.Name), size: size, time: h.ModificationTime, read: func(limit int64) ([]byte, error) {
			rr, err := open()
			if err != nil {
				return nil, err
			}
			for j := 0; j <= index; j++ {
				if _, err := rr.Next(); err != nil {
					return nil, err
				}
			}
			b, err := io.ReadAll(io.LimitReader(rr, limit))
			if errors.Is(err, rardecode.ErrBadFileChecksum) || errors.Is(err, rardecode.ErrShortFile) {
				return nil, err // read to its end and wrong: show nothing of it
			}
			if err != nil && len(b) == 0 {
				return nil, err
			}
			return b, nil
		}})
	}
	return ms, nil, nil
}

func openARJ(r io.ReaderAt, size int64) ([]member, []Candidate, error) {
	a, err := arj.NewReader(r, size)
	if err != nil {
		return nil, nil, err
	}
	var ms []member
	for _, f := range a.Files {
		m := member{name: pcName(f.Name), size: f.Size, time: f.Time}
		// Listed but not read: folders, encrypted members, and the rest of
		// a file that began in the previous volume (its middle is no use).
		// Labels and comment headers are left out.
		switch {
		case f.Dir:
			ms = append(ms, folder(m.name, f.Time))
			continue
		case f.Type > 1:
			continue
		case f.Flags&(arj.FlagGarbled|arj.FlagExtFile) != 0:
			ms = append(ms, m)
			continue
		}
		ms = append(ms, member{name: m.name, size: m.size, time: m.time, read: func(limit int64) ([]byte, error) {
			return a.ReadFile(f, limit)
		}})
	}
	return ms, nil, nil
}

func openARC(r io.ReaderAt, size int64) ([]member, []Candidate, error) {
	a, err := arc.NewReader(r, size)
	if err != nil {
		return nil, nil, err
	}
	var ms []member
	for _, f := range a.Files {
		ms = append(ms, member{name: pcName(f.Name), size: f.Size, time: f.Time, read: func(limit int64) ([]byte, error) {
			return a.ReadFile(f, limit)
		}})
	}
	return ms, nil, nil
}

func openCAB(r io.ReaderAt, size int64) ([]member, []Candidate, error) {
	a, err := cab.NewReader(r, size)
	if err != nil {
		return nil, nil, err
	}
	var ms []member
	for _, f := range a.Files {
		name := f.Name
		if !f.UTF8 {
			name = pcName(name)
		}
		ms = append(ms, member{name: name, size: f.Size, time: f.Time, read: func(limit int64) ([]byte, error) {
			return a.ReadFile(f, limit)
		}})
	}
	return ms, nil, nil
}

func openZOO(r io.ReaderAt, size int64) ([]member, []Candidate, error) {
	a, err := zoo.NewReader(r, size)
	if err != nil {
		return nil, nil, err
	}
	var ms []member
	for _, f := range a.Files {
		ms = append(ms, member{name: pcName(f.Name), size: f.Size, time: f.Time, read: func(limit int64) ([]byte, error) {
			return a.ReadFile(f, limit)
		}})
	}
	return ms, nil, nil
}

func openTar(r io.ReaderAt, size int64) ([]member, []Candidate, error) {
	sm, err := stream.OpenTar(r, size)
	if err != nil {
		return nil, nil, err
	}
	return fromStream(sm), nil, nil
}

func fromStream(sm []stream.Member) []member {
	ms := make([]member, 0, len(sm))
	for _, m := range sm {
		name := m.Name
		if name == "" {
			name = "unnamed"
		}
		if m.Dir {
			ms = append(ms, folder(pcName(name), m.Time))
			continue
		}
		ms = append(ms, member{name: pcName(name), size: m.Size, time: m.Time, read: m.Read})
	}
	return ms
}

func isKind(k stream.Kind) func([]byte, int64) bool {
	return func(h []byte, _ int64) bool { return stream.Detect(h) == k }
}

// isGzip leaves a gzipped Amiga disk image (.adz) to the disk formats.
func isGzip(h []byte, _ int64) bool {
	if stream.Detect(h) != stream.Gzip {
		return false
	}
	start := stream.Peek(stream.Gzip, h, 4)
	return !bytes.HasPrefix(start, []byte("DOS"))
}

func openStream(k stream.Kind) func(io.ReaderAt, int64) ([]member, []Candidate, error) {
	return func(r io.ReaderAt, size int64) ([]member, []Candidate, error) {
		sm, _, err := stream.Open(k, r, size)
		if err != nil {
			return nil, nil, err
		}
		return fromStream(sm), nil, nil
	}
}

// openSFX finds the archive inside a self-extracting program and opens it
// from there.
func openSFX(r io.ReaderAt, size int64) ([]member, []Candidate, error) {
	// A Zip is found from its end, wherever it starts.
	if ms, ex, err := tryOpen(openZip, r, size); err == nil && len(readable(ms)) > 0 {
		return ms, ex, nil
	}
	tried := 0
	for _, f := range sfx.Scan(r, size) {
		if tried == 8 {
			break
		}
		tried++
		var open func(io.ReaderAt, int64) ([]member, []Candidate, error)
		switch f.Kind {
		case "rar":
			open = openRAR
		case "7z":
			open = open7z
		case "arj":
			open = openARJ
		case "zoo":
			open = openZOO
		case "lha":
			open = openLHA
		case "arc":
			open = openARC
		case "cab":
			open = openCAB
		default:
			continue
		}
		n := size - f.Offset
		if ms, ex, err := tryOpen(open, io.NewSectionReader(r, f.Offset, n), n); err == nil && len(readable(ms)) > 0 {
			return ms, ex, nil
		}
	}
	return nil, nil, errNoArchive
}

// tryOpen opens a guessed archive; a reader that panics on what is not
// really its format only means "not this one".
func tryOpen(open func(io.ReaderAt, int64) ([]member, []Candidate, error), r io.ReaderAt, size int64) (ms []member, ex []Candidate, err error) {
	defer func() {
		if p := recover(); p != nil {
			ms, ex, err = nil, nil, errNoArchive
		}
	}()
	return open(r, size)
}
