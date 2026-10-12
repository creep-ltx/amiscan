package amiga

import (
	"os"
	"path/filepath"
	"strings"
	"time"
)

// dos.library: read-only access to LIBS: and nothing else.

const (
	errObjectNotFound = 205
	errNoMoreEntries  = 232
	errReadProtected  = 224
	offsetBeginning   = -1
	offsetCurrent     = 0
	offsetEnd         = 1
)

type openFile struct {
	data []byte
	pos  int
}

type lock struct {
	path    string
	entries []os.DirEntry // for ExNext, read at Examine
}

type files struct {
	locks   map[uint32]*lock // lock address -> what it is
	handles map[uint32]*openFile
	ioErr   uint32
	cwd     string // host path of the current directory, "" = none
	cwdLock uint32 // BPTR given by CurrentDir
}

func (f *files) init() {
	f.locks = map[uint32]*lock{}
	f.handles = map[uint32]*openFile{}
}

// hostPath maps an Amiga path to a file under LibsDir. Only LIBS: (and
// paths relative to a current directory inside it) are visible; each part
// is matched without regard to case, as on the Amiga, and must exist.
func (m *Machine) hostPath(name string) string {
	if m.LibsDir == "" {
		return ""
	}
	base, rest := m.files.cwd, name
	if dev, after, ok := strings.Cut(name, ":"); ok {
		if !strings.EqualFold(dev, "LIBS") {
			return ""
		}
		base, rest = m.LibsDir, after
	}
	if base == "" {
		return ""
	}
	p := base
	for _, part := range strings.Split(rest, "/") {
		if part == "" || part == "." || part == ".." {
			if part == "" && rest == "" {
				break
			}
			return "" // "/" (parent) and empty parts are not allowed
		}
		ents, err := os.ReadDir(p)
		if err != nil {
			return ""
		}
		found := ""
		for _, e := range ents {
			if strings.EqualFold(e.Name(), part) && (e.Type().IsRegular() || e.IsDir()) {
				found = e.Name()
				break
			}
		}
		if found == "" {
			return ""
		}
		p = filepath.Join(p, found)
	}
	return p
}

func (m *Machine) setupDos() {
	dos := m.AddFakeLibrary("dos.library", 40)
	c := m.CPU
	d := func(n int) uint32 { return c.D(n) }
	ret := func(v uint32) { c.SetD(0, v) }
	fail := func(code uint32) { m.files.ioErr = code; ret(0) }
	fs := &m.files
	f := dos.funcs
	f["IoErr"] = func() { ret(fs.ioErr) }
	f["SetIoErr"] = func() { old := fs.ioErr; fs.ioErr = d(1); ret(old) }
	f["Output"] = func() { ret(0) }
	f["Input"] = func() { ret(0) }
	f["Delay"] = func() {}
	f["Info"] = func() { ret(0) }
	f["NameFromLock"] = func() {
		l, ok := fs.locks[d(1)<<2]
		if !ok || d(3) == 0 {
			ret(0)
			return
		}
		rel, _ := filepath.Rel(m.LibsDir, l.path)
		name := "LIBS:"
		if rel != "." {
			name += filepath.ToSlash(rel)
		}
		if uint32(len(name)) >= d(3) {
			ret(0)
			return
		}
		copy(m.CPU.RAM[d(2):], name+"\x00")
		ret(0xffffffff)
	}
	f["DateStamp"] = func() { m.putDate(d(1), time.Now()); ret(d(1)) }
	f["CurrentDir"] = func() {
		old := fs.cwdLock
		fs.cwdLock = d(1)
		if l, ok := fs.locks[d(1)<<2]; ok {
			fs.cwd = l.path
		} else {
			fs.cwd = ""
		}
		ret(old)
	}
	newLock := func(p string, access uint32) uint32 {
		l := m.Alloc(20, true)
		m.w32(l+8, access) // fl_Access
		fs.locks[l] = &lock{path: p}
		return l >> 2
	}
	f["ParentDir"] = func() {
		l, ok := fs.locks[d(1)<<2]
		if !ok || filepath.Clean(l.path) == filepath.Clean(m.LibsDir) {
			fail(errObjectNotFound)
			return
		}
		ret(newLock(filepath.Dir(l.path), 0xfffffffe))
	}
	f["LoadSeg"] = func() {
		p := m.hostPath(m.CString(d(1)))
		if p == "" {
			fail(errObjectNotFound)
			return
		}
		data, err := os.ReadFile(p)
		if err != nil {
			fail(errObjectNotFound)
			return
		}
		seg, _, err := m.LoadSeg(data)
		if err != nil {
			if m.Trace {
				m.warnf("LoadSeg(%q): %v", m.CString(d(1)), err)
			}
			fail(121) // ERROR_FILE_NOT_OBJECT
			return
		}
		ret(seg)
	}
	f["UnLoadSeg"] = func() { m.UnLoadSeg(d(1)); ret(0xffffffff) }
	f["Lock"] = func() {
		p := m.hostPath(m.CString(d(1)))
		if p == "" {
			fail(errObjectNotFound)
			return
		}
		if _, err := os.Stat(p); err != nil {
			fail(errObjectNotFound)
			return
		}
		ret(newLock(p, d(2)))
	}
	f["DupLock"] = func() {
		l, ok := fs.locks[d(1)<<2]
		if !ok {
			ret(0)
			return
		}
		ret(newLock(l.path, 0xfffffffe))
	}
	f["UnLock"] = func() {
		l := d(1) << 2
		if _, ok := fs.locks[l]; ok {
			delete(fs.locks, l)
			m.Free(l)
		}
	}
	f["Examine"] = func() {
		l, ok := fs.locks[d(1)<<2]
		if !ok {
			fail(errObjectNotFound)
			return
		}
		st, err := os.Stat(l.path)
		if err != nil {
			fail(errObjectNotFound)
			return
		}
		if st.IsDir() {
			l.entries = nil
			ents, _ := os.ReadDir(l.path)
			for _, e := range ents {
				if e.Type().IsRegular() || e.IsDir() {
					l.entries = append(l.entries, e)
				}
			}
		}
		m.fillFib(d(2), st)
		m.w32(d(2)+FileInfoBlock_fib_DiskKey, 0) // ExNext's position
		ret(0xffffffff)
	}
	f["ExNext"] = func() {
		l, ok := fs.locks[d(1)<<2]
		fib := d(2)
		if !ok {
			fail(errObjectNotFound)
			return
		}
		i := m.r32(fib + FileInfoBlock_fib_DiskKey)
		for ; int(i) < len(l.entries); i++ {
			st, err := l.entries[i].Info()
			if err != nil {
				continue
			}
			m.fillFib(fib, st)
			m.w32(fib+FileInfoBlock_fib_DiskKey, i+1)
			ret(0xffffffff)
			return
		}
		fail(errNoMoreEntries)
	}
	f["Open"] = func() {
		p := m.hostPath(m.CString(d(1)))
		if p == "" || d(2) != 1005 { // MODE_OLDFILE only
			fail(errObjectNotFound)
			return
		}
		data, err := os.ReadFile(p)
		if err != nil {
			fail(errObjectNotFound)
			return
		}
		fh := m.Alloc(44, true)
		fs.handles[fh] = &openFile{data: data}
		ret(fh >> 2)
	}
	f["Close"] = func() {
		fh := d(1) << 2
		if _, ok := fs.handles[fh]; ok {
			delete(fs.handles, fh)
			m.Free(fh)
		}
		ret(0xffffffff)
	}
	f["Read"] = func() {
		h, ok := fs.handles[d(1)<<2]
		if !ok {
			ret(0xffffffff)
			return
		}
		n := copy(c.RAM[d(2):d(2)+min(d(3), RAMSize-d(2))], h.data[h.pos:])
		h.pos += n
		ret(uint32(n))
	}
	f["Write"] = func() { ret(d(3)) } // output is dropped
	f["Seek"] = func() {
		h, ok := fs.handles[d(1)<<2]
		if !ok {
			ret(0xffffffff)
			return
		}
		old, pos := h.pos, int(int32(d(2)))
		switch int32(d(3)) {
		case offsetCurrent:
			pos += h.pos
		case offsetEnd:
			pos += len(h.data)
		}
		if pos < 0 || pos > len(h.data) {
			ret(0xffffffff)
			return
		}
		h.pos = pos
		ret(uint32(old))
	}
	f["ExamineFH"] = func() {
		if h, ok := fs.handles[d(1)<<2]; ok {
			m.fillFibSize(d(2), "file", int64(len(h.data)), time.Now())
			ret(0xffffffff)
			return
		}
		ret(0)
	}
}

func (m *Machine) fillFib(fib uint32, st os.FileInfo) {
	m.fillFibSize(fib, st.Name(), st.Size(), st.ModTime())
	if st.IsDir() {
		m.w32(fib+FileInfoBlock_fib_DirEntryType, 2)
		m.w32(fib+FileInfoBlock_fib_EntryType, 2)
	}
}

func (m *Machine) fillFibSize(fib uint32, name string, size int64, t time.Time) {
	ramClear(m.CPU.RAM[fib : fib+SizeofFileInfoBlock])
	m.w32(fib+FileInfoBlock_fib_DiskKey, 1)
	m.w32(fib+FileInfoBlock_fib_DirEntryType, 0xfffffffd) // ST_FILE
	m.w32(fib+FileInfoBlock_fib_EntryType, 0xfffffffd)
	copy(m.CPU.RAM[fib+FileInfoBlock_fib_FileName:fib+FileInfoBlock_fib_FileName+107], name)
	m.w32(fib+FileInfoBlock_fib_Size, uint32(size))
	m.w32(fib+FileInfoBlock_fib_NumBlocks, uint32((size+487)/488))
	m.putDate(fib+FileInfoBlock_fib_Date, t)
}

// putDate writes a DateStamp (days since 1978, minutes, ticks).
func (m *Machine) putDate(a uint32, t time.Time) {
	epoch := time.Date(1978, 1, 1, 0, 0, 0, 0, time.UTC)
	dd := t.Sub(epoch)
	days := uint32(dd / (24 * time.Hour))
	rest := dd % (24 * time.Hour)
	m.w32(a, days)
	m.w32(a+4, uint32(rest/time.Minute))
	m.w32(a+8, uint32(rest%time.Minute/(time.Second/50)))
}
