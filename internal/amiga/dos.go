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

type files struct {
	locks   map[uint32]string // lock address -> host path
	handles map[uint32]*openFile
	ioErr   uint32
}

func (f *files) init() {
	f.locks = map[uint32]string{}
	f.handles = map[uint32]*openFile{}
}

// hostPath maps an Amiga path to a file in LibsDir; only LIBS: is visible.
func (m *Machine) hostPath(name string) string {
	dev, rest, ok := strings.Cut(name, ":")
	if !ok || !strings.EqualFold(dev, "LIBS") || m.LibsDir == "" {
		return ""
	}
	rest = strings.TrimPrefix(rest, "/")
	if rest == "" {
		return m.LibsDir
	}
	if strings.Contains(rest, "/") {
		return ""
	}
	ents, err := os.ReadDir(m.LibsDir)
	if err != nil {
		return ""
	}
	for _, e := range ents { // Amiga names are case-insensitive
		if strings.EqualFold(e.Name(), rest) {
			return filepath.Join(m.LibsDir, e.Name())
		}
	}
	return ""
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
	f["DateStamp"] = func() { m.putDate(d(1), time.Now()); ret(d(1)) }
	f["CurrentDir"] = func() { ret(0) }
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
		l := m.Alloc(20, true)
		m.w32(l+8, d(2)) // fl_Access
		fs.locks[l] = p
		ret(l >> 2)
	}
	f["DupLock"] = func() {
		p, ok := fs.locks[d(1)<<2]
		if !ok {
			ret(0)
			return
		}
		l := m.Alloc(20, true)
		fs.locks[l] = p
		ret(l >> 2)
	}
	f["UnLock"] = func() {
		l := d(1) << 2
		if _, ok := fs.locks[l]; ok {
			delete(fs.locks, l)
			m.Free(l)
		}
	}
	f["Examine"] = func() {
		p, ok := fs.locks[d(1)<<2]
		if !ok {
			fail(errObjectNotFound)
			return
		}
		st, err := os.Stat(p)
		if err != nil {
			fail(errObjectNotFound)
			return
		}
		m.fillFib(d(2), st)
		ret(0xffffffff)
	}
	f["ExNext"] = func() { fail(errNoMoreEntries) }
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
