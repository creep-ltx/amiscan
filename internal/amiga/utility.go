package amiga

// utility.library: tag lists and 32/64-bit arithmetic, as the ROM does
// them (XPK passes all its settings as tag lists).

const (
	tagDone   = 0
	tagIgnore = 1
	tagMore   = 2
	tagSkip   = 3
)

// nextTag is NextTagItem on a guest TagItem** at tlp.
func (m *Machine) nextTag(tlp uint32) uint32 {
	for n := 0; n < 100000; n++ {
		ti := m.r32(tlp)
		if ti == 0 {
			return 0
		}
		switch m.r32(ti) {
		case tagDone:
			return 0
		case tagIgnore:
			m.w32(tlp, ti+8)
		case tagMore:
			m.w32(tlp, m.r32(ti+4))
		case tagSkip:
			m.w32(tlp, ti+8+8*m.r32(ti+4))
		default:
			m.w32(tlp, ti+8)
			return ti
		}
	}
	return 0
}

// findTag is FindTagItem.
func (m *Machine) findTag(tag, list uint32) uint32 {
	cur := m.Alloc(4, false)
	defer m.Free(cur)
	m.w32(cur, list)
	for ti := m.nextTag(cur); ti != 0; ti = m.nextTag(cur) {
		if m.r32(ti) == tag {
			return ti
		}
	}
	return 0
}

func (m *Machine) setupUtility() {
	u := m.AddFakeLibrary("utility.library", 40)
	c := m.CPU
	d := func(n int) uint32 { return c.D(n) }
	a := func(n int) uint32 { return c.A(n) }
	ret := func(v uint32) { c.SetD(0, v) }
	f := u.funcs
	f["NextTagItem"] = func() { ret(m.nextTag(a(0))) }
	f["FindTagItem"] = func() { ret(m.findTag(d(0), a(0))) }
	f["GetTagData"] = func() {
		if ti := m.findTag(d(0), a(0)); ti != 0 {
			ret(m.r32(ti + 4))
		} else {
			ret(d(1))
		}
	}
	f["TagInArray"] = func() {
		for p := a(0); m.r32(p) != tagDone; p += 4 {
			if m.r32(p) == d(0) {
				ret(1)
				return
			}
		}
		ret(0)
	}
	f["PackBoolTags"] = func() {
		// PackBoolTags(initialFlags d0, tagList a0, boolMap a1)
		flags := d(0)
		cur := m.Alloc(4, false)
		m.w32(cur, a(0))
		for ti := m.nextTag(cur); ti != 0; ti = m.nextTag(cur) {
			for b := a(1); m.r32(b) != tagDone; b += 8 {
				if m.r32(b) == m.r32(ti) {
					if m.r32(ti+4) != 0 {
						flags |= m.r32(b + 4)
					} else {
						flags &^= m.r32(b + 4)
					}
				}
			}
		}
		m.Free(cur)
		ret(flags)
	}
	f["AllocateTagItems"] = func() { ret(m.allocMem(max(d(0), 1)*8, memfClear, true)) }
	f["FreeTagItems"] = func() {
		if a(0) != 0 {
			m.Free(a(0) - 8)
		}
	}
	f["CloneTagItems"] = func() {
		var items [][2]uint32
		cur := m.Alloc(4, false)
		m.w32(cur, a(0))
		for ti := m.nextTag(cur); ti != 0; ti = m.nextTag(cur) {
			items = append(items, [2]uint32{m.r32(ti), m.r32(ti + 4)})
		}
		m.Free(cur)
		p := m.allocMem(uint32(len(items)+1)*8, memfClear, true)
		for i, it := range items {
			m.w32(p+uint32(i)*8, it[0])
			m.w32(p+uint32(i)*8+4, it[1])
		}
		ret(p)
	}
	f["SMult32"] = func() { ret(uint32(int32(d(0)) * int32(d(1)))) }
	f["UMult32"] = func() { ret(d(0) * d(1)) }
	f["SMult64"] = func() {
		r := uint64(int64(int32(d(0))) * int64(int32(d(1))))
		c.SetD(1, uint32(r))
		ret(uint32(r >> 32))
	}
	f["UMult64"] = func() {
		r := uint64(d(0)) * uint64(d(1))
		c.SetD(1, uint32(r))
		ret(uint32(r >> 32))
	}
	f["SDivMod32"] = func() {
		if d(1) == 0 {
			ret(0)
			c.SetD(1, 0)
			return
		}
		q, r := int32(d(0))/int32(d(1)), int32(d(0))%int32(d(1))
		c.SetD(1, uint32(r))
		ret(uint32(q))
	}
	f["UDivMod32"] = func() {
		if d(1) == 0 {
			ret(0)
			c.SetD(1, 0)
			return
		}
		q, r := d(0)/d(1), d(0)%d(1)
		c.SetD(1, r)
		ret(q)
	}
	f["Stricmp"] = func() { ret(uint32(int32(cmpFold(m.CString(a(0)), m.CString(a(1)), -1)))) }
	f["Strnicmp"] = func() { ret(uint32(int32(cmpFold(m.CString(a(0)), m.CString(a(1)), int(d(0)))))) }
	f["ToUpper"] = func() {
		ch := byte(d(0))
		if ch >= 'a' && ch <= 'z' || ch >= 0xe0 && ch <= 0xfe && ch != 0xf7 {
			ch -= 32
		}
		ret(uint32(ch))
	}
	f["ToLower"] = func() {
		ch := byte(d(0))
		if ch >= 'A' && ch <= 'Z' || ch >= 0xc0 && ch <= 0xde && ch != 0xd7 {
			ch += 32
		}
		ret(uint32(ch))
	}
	f["GetUniqueID"] = func() { m.uniqueID++; ret(m.uniqueID) }
	f["CallHookPkt"] = func() {
		// CallHookPkt(hook a0, object a2, message a1): h_Entry with A0 hook, A2 object, A1 message
		saved := m.saveRegs()
		m.guestCall(m.r32(a(0)+8), map[string]uint32{"a0": a(0), "a1": a(1), "a2": a(2)}, func(d0 uint32) { m.osReturn(saved, d0) })
	}
}

func cmpFold(x, y string, n int) int {
	for i := 0; n < 0 || i < n; i++ {
		var a, b byte
		if i < len(x) {
			a = x[i]
		}
		if i < len(y) {
			b = y[i]
		}
		if a >= 'A' && a <= 'Z' {
			a += 32
		}
		if b >= 'A' && b <= 'Z' {
			b += 32
		}
		if a != b {
			return int(a) - int(b)
		}
		if a == 0 {
			return 0
		}
	}
	return 0
}
