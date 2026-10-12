package amiga

// Exec lists live in guest memory, because guest code walks them too.

func (m *Machine) NewList(l uint32, typ uint8) {
	m.w32(l+List_lh_Head, l+List_lh_Tail)
	m.w32(l+List_lh_Tail, 0)
	m.w32(l+List_lh_TailPred, l+List_lh_Head)
	m.w8(l+List_lh_Type, typ)
}

func (m *Machine) AddHead(l, n uint32) {
	first := m.r32(l + List_lh_Head)
	m.w32(n+Node_ln_Succ, first)
	m.w32(n+Node_ln_Pred, l+List_lh_Head)
	m.w32(first+Node_ln_Pred, n)
	m.w32(l+List_lh_Head, n)
}

func (m *Machine) AddTail(l, n uint32) {
	last := m.r32(l + List_lh_TailPred)
	m.w32(n+Node_ln_Succ, l+List_lh_Tail)
	m.w32(n+Node_ln_Pred, last)
	m.w32(last+Node_ln_Succ, n)
	m.w32(l+List_lh_TailPred, n)
}

func (m *Machine) Remove(n uint32) {
	succ, pred := m.r32(n+Node_ln_Succ), m.r32(n+Node_ln_Pred)
	m.w32(pred+Node_ln_Succ, succ)
	m.w32(succ+Node_ln_Pred, pred)
}

func (m *Machine) RemHead(l uint32) uint32 {
	n := m.r32(l + List_lh_Head)
	if m.r32(n+Node_ln_Succ) == 0 {
		return 0
	}
	m.Remove(n)
	return n
}

func (m *Machine) RemTail(l uint32) uint32 {
	n := m.r32(l + List_lh_TailPred)
	if m.r32(n+Node_ln_Pred) == 0 {
		return 0
	}
	m.Remove(n)
	return n
}

// Enqueue inserts n by priority (higher first, FIFO among equals).
func (m *Machine) Enqueue(l, n uint32) {
	pri := int8(m.r8(n + Node_ln_Pri))
	next := m.r32(l + List_lh_Head)
	for m.r32(next+Node_ln_Succ) != 0 && int8(m.r8(next+Node_ln_Pri)) >= pri {
		next = m.r32(next + Node_ln_Succ)
	}
	pred := m.r32(next + Node_ln_Pred)
	m.w32(n+Node_ln_Succ, next)
	m.w32(n+Node_ln_Pred, pred)
	m.w32(pred+Node_ln_Succ, n)
	m.w32(next+Node_ln_Pred, n)
}

// FindName searches from the list header l (or from a node, like exec:
// the search starts at the successor of start).
func (m *Machine) FindName(start uint32, name string) uint32 {
	for n := m.r32(start + Node_ln_Succ); n != 0 && m.r32(n+Node_ln_Succ) != 0; n = m.r32(n + Node_ln_Succ) {
		if m.CString(m.r32(n+Node_ln_Name)) == name {
			return n
		}
	}
	return 0
}
