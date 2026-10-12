package amiga

import "fmt"

// fakeLib is a library implemented in Go.
type fakeLib struct {
	name  string
	base  uint32
	funcs map[string]func()
}

// fakeVectors is how many jump table entries a Go library gets.
const fakeVectors = 200

// newFakeLib builds a library (or device) whose jump table traps into Go.
func (m *Machine) newFakeLib(name string, version uint16, posSize uint32, nodeType uint8) *fakeLib {
	idx := len(m.libs)
	neg := uint32(fakeVectors * 6)
	mem := m.Alloc(neg+posSize, true)
	base := mem + neg
	for i := uint32(1); i <= fakeVectors; i++ {
		e := base - i*6
		m.w16(e, 0x4afc)
		m.w16(e+2, uint16(idx<<10)|uint16(i))
		m.w16(e+4, 0x4e75) // RTS
	}
	m.w8(base+Node_ln_Type, nodeType)
	m.w32(base+Node_ln_Name, m.PutString(name))
	m.w16(base+Library_lib_NegSize, uint16(neg))
	m.w16(base+Library_lib_PosSize, uint16(posSize))
	m.w16(base+Library_lib_Version, version)
	m.w32(base+Library_lib_IdString, m.PutString(fmt.Sprintf("%s %d.0 (AmiScan)", name, version)))
	m.w16(base+Library_lib_OpenCnt, 1)
	f := &fakeLib{name: name, base: base, funcs: map[string]func(){}}
	m.libs = append(m.libs, f)
	return f
}

// AddFakeLibrary adds a Go library to the system list; its calls all
// return 0 unless funcs fills them in.
func (m *Machine) AddFakeLibrary(name string, version uint16) *fakeLib {
	f := m.newFakeLib(name, version, 64, NTLibrary)
	m.AddTail(m.SysBase+ExecBase_LibList, f.base)
	return f
}

// AddFakeDevice puts a device node in the device list (xvs.library will
// not start without trackdisk.device).
func (m *Machine) AddFakeDevice(name string) *fakeLib {
	f := m.newFakeLib(name, 40, 64, NTDevice)
	m.AddTail(m.SysBase+ExecBase_DeviceList, f.base)
	return f
}

func (m *Machine) setupExec() {
	exec := m.newFakeLib("exec.library", 40, SizeofExecBase, NTLibrary)
	sb := exec.base
	m.SysBase = sb
	m.w32(4, sb)
	m.w16(sb+Library_lib_Revision, 68)
	m.w16(sb+ExecBase_SoftVer, 68)
	m.w16(sb+ExecBase_AttnFlags, 0x0003) // AFF_68010 | AFF_68020
	m.w8(sb+ExecBase_IDNestCnt, 0xff)
	m.w8(sb+ExecBase_TDNestCnt, 0xff)
	m.w8(sb+ExecBase_VBlankFrequency, 50)
	m.w8(sb+ExecBase_PowerSupplyFrequency, 50)
	m.w32(sb+ExecBase_ex_EClockFrequency, 709379)
	for _, l := range []struct {
		off uint32
		typ uint8
	}{
		{ExecBase_MemList, NTMemory}, {ExecBase_ResourceList, 8}, {ExecBase_DeviceList, NTDevice},
		{ExecBase_IntrList, 2}, {ExecBase_LibList, NTLibrary}, {ExecBase_PortList, 4},
		{ExecBase_TaskReady, NTTask}, {ExecBase_TaskWait, NTTask}, {ExecBase_SemaphoreList, NTSignalSem},
	} {
		m.NewList(sb+l.off, l.typ)
	}
	m.AddTail(sb+ExecBase_LibList, sb)
	// one memory header covering the heap, so TypeOfMem and friends work
	mh := m.Alloc(SizeofMemHeader, true)
	m.w8(mh+Node_ln_Type, NTMemory)
	m.w32(mh+Node_ln_Name, m.PutString("fast memory"))
	m.w16(mh+MemHeader_mh_Attributes, memfPublic|memfFast)
	m.w32(mh+MemHeader_mh_Lower, heapStart)
	m.w32(mh+MemHeader_mh_Upper, heapEnd)
	m.AddTail(sb+ExecBase_MemList, mh)
	m.w32(sb+ExecBase_ResModules, m.Alloc(4, true)) // empty, NULL-terminated

	// the one process everything runs in
	t := m.Alloc(SizeofProcess, true)
	m.w8(t+Node_ln_Type, NTProcess)
	m.w32(t+Node_ln_Name, m.PutString("AmiScan"))
	m.w8(t+Task_tc_State, 2) // running
	m.w32(t+Task_tc_SigAlloc, 0xffff)
	m.w32(t+Task_tc_SPLower, userStack-stackSize+0x200)
	m.w32(t+Task_tc_SPUpper, userStack)
	m.w32(t+Process_pr_WindowPtr, 0xffffffff) // no requesters
	m.task = t
	m.w32(sb+ExecBase_ThisTask, t)

	c := m.CPU
	d := func(n int) uint32 { return c.D(n) }
	a := func(n int) uint32 { return c.A(n) }
	ret := func(v uint32) { c.SetD(0, v) }
	nest := func(off uint32, delta int8) {
		m.w8(sb+off, uint8(int8(m.r8(sb+off))+delta))
	}
	f := exec.funcs
	f["Forbid"] = func() { nest(ExecBase_TDNestCnt, 1) }
	f["Permit"] = func() { nest(ExecBase_TDNestCnt, -1) }
	f["Disable"] = func() { nest(ExecBase_IDNestCnt, 1) }
	f["Enable"] = func() { nest(ExecBase_IDNestCnt, -1) }
	f["SetSR"] = func() { ret(0) }
	f["CacheClearU"] = func() {}
	f["CacheClearE"] = func() {}
	f["CacheControl"] = func() { ret(0) }
	f["AllocMem"] = func() { ret(m.allocMem(d(0), d(1), false)) }
	f["AllocVec"] = func() { ret(m.allocMem(d(0), d(1), true)) }
	f["FreeMem"] = func() { m.Free(a(1)) }
	f["FreeVec"] = func() {
		if a(1) != 0 {
			m.Free(a(1) - 8)
		}
	}
	f["AvailMem"] = func() {
		total, largest := m.heap.available()
		if d(1)&memfLargest != 0 {
			ret(largest)
		} else if d(1)&memfChip != 0 {
			ret(0)
		} else {
			ret(total)
		}
	}
	f["TypeOfMem"] = func() {
		if a(1) >= heapStart && a(1) < heapEnd {
			ret(memfPublic | memfFast)
		} else {
			ret(0)
		}
	}
	f["Allocate"] = func() { ret(m.allocate(a(0), d(0))) }
	f["Deallocate"] = func() { m.deallocate(a(0), a(1), d(0)) }
	f["CopyMem"] = func() { copy(c.RAM[a(1):a(1)+d(0)], c.RAM[a(0):a(0)+d(0)]) }
	f["CopyMemQuick"] = f["CopyMem"]
	f["AddHead"] = func() { m.AddHead(a(0), a(1)) }
	f["AddTail"] = func() { m.AddTail(a(0), a(1)) }
	f["Remove"] = func() { m.Remove(a(1)) }
	f["RemHead"] = func() { ret(m.RemHead(a(0))) }
	f["RemTail"] = func() { ret(m.RemTail(a(0))) }
	f["Enqueue"] = func() { m.Enqueue(a(0), a(1)) }
	f["Insert"] = func() {
		// Insert(list, node, pred): after pred, or at the head if pred is 0
		if a(2) == 0 {
			m.AddHead(a(0), a(1))
			return
		}
		next := m.r32(a(2) + Node_ln_Succ)
		m.w32(a(1)+Node_ln_Succ, next)
		m.w32(a(1)+Node_ln_Pred, a(2))
		m.w32(next+Node_ln_Pred, a(1))
		m.w32(a(2)+Node_ln_Succ, a(1))
	}
	f["FindName"] = func() { ret(m.FindName(a(0), m.CString(a(1)))) }
	f["FindTask"] = func() {
		if a(1) == 0 || m.CString(a(1)) == "AmiScan" {
			ret(t)
		} else {
			ret(0)
		}
	}
	f["SetTaskPri"] = func() { ret(0) }
	f["SetSignal"] = func() {
		old := m.r32(t + Task_tc_SigRecvd)
		m.w32(t+Task_tc_SigRecvd, (old&^d(1))|(d(0)&d(1)))
		ret(old)
	}
	f["AllocSignal"] = func() {
		alloc := m.r32(t + Task_tc_SigAlloc)
		want := int32(d(0))
		for i := int32(16); i < 32; i++ {
			if (want == -1 || want == i) && alloc&(1<<i) == 0 {
				m.w32(t+Task_tc_SigAlloc, alloc|1<<i)
				ret(uint32(i))
				return
			}
		}
		ret(0xffffffff)
	}
	f["FreeSignal"] = func() {
		if int32(d(0)) >= 0 {
			m.w32(t+Task_tc_SigAlloc, m.r32(t+Task_tc_SigAlloc)&^(1<<d(0)))
		}
	}
	f["Wait"] = func() {
		// a single task cannot wait; whatever it waits for has arrived
		ret(d(0))
	}
	f["Signal"] = func() {}
	f["InitSemaphore"] = func() {
		s := a(0)
		ramClear(c.RAM[s+Node_ln_Type : s+SizeofSignalSemaphore])
		m.w8(s+Node_ln_Type, NTSignalSem)
		m.NewList(s+16, 0) // ss_WaitQueue (a MinList)
		m.w16(s+SignalSemaphore_ss_QueueCount, 0xffff)
	}
	obtain := func(s uint32) {
		m.w16(s+SignalSemaphore_ss_NestCount, m.r16(s+SignalSemaphore_ss_NestCount)+1)
		m.w16(s+SignalSemaphore_ss_QueueCount, m.r16(s+SignalSemaphore_ss_QueueCount)+1)
		m.w32(s+SignalSemaphore_ss_Owner, t)
	}
	f["ObtainSemaphore"] = func() { obtain(a(0)) }
	f["ObtainSemaphoreShared"] = f["ObtainSemaphore"]
	f["AttemptSemaphore"] = func() { obtain(a(0)); ret(1) }
	f["AttemptSemaphoreShared"] = f["AttemptSemaphore"]
	f["ReleaseSemaphore"] = func() {
		s := a(0)
		n := m.r16(s+SignalSemaphore_ss_NestCount) - 1
		m.w16(s+SignalSemaphore_ss_NestCount, n)
		m.w16(s+SignalSemaphore_ss_QueueCount, m.r16(s+SignalSemaphore_ss_QueueCount)-1)
		if n == 0 {
			m.w32(s+SignalSemaphore_ss_Owner, 0)
		}
	}
	f["AddSemaphore"] = func() { f["InitSemaphore"](); m.Enqueue(sb+ExecBase_SemaphoreList, a(1)) }
	f["FindSemaphore"] = func() { ret(m.FindName(sb+ExecBase_SemaphoreList, m.CString(a(1)))) }
	f["FindResident"] = func() { ret(0) }
	f["FindPort"] = func() { ret(m.FindName(sb+ExecBase_PortList, m.CString(a(1)))) }
	open := func(name string, version uint32) uint32 {
		l := m.FindName(sb+ExecBase_LibList, name)
		if l == 0 || uint32(m.r16(l+Library_lib_Version)) < version {
			if m.Trace || l != 0 {
				m.warnf("OpenLibrary(%q, %d): not available", name, version)
			}
			return 0
		}
		m.w16(l+Library_lib_OpenCnt, m.r16(l+Library_lib_OpenCnt)+1)
		return l
	}
	f["OpenLibrary"] = func() { ret(open(m.CString(a(1)), d(0))) }
	f["OldOpenLibrary"] = func() { ret(open(m.CString(a(1)), 0)) }
	f["CloseLibrary"] = func() {
		if l := a(1); l != 0 {
			m.w16(l+Library_lib_OpenCnt, m.r16(l+Library_lib_OpenCnt)-1)
		}
	}
	f["OpenResource"] = func() { ret(m.FindName(sb+ExecBase_ResourceList, m.CString(a(1)))) }
	f["OpenDevice"] = func() { ret(32) } // IOERR_OPENFAIL-ish: no devices here
	f["CloseDevice"] = func() {}
	ioDone := func() {
		if a(1) != 0 {
			m.w8(a(1)+IORequest_io_Error, 0xfe) // IOERR_NOCMD
		}
		ret(0xfe)
	}
	f["DoIO"] = ioDone
	f["SendIO"] = ioDone
	f["WaitIO"] = ioDone
	f["CheckIO"] = func() { ret(a(1)) }
	f["AbortIO"] = func() { ret(0) }
	f["GetMsg"] = func() { ret(m.RemHead(a(0) + 20)) } // mp_MsgList
	f["ReplyMsg"] = func() {}
	f["PutMsg"] = func() {}
	f["CreateMsgPort"] = func() {
		p := m.Alloc(34, true)
		m.w8(p+Node_ln_Type, 4)
		m.NewList(p+20, 5)
		ret(p)
	}
	f["DeleteMsgPort"] = func() {
		if a(0) != 0 {
			m.Free(a(0))
		}
	}
	f["CreateIORequest"] = func() {
		if a(0) == 0 {
			ret(0)
			return
		}
		r := m.Alloc(max(d(0), SizeofIORequest), true)
		m.w8(r+Node_ln_Type, 5)
		m.w32(r+14, a(0)) // mn_ReplyPort
		m.w16(r+18, uint16(d(0)))
		ret(r)
	}
	f["DeleteIORequest"] = func() {
		if a(0) != 0 {
			m.Free(a(0))
		}
	}
	f["SumLibrary"] = func() {}
	f["SetFunction"] = func() {
		// SetFunction(lib a1, offset a0, new d0): returns the old vector
		e := a(1) + a(0)
		old := m.r32(e + 2)
		m.w16(e, 0x4ef9)
		m.w32(e+2, d(0))
		ret(old)
	}
	f["MakeLibrary"] = func() {
		if a(2) != 0 {
			m.warnf("MakeLibrary with an init function is not supported")
			ret(0)
			return
		}
		ret(m.makeLibrary(a(0), a(1), d(0)))
	}
	f["MakeFunctions"] = func() { ret(m.makeFunctions(a(0), a(1), a(2))) }
	f["InitStruct"] = func() { m.initStruct(a(1), a(2), d(0)) }
	f["AddLibrary"] = func() { m.Enqueue(sb+ExecBase_LibList, a(1)) }
	f["AddDevice"] = func() { m.Enqueue(sb+ExecBase_DeviceList, a(1)) }
	f["AddResource"] = func() { m.Enqueue(sb+ExecBase_ResourceList, a(1)) }
	f["AddPort"] = func() { m.NewList(a(1)+20, 5); m.Enqueue(sb+ExecBase_PortList, a(1)) }
	f["RemPort"] = func() { m.Remove(a(1)) }
	f["RemLibrary"] = func() { m.Remove(a(1)); ret(0) }
	f["Alert"] = func() { m.CPU.Fail(fmt.Errorf("guest called Alert($%08x)", d(7))) }
	f["Debug"] = func() {}
	f["RawDoFmt"] = func() { m.warnf("RawDoFmt not emulated"); ret(a(0)) }
	f["CreatePool"] = func() {
		p := m.Alloc(8, true)
		m.w32(p, d(1)) // remember the flags
		ret(p)
	}
	f["DeletePool"] = func() {}
	f["AllocPooled"] = func() { ret(m.allocMem(d(0), m.r32(a(0))|memfClear, false)) }
	f["FreePooled"] = func() { m.Free(a(1)) }
	f["AllocVecPooled"] = func() { ret(m.allocMem(d(0), memfClear, true)) }
	f["FreeVecPooled"] = func() {
		if a(1) != 0 {
			m.Free(a(1) - 8)
		}
	}
}

// Memory flags.
const (
	memfPublic  = 1 << 0
	memfChip    = 1 << 1
	memfFast    = 1 << 2
	memfClear   = 1 << 16
	memfLargest = 1 << 17
)

// allocMem is AllocMem / AllocVec (vec stores the size in front).
func (m *Machine) allocMem(size, flags uint32, vec bool) uint32 {
	if size == 0 || size > RAMSize {
		return 0
	}
	if !vec {
		return m.Alloc(size, flags&memfClear != 0)
	}
	p := m.Alloc(size+8, flags&memfClear != 0)
	if p == 0 {
		return 0
	}
	m.w32(p, size+8)
	return p + 8
}

// allocate is exec's Allocate on a guest MemHeader, chunk for chunk like
// the ROM, because the caller set up and may inspect the header itself.
func (m *Machine) allocate(mh, size uint32) uint32 {
	if size == 0 {
		return 0
	}
	size = (size + 7) &^ 7
	if size > m.r32(mh+MemHeader_mh_Free) {
		return 0
	}
	prev := mh + MemHeader_mh_First
	for ch := m.r32(prev); ch != 0; prev, ch = ch, m.r32(ch+MemChunk_mc_Next) {
		bytes := m.r32(ch + MemChunk_mc_Bytes)
		if bytes < size {
			continue
		}
		if bytes == size {
			m.w32(prev, m.r32(ch+MemChunk_mc_Next))
		} else {
			rest := ch + size
			m.w32(rest+MemChunk_mc_Next, m.r32(ch+MemChunk_mc_Next))
			m.w32(rest+MemChunk_mc_Bytes, bytes-size)
			m.w32(prev, rest)
		}
		m.w32(mh+MemHeader_mh_Free, m.r32(mh+MemHeader_mh_Free)-size)
		return ch
	}
	return 0
}

// deallocate is exec's Deallocate: insert sorted and merge neighbours.
func (m *Machine) deallocate(mh, block, size uint32) {
	if block == 0 || size == 0 {
		return
	}
	size = ((block & 7) + size + 7) &^ 7
	block &^= 7
	head := mh + MemHeader_mh_First // acts as a chunk whose mc_Next is mh_First
	prev := head
	next := m.r32(prev)
	for next != 0 && next < block {
		prev, next = next, m.r32(next+MemChunk_mc_Next)
	}
	m.w32(mh+MemHeader_mh_Free, m.r32(mh+MemHeader_mh_Free)+size)
	if next != 0 && block+size == next {
		size += m.r32(next + MemChunk_mc_Bytes)
		next = m.r32(next + MemChunk_mc_Next)
	}
	if prev != head && prev+m.r32(prev+MemChunk_mc_Bytes) == block {
		m.w32(prev+MemChunk_mc_Bytes, m.r32(prev+MemChunk_mc_Bytes)+size)
		m.w32(prev+MemChunk_mc_Next, next)
		return
	}
	m.w32(block+MemChunk_mc_Next, next)
	m.w32(block+MemChunk_mc_Bytes, size)
	m.w32(prev, block)
}
