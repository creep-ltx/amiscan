#include "glue.h"
#include "musashi/m68k.h"
#ifdef _WIN32
#include <windows.h>
#else
#include <sys/mman.h>
#endif

uint8_t *amiscan_ram;
uint32_t amiscan_ram_size;
uint32_t amiscan_bad_accesses;
uint32_t amiscan_last_bad;
uint32_t amiscan_hw_accesses;

extern int goIllegal(unsigned int opcode); // cpu.go

// Full 32-bit addresses (a 68020 with fast RAM above 16 MB).
#define ADDR(a) (a)

static inline int is_hw(uint32_t a) {
	// CIA ($BFxxxx) and custom chips ($DFxxxx). xvs.library peeks at
	// VHPOSR for a random value; reading 0 is good enough.
	return (a >= 0xbf0000 && a < 0xc00000) || (a >= 0xdf0000 && a < 0xe00000);
}

static inline int ok(uint32_t a, uint32_t n) {
	if (is_hw(a)) { amiscan_hw_accesses++; return 0; }
	if ((uint64_t)a + n <= amiscan_ram_size) return 1;
	amiscan_bad_accesses++; amiscan_last_bad = a;
	return 0;
}

unsigned int m68k_read_memory_8(unsigned int a) {
	a = ADDR(a);
	return ok(a, 1) ? amiscan_ram[a] : 0;
}
unsigned int m68k_read_memory_16(unsigned int a) {
	a = ADDR(a);
	if (!ok(a, 2)) return 0;
	return (amiscan_ram[a] << 8) | amiscan_ram[a + 1];
}
unsigned int m68k_read_memory_32(unsigned int a) {
	a = ADDR(a);
	if (!ok(a, 4)) return 0;
	uint8_t *p = amiscan_ram + a;
	return ((uint32_t)p[0] << 24) | (p[1] << 16) | (p[2] << 8) | p[3];
}
void m68k_write_memory_8(unsigned int a, unsigned int v) {
	a = ADDR(a);
	if (ok(a, 1)) amiscan_ram[a] = v;
}
void m68k_write_memory_16(unsigned int a, unsigned int v) {
	a = ADDR(a);
	if (ok(a, 2)) { amiscan_ram[a] = v >> 8; amiscan_ram[a + 1] = v; }
}
void m68k_write_memory_32(unsigned int a, unsigned int v) {
	a = ADDR(a);
	if (ok(a, 4)) {
		uint8_t *p = amiscan_ram + a;
		p[0] = v >> 24; p[1] = v >> 16; p[2] = v >> 8; p[3] = v;
	}
}
unsigned int m68k_read_disassembler_8(unsigned int a) { return m68k_read_memory_8(a); }
unsigned int m68k_read_disassembler_16(unsigned int a) { return m68k_read_memory_16(a); }
unsigned int m68k_read_disassembler_32(unsigned int a) { return m68k_read_memory_32(a); }

static int illg(int opcode) { return goIllegal(opcode); }

// RAM is reserved address space: the host only spends memory on the
// pages the guest touches, and amiscan_discard gives them back (the
// guest then reads zeros there).
#ifdef _WIN32
uint8_t *amiscan_map_ram(uint32_t size) {
	// committed pages are zero and only become real memory when touched
	return VirtualAlloc(0, size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
}

void amiscan_discard(uint32_t addr, uint32_t len) {
	uint64_t page = 4096, lo = ((uint64_t)addr + page - 1) & ~(page - 1), hi = ((uint64_t)addr + len) & ~(page - 1);
	if (hi > lo && hi <= amiscan_ram_size) {
		VirtualFree(amiscan_ram + lo, hi - lo, MEM_DECOMMIT);
		VirtualAlloc(amiscan_ram + lo, hi - lo, MEM_COMMIT, PAGE_READWRITE);
	}
}
#else
#ifndef MAP_NORESERVE
#define MAP_NORESERVE 0
#endif
#ifndef MAP_ANONYMOUS
#define MAP_ANONYMOUS MAP_ANON
#endif
uint8_t *amiscan_map_ram(uint32_t size) {
	void *p = mmap(0, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
	return p == MAP_FAILED ? 0 : p;
}

void amiscan_discard(uint32_t addr, uint32_t len) {
	// fresh zero pages over the range: madvise(MADV_DONTNEED) would do on
	// Linux, but on macOS it does not promise zeros
	uint64_t page = 4096, lo = ((uint64_t)addr + page - 1) & ~(page - 1), hi = ((uint64_t)addr + len) & ~(page - 1);
	if (hi > lo && hi <= amiscan_ram_size)
		mmap(amiscan_ram + lo, hi - lo, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE | MAP_FIXED, -1, 0);
}
#endif

void amiscan_init(uint8_t *ram, uint32_t size, int cpu_type) {
	amiscan_ram = ram;
	amiscan_ram_size = size;
	m68k_init();
	m68k_set_cpu_type(cpu_type);
	m68k_set_illg_instr_callback(illg);
	m68k_pulse_reset();
}

int amiscan_execute(int cycles) { return m68k_execute(cycles); }
