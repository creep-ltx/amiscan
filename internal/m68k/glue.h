#ifndef AMISCAN_GLUE_H
#define AMISCAN_GLUE_H
#include <stdint.h>

// Guest RAM is one flat block from address 0. Accesses outside it read 0
// and are counted, so a wild pointer never touches host memory.
extern uint8_t *amiscan_ram;
extern uint32_t amiscan_ram_size;
extern uint32_t amiscan_bad_accesses;
extern uint32_t amiscan_last_bad;
extern uint32_t amiscan_hw_accesses;

void amiscan_init(uint8_t *ram, uint32_t size, int cpu_type);
int amiscan_execute(int cycles);
#endif
