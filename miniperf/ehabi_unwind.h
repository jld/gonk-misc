#include <stdint.h>

typedef struct EHAddrSpace* ehabi_addrspace;

ehabi_addrspace ehabi_addrspace_alloc(void);
void ehabi_addrspace_free(void);
void ehabi_mmap(ehabi_addrspace space, uint32_t addr, uint32_t len,
    const char *path, uint32_t offset);
ehabi_addrspace ehabi_fork(ehabi_addrspace space);

size_t ehabi_unwind(ehabi_addrspace space, const uint32_t regs[16], 
    const void *stack, size_t stacksize, uint32_t *pcOut, size_t numPCs);
