#include <stdint.h>

struct miniperf_header {
	uint64_t magic;
	uint64_t reserved;
	uint64_t sample_type;
};

#define MINIPERF_MAGIC 0x66726550696e694dULL

#define MINIPERF_HEADER_INIT(sample) { \
	.magic = MINIPERF_MAGIC,       \
	.reserved = 0,                 \
	.sample_type = sample          \
}
