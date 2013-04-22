#define _GNU_SOURCE
#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <inttypes.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>
#include "perf_event.h"
#include "perf.h"
#include "miniperf.h"

#ifdef NO_GETLINE
static ssize_t minigetline(char **lineptr, size_t *n, FILE *stream);
#define getline minigetline
#endif

struct perf_info_mmap {
	uint32_t pid, tid;
	uint64_t addr, len, offset;
};

struct perf_info_comm {
	uint32_t pid, tid;
};

struct our_sample_id_all {
	uint32_t pid, tid;
	uint64_t time;
	uint32_t cpu, res;
};

#define ROUNDUP8(x) (((x) + 7) & ~7)
static const char zeroes[7] = { 0, 0, 0, 0, 0, 0, 0 };

#define BUF_PAGES_SHIFT 5
#define BUF_PAGES (1UL << BUF_PAGES_SHIFT)

static FILE *outfile;
static volatile sig_atomic_t exiting = 0;

static void
start_exiting(int unused)
{
	exiting = 1;
}


static void
synthetic_mmap(const struct perf_info_mmap *event,
    const struct our_sample_id_all *id,
    const char *name, uint16_t misc)
{
	struct perf_event_header header;
	size_t namelen;

	namelen = strlen(name) + 1;
	header.type = PERF_RECORD_MMAP;
	header.misc = misc;
	header.size = sizeof(header) + sizeof(*event) + ROUNDUP8(namelen)
	    + sizeof(*id);

	fwrite(&header, sizeof(header), 1, outfile);
	fwrite(event, sizeof(*event), 1, outfile);
	fwrite(name, namelen, 1, outfile);
	fwrite(zeroes, ROUNDUP8(namelen) - namelen, 1, outfile);
	fwrite(id, sizeof(*id), 1, outfile);
}

static void
synthetic_comm(const struct perf_info_comm *event,
    const struct our_sample_id_all *id,
    const char *name, uint16_t misc)
{
	struct perf_event_header header;
	size_t namelen;

	namelen = strlen(name) + 1;
	header.type = PERF_RECORD_COMM;
	header.misc = misc;
	header.size = sizeof(header) + sizeof(*event) + ROUNDUP8(namelen)
	    + sizeof(*id);

	fwrite(&header, sizeof(header), 1, outfile);
	fwrite(event, sizeof(*event), 1, outfile);
	fwrite(name, namelen, 1, outfile);
	fwrite(zeroes, ROUNDUP8(namelen) - namelen, 1, outfile);
	fwrite(id, sizeof(*id), 1, outfile);
}


static void
synthetic_mmaps_for_pid(uint32_t pid)
{
	struct perf_info_mmap info;
	struct our_sample_id_all id;
	char *name = NULL;
	char *linebuf = NULL;
	size_t linebufsize;
	FILE *maps;

	id.time = 0;
	id.cpu = id.res = 0;
	id.pid = id.tid = info.pid = info.tid = pid;
	asprintf(&name, "/proc/%"PRIu32"/maps", pid);
	maps = fopen(name, "r");
	if (!maps) {
		fprintf(stderr, "fopen: %s: %s\n", name, strerror(errno));
		free(name);
		return;
	};
	free(name);
	for (;;) {
		ssize_t linesize;
		char prot[5];
		int nameoff = -1;

		linesize = getline(&linebuf, &linebufsize, maps);
		if (linesize <= 0)
			break;
		linebuf[linesize - 1] = '\0';

		sscanf(linebuf,
		    "%"PRIx64"-%"PRIx64" %4s %"PRIx64" %*x:%*x %*u %n",
		    &info.addr, &info.len, prot, &info.offset, &nameoff);
		if (nameoff < 0) {
			fprintf(stderr,
			    "Bad line in /proc/%"PRIu32"/maps: %s\n",
			    pid, linebuf);
			continue;
		}
		info.len -= info.addr;
		if (strchr(prot, 'x'))
			synthetic_mmap(&info, &id, linebuf + nameoff,
			    PERF_RECORD_MISC_USER);
	}
	free(linebuf);
	fclose(maps);
}

static void
synthetic_comms_for_pid(uint32_t pid)
{
	struct perf_info_comm info;
	struct our_sample_id_all id;
	FILE *file;
	DIR *dir;
	char *name;
	struct dirent *dirent;
	char *linebuf = NULL;
	size_t linebufsize;

	id.time = 0;
	id.cpu = id.res = 0;
	id.pid = info.pid = pid;
	asprintf(&name, "/proc/%d/task", pid);
	dir = opendir(name);
	if (!dir) {
		fprintf(stderr, "opendir: %s: %s\n", name, strerror(errno));
		free(name);
		return;
	}
	free(name);
	while ((dirent = readdir(dir))) {
		ssize_t linesize;
		uint32_t tid;

		if (sscanf(dirent->d_name, "%"PRIu32, &tid) < 1)
			continue;
		asprintf(&name, "/proc/%s/comm", dirent->d_name);
		file = fopen(name, "r");
		if (!file) {
			fprintf(stderr, "fopen: %s: %s\n", name,
			    strerror(errno));
			free(name);
			continue;
		}
		free(name);
		name = NULL;
		linesize = getline(&linebuf, &linebufsize, file);
		fclose(file);
		if (linesize <= 0)
			continue;

		linebuf[linesize - 1] = '\0';
		id.tid = info.tid = tid;
		synthetic_comm(&info, &id, linebuf, PERF_RECORD_MISC_USER);
	}
	free(linebuf);
	closedir(dir);
}

struct kmodule {
	uint64_t start;
	char *name;
};

static int
kmodule_cmp(const void *a, const void *b) {
	uint64_t as, bs;

	as = ((const struct kmodule *)a)->start;
	bs = ((const struct kmodule *)b)->start;
	return as < bs ? -1 : as > bs ? 1 : 0;
}

static void
synthetic_mmaps_for_kernel(void)
{
	static const char *kmodname = "[kernel.kallsyms]_text";
	struct perf_info_mmap info;
	struct our_sample_id_all id;
	FILE *modules, *kallsyms;
	char *linebuf = NULL;
	size_t linebufsize;
	struct kmodule *mod_acc;
	size_t mod_read, mod_alloc, i;

	kallsyms = fopen("/proc/kallsyms", "r");
	if (!kallsyms) {
		fprintf(stderr, "fopen: %s: %s\n", "/proc/kallsyms",
		    strerror(errno));
		return;
	}
	mod_acc = malloc(sizeof(mod_acc[0]));
	mod_alloc = 1;
	mod_read = 1;
	mod_acc[0].start = 0;
	mod_acc[0].name = strdup(kmodname);
	for (;;) {
		ssize_t linesize;
		linesize = getline(&linebuf, &linebufsize, kallsyms);
		if (linesize <= 0)
			break;
		if (strchr(linebuf, '\t'))
			// Can this actually happen?
			continue;
		mod_acc[0].start = strtoull(linebuf, NULL, 16);
		break;
	}
	fclose(kallsyms);

	modules = fopen("/proc/modules", "r");
	if (!modules) {
		fprintf(stderr, "fopen: %s: %s\n", "/proc/modules",
		    strerror(errno));
		return;
	}

	for (;;) {
		struct kmodule thismod;
		ssize_t linesize;
		char *space;

		linesize = getline(&linebuf, &linebufsize, modules);
		if (linesize <= 0)
			break;
		linebuf[linesize - 1] = '\0';
		space = strchr(linebuf, ' ');
		if (!space)
			continue;
		*space = '\0';
		if (sscanf(space + 1, "%*s %*s %*s %*s %"PRIx64,
			&thismod.start) < 1)
			continue;
		asprintf(&thismod.name, "[%s]", linebuf);
		if (mod_read >= mod_alloc) {
			mod_alloc = mod_alloc * 2 + 1;
			mod_acc = realloc(mod_acc, mod_alloc
			    * sizeof(mod_acc[0]));
		}
		mod_acc[mod_read++] = thismod;
	}
	free(linebuf);
	fclose(modules);
	qsort(mod_acc, mod_read, sizeof(mod_acc[0]), kmodule_cmp);

	id.time = 0;
	id.cpu = id.res = 0;
	id.pid = info.pid = -1;
	id.tid = info.tid = 0;
	info.offset = 0;
	for (i = 0; i < mod_read; ++i) {
		const char* fixed_name;
		uint64_t modend;

		modend = i + 1 < mod_read ? mod_acc[i + 1].start : 0;
		info.addr = mod_acc[i].start;
		info.len = modend - info.addr;
		synthetic_mmap(&info, &id, mod_acc[i].name,
		    PERF_RECORD_MISC_KERNEL);
		free(mod_acc[i].name);
	}
	free(mod_acc);
}

static uint32_t *pidmap = NULL;
static uint32_t pidsize = 0;

static void
enlarge_pidmap(uint32_t pid)
{
	uint32_t newsize = pidsize;

	while (pid >= newsize)
		newsize = newsize > 0 ? newsize * 2 : 512;
	if (newsize == pidsize)
		return;
	pidmap = realloc(pidmap, newsize / 8);
	memset(pidmap + pidsize / 32, 0, (newsize - pidsize) / 8);
	pidsize = newsize;
}

static int
test_pid(uint32_t pid)
{
	enlarge_pidmap(pid);
	return !!(pidmap[pid / 32] & (((uint32_t)1) << (pid % 32)));
}

static int
mark_pid(uint32_t pid)
{
	enlarge_pidmap(pid);
	return pidmap[pid / 32] |= ((uint32_t)1) << (pid % 32);
}

static size_t
event_snoop(uint8_t *ring, size_t ringsize, size_t idx)
{
	static uint32_t pid, ppid;

	struct perf_event_header *header;
	uint32_t *idptr;

	header = (struct perf_event_header *)(ring + (idx % ringsize));
	switch (header->type) {
	case PERF_RECORD_SAMPLE:
		idptr = (uint32_t *)(ring +
		    (idx + sizeof(*header) + 8) % ringsize);
		pid = idptr[0];
		if (!test_pid(pid)) {
			synthetic_comms_for_pid(pid);
			synthetic_mmaps_for_pid(pid);
			mark_pid(pid);
		}
		break;
	case PERF_RECORD_FORK:
		idptr = (uint32_t *)(ring +
		    (idx + sizeof(*header)) % ringsize);
		pid = idptr[0];
		ppid = idptr[1];
		if (!test_pid(ppid)) {
			synthetic_comms_for_pid(ppid);
			synthetic_mmaps_for_pid(ppid);
			mark_pid(ppid);
		}
		mark_pid(pid);
		break;
	}
	return header->size;
}


int
main(int argc, char **argv)
{
	int cpus, i, live;
	size_t page_size, buf_size;
	struct pollfd *fds;
	volatile struct perf_event_mmap_page **bufs;
	const uint64_t sample_type =
	    PERF_SAMPLE_IP |
	    PERF_SAMPLE_TID |
	    PERF_SAMPLE_TIME |
	    PERF_SAMPLE_CALLCHAIN |
	    PERF_SAMPLE_CPU |
	    PERF_SAMPLE_PERIOD;
	const struct miniperf_header header =
	    MINIPERF_HEADER_INIT(sample_type);

	umask(0077);
	outfile = fopen("miniperf.data", "wb");
	if (!outfile) {
		fprintf(stderr, "fopen: %s: %s\n", "miniperf.data",
		    strerror(errno));
		return 1;
	}

	cpus = sysconf(_SC_NPROCESSORS_CONF);
	page_size = sysconf(_SC_PAGESIZE);
	buf_size = page_size * BUF_PAGES;
	fds = calloc(cpus, sizeof(fds[0]));
	bufs = calloc(cpus, sizeof(bufs[0]));
	for (i = 0; i < cpus; ++i) {
		struct perf_event_attr attr;

		memset(&attr, 0, sizeof(attr));
		attr.type = PERF_TYPE_HARDWARE;
		attr.size = sizeof(struct perf_event_attr);
		attr.config = PERF_COUNT_HW_CPU_CYCLES;
		attr.freq = 1;
		attr.sample_freq = 4000;
		attr.sample_type = sample_type;
		attr.read_format = 0;
		attr.inherit = 1;
		attr.mmap = 1;
		attr.comm = 1;
		attr.task = 1;
		attr.precise_ip = 0; // ???
		attr.sample_id_all = 1; // ???

		fds[i].fd = syscall(__NR_perf_event_open, &attr, -1, i, -1, 0);
		if (fds[i].fd < 0) {
			perror("perf_event_open");
			return 1;
		}
		fds[i].events = POLLIN;
		bufs[i] = mmap(NULL, page_size + buf_size,
		    PROT_READ | PROT_WRITE, MAP_SHARED, fds[i].fd, 0);
		if (bufs[i] == MAP_FAILED) {
			perror("mmap");
			return 1;
		}
		// TODO: map a guard page here to protect me from myself?
	}

	signal(SIGINT, start_exiting);
	signal(SIGHUP, start_exiting);

	fwrite(&header, sizeof(header), 1, outfile);
	synthetic_mmaps_for_kernel();
	mark_pid(0);
	do {
		live = cpus;
		if (!exiting)
			poll(fds, cpus, -1);
		for (i = 0; i < cpus; ++i) {
			uint8_t *base;
			uint64_t head, tail;

			if (!exiting && (fds[i].revents & POLLIN) == 0)
				continue;
			if (exiting) {
				ioctl(fds[i].fd, PERF_EVENT_IOC_DISABLE);
			}

#ifdef DEBUG
			fprintf(stderr, "CPU%d %s.\n", i,
			    exiting ? "will be drained" : "has stuff");
#endif

			base = (void *)((uintptr_t)(bufs[i]) + page_size);
			head = bufs[i]->data_head;
			tail = bufs[i]->data_tail;
			rmb();
			while (head > tail) {
				size_t to_write;

				to_write = event_snoop(base, buf_size, tail);
				assert(to_write > 0);
				while (to_write > 0) {
					size_t end, written;

					end = tail + to_write;
					if (end / buf_size != tail / buf_size)
						end = (end / buf_size)
						    * buf_size;
					written =
					    fwrite(base + (tail % buf_size),
						1, end - tail, outfile);
					if (written == 0) {
						perror("fwrite");
						return 1;
					}
					tail += written;
					to_write -= written;
				}
				bufs[i]->data_tail = tail;
			}
			if (exiting) {
				head = bufs[i]->data_head;
				rmb();
				if (head == tail)
					--live;
			}
		}
	} while (live > 0);
	return 0;
}


#ifdef NO_GETLINE
static ssize_t
minigetline(char **lineptr, size_t *n, FILE *stream)
{
	char *rv;
	size_t so_far = 0;

	if (!*lineptr) {
		*n = 64;
		*lineptr = malloc(*n);
	}
	for (;;) {
		size_t this_time;

		rv = fgets(*lineptr + so_far, *n - 1 - so_far, stream);
		if (!rv) {
			if (so_far == 0) {
				return -1;
			} else {
				break;
			}
		}
		this_time = strlen(*lineptr + so_far);
		so_far += this_time;
		if ((*lineptr)[so_far - 1] == '\n') {
			break;
		}
		*n *= 2;
		*lineptr = realloc(*lineptr, *n);
	}
	if ((*lineptr)[so_far - 1] != '\n') {
		so_far++;
		(*lineptr)[so_far - 1] = '\n';
		(*lineptr)[so_far] = '\0';
	}
	return so_far;
}
#endif
