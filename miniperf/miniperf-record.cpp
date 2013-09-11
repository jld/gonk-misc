#define __STDC_FORMAT_MACROS
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

#include <vector>
#include <algorithm>
#include <map>

#include "perf_event.h"
#include "perf.h"
#include "miniperf.h"
#include "ehabi_unwind.h"

static struct eventtab_elem {
	const char *name;
	// NOTE these next two fields could be abbreviated to save space
	uint32_t type;
	uint64_t config;
} eventtab[] = {
	{ "cpu-cycles",
	  PERF_TYPE_HARDWARE, PERF_COUNT_HW_CPU_CYCLES },
	{ "cycles",
	  PERF_TYPE_HARDWARE, PERF_COUNT_HW_CPU_CYCLES },
	{ "instructions",
	  PERF_TYPE_HARDWARE, PERF_COUNT_HW_INSTRUCTIONS },
	{ "cache-references",
	  PERF_TYPE_HARDWARE, PERF_COUNT_HW_CACHE_REFERENCES },
	{ "cache-misses",
	  PERF_TYPE_HARDWARE, PERF_COUNT_HW_CACHE_MISSES },
	{ "branch-instructions",
	  PERF_TYPE_HARDWARE, PERF_COUNT_HW_BRANCH_INSTRUCTIONS },
	{ "branches",
	  PERF_TYPE_HARDWARE, PERF_COUNT_HW_BRANCH_INSTRUCTIONS },
	{ "branch-misses",
	  PERF_TYPE_HARDWARE, PERF_COUNT_HW_BRANCH_MISSES },
	{ "bus-cycles",
	  PERF_TYPE_HARDWARE, PERF_COUNT_HW_BUS_CYCLES },
	{ "stalled-cycles-frontend",
	  PERF_TYPE_HARDWARE, PERF_COUNT_HW_STALLED_CYCLES_FRONTEND },
	{ "idle-cycles-frontend",
	  PERF_TYPE_HARDWARE, PERF_COUNT_HW_STALLED_CYCLES_FRONTEND },
	{ "stalled-cycles-backend",
	  PERF_TYPE_HARDWARE, PERF_COUNT_HW_STALLED_CYCLES_BACKEND },
	{ "idle-cycles-backend",
	  PERF_TYPE_HARDWARE, PERF_COUNT_HW_STALLED_CYCLES_BACKEND },

	{ "cpu-clock",
	  PERF_TYPE_SOFTWARE, PERF_COUNT_SW_CPU_CLOCK },
	{ "task-clock",
	  PERF_TYPE_SOFTWARE, PERF_COUNT_SW_TASK_CLOCK },
	{ "page-faults",
	  PERF_TYPE_SOFTWARE, PERF_COUNT_SW_PAGE_FAULTS },
	{ "faults",
	  PERF_TYPE_SOFTWARE, PERF_COUNT_SW_PAGE_FAULTS },
	{ "minor-faults",
	  PERF_TYPE_SOFTWARE, PERF_COUNT_SW_PAGE_FAULTS_MIN },
	{ "major-faults",
	  PERF_TYPE_SOFTWARE, PERF_COUNT_SW_PAGE_FAULTS_MAJ },
	{ "context-switches",
	  PERF_TYPE_SOFTWARE, PERF_COUNT_SW_CONTEXT_SWITCHES },
	{ "cs",
	  PERF_TYPE_SOFTWARE, PERF_COUNT_SW_CONTEXT_SWITCHES },
	{ "cpu-migrations",
	  PERF_TYPE_SOFTWARE, PERF_COUNT_SW_CPU_MIGRATIONS },
	{ "alignment-faults",
	  PERF_TYPE_SOFTWARE, PERF_COUNT_SW_ALIGNMENT_FAULTS },
	{ "emulation-faults",
	  PERF_TYPE_SOFTWARE, PERF_COUNT_SW_EMULATION_FAULTS }
};
static const int eventtab_len = sizeof(eventtab) / sizeof(eventtab[0]);


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

struct perf_info_fork {
	uint32_t pid, ppid;
	uint32_t tid, ptid;
	uint64_t time;
};

struct our_sample_id_all {
	uint32_t pid, tid;
	uint64_t time;
	uint32_t cpu, res;
};

#define ROUNDUP8(x) (((x) + 7) & ~7)
static const char zeroes[7] = { 0, 0, 0, 0, 0, 0, 0 };

static FILE *outfile;
static volatile sig_atomic_t exiting = 0;

static void
start_exiting(int unused)
{
	exiting = 1;
}


static std::map<uint32_t, EHAddrSpace *> pidmap;

static bool
test_pid(uint32_t pid)
{
	auto i = pidmap.find(pid);
	if (i == pidmap.end()) {
		pidmap[pid] = EHNewSpace();
		return false;
	}
	return true;
}

static void
fork_pid(uint32_t pid, uint32_t ppid)
{
	pidmap[pid] = EHForkSpace(pidmap[ppid]);
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
	EHAddrSpace *space = pidmap[pid];
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
		if (strchr(prot, 'x')) {
			const char *name = linebuf + nameoff;

			if (*name == '\0')
				name = "//anon";
			if (name[0] == '/' && name[1] != '/')
				EHAddMMap(space, info.addr, info.len, name, info.offset);
			synthetic_mmap(&info, &id, name, PERF_RECORD_MISC_USER);
		}
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

static bool operator<(const kmodule &a, const kmodule &b) {
	return a.start < b.start;
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
	std::vector<kmodule> mod_acc;

	kallsyms = fopen("/proc/kallsyms", "r");
	if (!kallsyms) {
		fprintf(stderr, "fopen: %s: %s\n", "/proc/kallsyms",
		    strerror(errno));
		return;
	}
	mod_acc.resize(1);
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
		mod_acc.push_back(thismod);
	}
	free(linebuf);
	fclose(modules);

	std::sort(mod_acc.begin(), mod_acc.end());

	id.time = 0;
	id.cpu = id.res = 0;
	id.pid = info.pid = -1;
	id.tid = info.tid = 0;
	info.offset = 0;
	for (size_t i = 0; i < mod_acc.size(); ++i) {
		uint64_t modend;

		modend = i + 1 < mod_acc.size() ? mod_acc[i + 1].start : 0;
		info.addr = mod_acc[i].start;
		info.len = modend - info.addr;
		synthetic_mmap(&info, &id, mod_acc[i].name,
		    PERF_RECORD_MISC_KERNEL);
		free(mod_acc[i].name);
		mod_acc[i].name = NULL;
	}
}

static size_t
event_write(uint8_t *ring, size_t ringsize, size_t idx)
{
	void *record = ring + (idx % ringsize);
	bool alloced = false;
	const perf_event_header *header =
	    reinterpret_cast<perf_event_header *>(record);

	if (idx / ringsize != (idx + header->size) / ringsize) {
		size_t first = ringsize - (idx % ringsize);

		record = malloc(header->size);
		alloced = true;
		memcpy(record, ring + (idx % ringsize), first);
		memcpy((char*)record + first, ring, header->size - first);
		header = reinterpret_cast<perf_event_header *>(record);
	}

	switch (header->type) {
	case PERF_RECORD_SAMPLE: {
		struct perf_sample {
			perf_event_header header;
			uint64_t ip;
			uint32_t pid, tid;
			uint64_t time;
			uint32_t cpu, res;
			uint64_t stack_nr;
			uint64_t stack[0];
		} *sample = reinterpret_cast<perf_sample *>(record);

		if (!test_pid(sample->pid)) {
			synthetic_comms_for_pid(sample->pid);
			synthetic_mmaps_for_pid(sample->pid);
		}
	}	break;
	case PERF_RECORD_FORK: {
		struct perf_fork {
			perf_event_header header;
			perf_info_fork info;
		} const *sample = reinterpret_cast<perf_fork *>(record);
		const perf_info_fork *info = &sample->info;

		if (!test_pid(info->ppid)) {
			synthetic_comms_for_pid(info->ppid);
			synthetic_mmaps_for_pid(info->ppid);
		}
		if (info->pid != info->ppid)
			fork_pid(info->pid, info->ppid);
	}	break;
	case PERF_RECORD_MMAP: {
		struct perf_mmap {
			perf_event_header header;
			perf_info_mmap info;
		} const *sample = reinterpret_cast<perf_mmap *>(record);
		const perf_info_mmap *info = &sample->info;
		const char *filename = reinterpret_cast<const char *>(&sample[1]);

		if ((header->misc & PERF_RECORD_MISC_CPUMODE_MASK)
		    == PERF_RECORD_MISC_USER
		    /* Assume the kernel won't give us an unterminated filename. */
		    && filename[0] == '/' && filename[1] != '/') {
			test_pid(info->pid);
			EHAddMMap(pidmap[info->pid], info->addr, info->len, filename,
			    info->offset);
		}
	}	break;
	}

	if (fwrite(record, header->size, 1, outfile) < 1) {
		perror("fwrite");
		exit(1);
	}
	size_t size = header->size;
	if (alloced)
		free(record);
	return size;
}


int
main(int argc, char **argv)
{
	int cpus, i, live, opt;
	size_t page_size, buf_size;
	struct pollfd *fds;
	struct miniperf_header header = MINIPERF_HEADER_INIT(0);
	volatile struct perf_event_mmap_page **bufs;
	struct perf_event_attr attr;
	const char *outfilename = "miniperf.data";
	size_t buf_pages = 32;
	char *cp;

	memset(&attr, 0, sizeof(attr));
	attr.type = PERF_TYPE_SOFTWARE;
	attr.size = sizeof(struct perf_event_attr);
	attr.config = PERF_COUNT_SW_CPU_CLOCK;
	attr.freq = 1;
	attr.sample_freq = 4000;
	attr.sample_type =
	    PERF_SAMPLE_IP |
	    PERF_SAMPLE_TID |
	    PERF_SAMPLE_TIME |
	    PERF_SAMPLE_CALLCHAIN |
	    PERF_SAMPLE_CPU;
	attr.read_format = 0;
	attr.inherit = 1;
	attr.mmap = 1;
	attr.comm = 1;
	attr.task = 1;
	attr.precise_ip = 0; // ???
	attr.sample_id_all = 1;

	while ((opt = getopt(argc, argv, "age:c:F:m:o:S:")) != -1) {
		switch(opt) {
		case 'a':
		case 'g':
			// Ignored; for compatibility.
			break;
		case 'e':
			for (i = 0; i < eventtab_len; ++i)
				if (strcmp(optarg, eventtab[i].name) == 0)
					break;
			if (i >= eventtab_len) {
				fprintf(stderr, "%s: %s: invalid event name\n",
				    argv[0], optarg);
				return 1;
			}
			attr.type = eventtab[i].type;
			attr.config = eventtab[i].config;
			break;
		case 'c':
			attr.freq = 0;
			attr.sample_period = strtoull(optarg, &cp, 0);
			if (!*optarg || *cp) {
				fprintf(stderr, "%s: %s: invalid sample %s\n",
				    argv[0], optarg, "period");
				return 1;
			}
			break;
		case 'F':
			attr.freq = 1;
			attr.sample_freq =  strtoull(optarg, &cp, 0);
			if (!*optarg || *cp) {
				fprintf(stderr, "%s: %s: invalid sample %s\n",
				    argv[0], optarg, "frequency");
				return 1;
			}
			break;
		case 'm':
			buf_pages = strtoul(optarg, &cp, 0);
			if (!*optarg || *cp
			    || (buf_pages & (buf_pages - 1)) != 0) {
				fprintf(stderr, "%s: %s: invalid number"
				    " of pages\n", argv[0], optarg);
				return 1;
			}
			break;
		case 'o':
			outfilename = optarg;
			break;
		case 'S':
			attr.sample_stack_user = strtoul(optarg, &cp, 0);
			if (!*optarg || *cp) {
				fprintf(stderr, "%s: %s: invalid stack capture"
				    " size\n", argv[0], optarg);
				return 1;
			}
			if (attr.sample_stack_user > 0) {
				attr.sample_type |= PERF_SAMPLE_STACK_USER
				    | PERF_SAMPLE_REGS_USER;
				attr.sample_regs_user = 0xffff;
			}
			break;
		case '?':
			// Bionic does something odd here, so add a newline.
			fprintf(stderr, "\n%s: invalid option -%c\n",
			    argv[0], optopt);
			return 1;
		default:
			assert(0);
		}
	}

	umask(0077);
	outfile = fopen(outfilename, "wb");
	if (!outfile) {
		fprintf(stderr, "fopen: %s: %s\n", outfilename,
		    strerror(errno));
		return 1;
	}

	cpus = sysconf(_SC_NPROCESSORS_CONF);
	page_size = sysconf(_SC_PAGESIZE);
	buf_size = page_size * buf_pages;
	setbuffer(outfile, new char[buf_size], buf_size);
	fds = new pollfd[cpus];
	memset(fds, 0, sizeof(pollfd[cpus]));
	bufs = new volatile perf_event_mmap_page *[cpus];
	for (i = 0; i < cpus; ++i) {
		fds[i].fd = syscall(__NR_perf_event_open, &attr, -1, i, -1, 0);
		if (fds[i].fd < 0) {
			perror("perf_event_open");
			return 1;
		}
		fds[i].events = POLLIN;
		void *buf = mmap(NULL, page_size + buf_size,
		    PROT_READ | PROT_WRITE, MAP_SHARED, fds[i].fd, 0);
		if (buf == MAP_FAILED) {
			perror("mmap");
			return 1;
		}
		bufs[i] = reinterpret_cast<volatile perf_event_mmap_page *>(buf);
		// TODO: map a guard page here to protect me from myself?
	}

	signal(SIGINT, start_exiting);
	signal(SIGHUP, start_exiting);

	header.sample_type = attr.sample_type;
	fwrite(&header, sizeof(header), 1, outfile);
	synthetic_mmaps_for_kernel();
	test_pid(0);
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

			base = (uint8_t *)((uintptr_t)(bufs[i]) + page_size);
			head = bufs[i]->data_head;
			tail = bufs[i]->data_tail;
			rmb();
			while (head > tail) {
				tail += event_write(base, buf_size, tail);
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
		*lineptr = reinterpret_cast<char *>(malloc(*n));
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
		*lineptr = reinterpret_cast<char *>(realloc(*lineptr, *n));
	}
	if ((*lineptr)[so_far - 1] != '\n') {
		so_far++;
		(*lineptr)[so_far - 1] = '\n';
		(*lineptr)[so_far] = '\0';
	}
	return so_far;
}
#endif
