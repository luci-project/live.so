// live.so - dynamic updating shared libraries
// Copyright 2024 by Bernhard Heinloth <heinloth@cs.fau.de>
// SPDX-License-Identifier: AGPL-3.0-or-later

#define _GNU_SOURCE
#include <linux/limits.h>

#include <assert.h>
#include <dlfcn.h>
#include <link.h>
#include <errno.h>
#include <fcntl.h>
#include <gelf.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <stdbool.h>
#include <unistd.h>
#include <search.h>
#include <pthread.h>
#include <sys/mman.h>
#include <sys/inotify.h>
#include <sys/sendfile.h>
#include <sys/stat.h>
#include <stdarg.h>
#include <time.h>

/*** Start of configuration ***/

// Libraries to ignore for live updates
static const char * ignore_libs[] = { "linux-vdso.so.1", "/libc.so.6", "/ld-linux-x86-64.so.2", "/libelf.so.1", "/libz.so.1", "/live.so" };

// Delay between modification event and update in microseconds
// (this can be handy to prevent an update after file was removed but before the new version was installed)
const useconds_t update_delay = 20000;

// Maximum number of libraries to handle
// (upper limit of loaded libraries, sum of all initial and each updated version)
const size_t lib_hash_max_elements = 1000;

// Default page size
static int pagesize = 0x1000;

/*** End of configuration ***/


// Macros for logging
#define ERR(FMT,...) logmsg(ERROR, __BASE_FILE__, __LINE__, FMT, ## __VA_ARGS__)
#define WARN(FMT,...) logmsg(WARNING, __BASE_FILE__, __LINE__, FMT, ## __VA_ARGS__)
#define LOG(FMT,...) logmsg(INFO, __BASE_FILE__, __LINE__, FMT, ## __VA_ARGS__)
#define DBG(FMT,...) logmsg(DEBUG, __BASE_FILE__, __LINE__, FMT, ## __VA_ARGS__)

// Helper to count elements in array
#define COUNT(x) (sizeof(x)/sizeof(x[0]))

// Supported logging levels
enum LogLevel {
	ERROR   =  0,
	WARNING =  1,
	INFO    =  2,
	DEBUG   =  3
};

struct Identity;
struct Lib;

// Library instance (representing either initial version or a specific updated version of a library)
typedef struct Lib {
	char * realpath;
	unsigned version;
	uint32_t checksum;
	void * handle;
	ElfW(Addr) addr;
	uintptr_t got;
	size_t gotsz;
	struct Lib * prev;
	struct Identity * base;
} lib_t;

// Representation of a single writable segment (which has to be shared)
typedef struct SharedMem {
	int fd;
	int flags;
	ElfW(Addr) addr;
	size_t size;
	size_t align;
} sharedmem_t;

// Library identity (reference to a library)
typedef struct Identity {
	int wd;
	char * path;
	char * name;
	sharedmem_t * sharedmem;
	size_t sharedmemsz;
	lib_t * current;
} identity_t;

// Mapping library path to version
static struct hsearch_data lib_hash;

// Count of library identieties
static size_t identities = 0;
static identity_t * identity = NULL;
static sharedmem_t ** fork_sharedmem = NULL;

static int inotify_fd = -1;
static const int inotify_flags = IN_MODIFY | IN_DELETE_SELF | IN_MOVE_SELF | IN_DONT_FOLLOW;

static pthread_t thread_watcher;

static enum LogLevel loglevel;
static time_t logstart = 0;

static void logmsg(enum LogLevel level, const char * file, unsigned line, const char* format, ...) {
	if (level > DEBUG)
		level = DEBUG;
	if (level <= loglevel) {
		int e = errno;
		const char * intro[] = { "\x1b[41;30m ERROR \x1b[40;31m", "\x1b[43;30mWARNING\x1b[40;33m", "\x1b[47;30m INFO  \x1b[40;37m", "\x1b[7;1m DEBUG \x1b[0;40m" };
		char buf[1024] = { '\0' };
		int n = snprintf(buf, 1023, "%s %6lu %6lu %s:%-4u \x1b[49m ", intro[level], (long unsigned)(time(NULL) - logstart), (long unsigned)getpid(), file, line);
		if (n < 0)
			abort();
		va_list args;
		va_start(args, format);
		errno = e;
		if (vsnprintf(buf + n, 1023 - n, format, args) < 0)
			abort();
		va_end(args);
		fprintf(stderr, "%s\x1b[0m\n", buf);
	}
}


static bool ignore_lib(const char * path) {
	const char * name = strrchr(path, '/');
	if (name == NULL)
		name = path;
	for (size_t i = 0; i < COUNT(ignore_libs); i++)
		if (strcmp(name, ignore_libs[i]) == 0)
			return true;
	return false;
}


static uint32_t filechecksum(const char *path) {
	uint32_t crc = 0xffffffff;

	int fd = open(path, O_RDONLY);
	if (fd == -1) {
		WARN("Unable to open %s: %m", path);
	} else {
		char buf[4096] = { '\0' };
		ssize_t len;
		while ((len = read(fd, buf, COUNT(buf))) > 0)
			for (ssize_t i = 0; i < len; i++) {
				crc ^= buf[i];
				for (ssize_t j = 0; j < 8; j++)
					crc = (crc >> 1) ^ (0xedb88320 & -(crc & 1));
			}
		close(fd);
		if (len == -1)
			WARN("Error reading %s for checksum: %m", path);
		else
			DBG("Checksum of %s is %x", path, ~crc);
	}
	return ~crc;
}


static lib_t * dlload(const char * path) {
	lib_t * lib = calloc(1, sizeof(lib_t));
	if (lib != NULL) {
		dlerror();
		if ((lib->handle = dlopen(path, RTLD_LAZY | RTLD_LOCAL)) == NULL) {
			WARN("Loading %s failed: %s", path == NULL ? "main program" : path, dlerror());
			free(lib);
			lib = NULL;
		}
	}
	return lib;
}


static bool map_sharedmem(const lib_t * lib, sharedmem_t * s) {
	size_t offset = s->addr % s->align;
	uintptr_t mem_page_addr = s->addr + lib->addr - offset;
	size_t mem_page_size = s->size + offset;

	if (lib->version == 0) {
		char fdname[PATH_MAX] = { '\0' };
		snprintf(fdname, PATH_MAX, "shmem#%s#%p", lib->base->name, (void*)(s->addr));

		if ((s->fd = memfd_create(fdname, MFD_CLOEXEC | MFD_ALLOW_SEALING)) == -1) {
			ERR("Creating memory fd for %p of %s v%u failed: %m", (void*)(s->addr), lib->base->name, lib->version);
			close(s->fd);
			s->fd = -1;
			return false;
		}
		for (size_t written = 0; written < mem_page_size;) {
			ssize_t w = write(s->fd, (void*)(mem_page_addr + written), mem_page_size - written);
			if (w == -1) {
				ERR("Writing memory %zu bytes from %p for %p of %s v%u failed: %m", mem_page_size - written, (void*)(mem_page_addr + written), (void*)(s->addr), lib->base->name, lib->version);
				close(s->fd);
				s->fd = -1;
				return false;
			} else {
				written += w;
			}
		}
		if (fcntl(s->fd, F_ADD_SEALS, F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL) == -1) {
			LOG("Sealing memory fd for %p of %s v%u failed: %m", (void*)(s->addr), lib->base->name, lib->version);
			// continue
		}
		if (mmap((void*)mem_page_addr, mem_page_size, s->flags, MAP_SHARED | MAP_FIXED, s->fd, 0) == MAP_FAILED) {
			ERR("Unable to create shared memory %d at %p (%zu bytes) in %s v%u: %m", s->fd, (void*)(s->addr), s->size, lib->base->name, lib->version);
			close(s->fd);
			s->fd = -1;
			return false;
		} else {
			LOG("Created shared memory %d at %p (%zu bytes) in %s v%u", s->fd, (void*)(s->addr), s->size, lib->base->name, lib->version);
			return true;
		}
	} else {
		assert(lib->base->sharedmemsz == 0 || lib->base->sharedmem != NULL);
		for (size_t j = 0; j < lib->base->sharedmemsz; j++) {
			sharedmem_t * f = lib->base->sharedmem + j;
			if (s->addr == f->addr && s->size == f->size) {
				if (f->fd < 0) {
					ERR("Not a valid shared memory for %p (%zu bytes) in %s v%u", (void*)(s->addr), s->size, lib->base->name, lib->version);
					return false;
				} else if (mmap((void*)mem_page_addr, mem_page_size, s->flags, MAP_SHARED | MAP_FIXED, f->fd, 0) == MAP_FAILED) {
					ERR("Unable to map shared memory %d at %p (%zu bytes) in %s v%u: %m", f->fd, (void*)(s->addr), s->size, lib->base->name, lib->version);
					return false;
				} else {
					LOG("Mapped shared memory %d at %p (%zu bytes) in %s v%u", f->fd, (void*)(s->addr), s->size, lib->base->name, lib->version);
					return true;
				}
			}
		}
		ERR("No shared memory exists for %p (%zu bytes) in %s v%u", (void*)(s->addr), s->size, lib->base->name, lib->version);
		return false;
	}
}


static bool elfread(lib_t * lib) {
	assert(lib != NULL);
	assert(lib->base != NULL);
	assert(lib->base->current != NULL);

	bool success = true;
	int fd = open(lib->realpath, O_RDONLY);
	if (fd == -1) {
		LOG("Opening %s failed: %m", lib->realpath);
		return false;
	}
	Elf * elf = elf_begin (fd, ELF_C_READ, NULL);
	if (elf == NULL) {
		LOG("Cannot read ELF data of %s: %s", lib->realpath, elf_errmsg(0));
	} else {
		GElf_Ehdr ehdr_mem;
		GElf_Ehdr *ehdr = gelf_getehdr(elf, &ehdr_mem);
		if (ehdr == NULL) {
			LOG("Cannot read ELF object file header of %s: %s", lib->realpath, elf_errmsg(0));
			success = false;
		} else if (ehdr->e_type != ET_EXEC && ehdr->e_type != ET_DYN) {
			LOG("Unsupported ELF type in %s",  lib->base->path);
			success = false;
		} else {
			GElf_Phdr phdr_mem;
			size_t phdr_num;
			if (elf_getphdrnum(elf, &phdr_num) == -1) {
				LOG("Cannot read ELF object program header number of %s: %s", lib->realpath, elf_errmsg(0));
				success = false;
			} else {
				sharedmem_t shmem[phdr_num];
				size_t shmem_num = 0;
				size_t addr_delta = ehdr->e_type == ET_EXEC ? lib->addr : 0;
				for (size_t p = 0; p < phdr_num; p++) {
					GElf_Phdr * phdr = gelf_getphdr(elf, p, &phdr_mem);
					if (phdr == NULL) {
						LOG("Cannot read ELF program header #%zu of %s: %s", p, lib->realpath, elf_errmsg(0));
						success = false;
						break;
					} else if (phdr->p_type == PT_GNU_RELRO) {
						// Ignore Relro section
						for (size_t i = 0; i < shmem_num; i++) {
							if (shmem[i].addr == phdr->p_vaddr - addr_delta) {
								shmem[i].addr += phdr->p_memsz;
								shmem[i].size -= phdr->p_memsz;
								break;
							}
						}
					} else if (phdr->p_type == PT_LOAD && (phdr->p_flags & PF_W) != 0) {
						shmem[shmem_num++] = (sharedmem_t) {
							.fd = -1,
							.flags = ((phdr->p_flags & PF_R) ? PROT_READ : 0) | ((phdr->p_flags & PF_W) ? PROT_WRITE : 0) | ((phdr->p_flags & PF_X) ? PROT_EXEC : 0),
							.addr = phdr->p_vaddr - addr_delta,
							.size = phdr->p_memsz,
							.align = phdr->p_align
						};
					}
				}

				for (size_t i = 0; i < shmem_num; i++) {
					if (!map_sharedmem(lib, shmem + i))
						success = false;
				}
				if (lib->version == 0 && shmem_num > 0) {
					if ((lib->base->sharedmem = malloc(sizeof(sharedmem_t) * shmem_num)) == NULL) {
						ERR("Unable to allocate memory for %zu shared memory entries - aborting.", shmem_num);
						abort();
					}
					memcpy(lib->base->sharedmem, shmem, sizeof(sharedmem_t) * shmem_num);
					lib->base->sharedmemsz = shmem_num;
				}
				assert(lib->base->sharedmemsz == 0 || lib->base->sharedmem != NULL);
			}

			// GOT auf 0 setzen
			Elf_Scn * scn = NULL;
			while ((scn = elf_nextscn(elf, scn)) != NULL) {
				GElf_Shdr shdr_mem;
				GElf_Shdr * shdr = gelf_getshdr(scn, &shdr_mem);
				if (shdr == NULL) {
					LOG("Cannot read ELF section header of %s: %s", lib->realpath, elf_errmsg(0));
					break;
				}
				// Only GOT sections
				const char * section_name = elf_strptr(elf, ehdr->e_shstrndx, shdr->sh_name);
				if (section_name != NULL && strncmp(section_name, ".got", 4) == 0) {
					if (lib->got == 0) {
						lib->got = shdr->sh_addr;
						lib->gotsz = shdr->sh_size;
					} else if (lib->got + lib->gotsz == shdr->sh_addr) {
						lib->gotsz += shdr->sh_size;
					} else {
						LOG("Non-continous global offset tables in %s: %s", lib->realpath, section_name);
					}
				}
				
			}
		}
		elf_end(elf);
	}
	close(fd);

	// For RELRO, ensure GOT is writable
	uintptr_t addr = lib->addr + lib->got & (~(pagesize-1));
	size_t len = lib->addr + lib->got + lib->gotsz - addr;
	if (mprotect((void*)addr, len, PROT_READ | PROT_WRITE) != 0)
		LOG("(Un)protecting %lx (%zu bytes) in %s v%u failed: %m", lib->addr + addr, len, lib->base->name, lib->version);

	return success;
}


static void relink_got(lib_t * lib) {
	// Alle GOT Einträge durchgehen
	for (uintptr_t offset = 0; offset < lib->gotsz; offset += 8) {
		uintptr_t * entry = (uintptr_t *)(lib->addr + lib->got + offset);
		// Valid entries only
		if (*entry >= 0x40000) {
			// Resolve address to symbol
			Dl_info info;
			if (dladdr((void*)(*entry), &info) == 0 || info.dli_saddr == NULL)
				continue;

			// Lookup symbol in our lib list
			ENTRY *r;
			hsearch_r((ENTRY) { .key = (char*)info.dli_fname }, FIND, &r, &lib_hash);
			if (r != NULL) {
				lib_t * old_lib = (lib_t *) (r->data);
				identity_t * target = old_lib->base;
				// Check if update is necessary
				if (target->current == old_lib)
					continue;

				uintptr_t ptr = (uintptr_t)dlsym(target->current->handle, info.dli_sname);
				if (ptr == 0) {
					WARN("Symbol %s not found in %s v%u", info.dli_sname, target->name, target->current->version);
				} else if (ptr != *entry) {
					// Update!
					LOG("Updating symbol value of %s (%s v%u) in %s v%u from %lx to %lx", info.dli_sname, target->name, target->current->version, lib->base->name, lib->version, *entry, ptr);
					*entry = ptr;
				} else {
					LOG("No update symbol value of %s (%s v%u) in %s v%u from %lx to %lx", info.dli_sname, target->name, target->current->version, lib->base->name, lib->version, *entry, ptr);
				}
			} else if (!ignore_lib(info.dli_fname)) {
				WARN("No lib %s for symbol %s found!", info.dli_fname, info.dli_sname);
			}
		}
	}
}


static int memfddup(const char * name, int src_fd, ssize_t len) {
	if (src_fd < 0)
		return -1;

	errno = 0;
	int mem_fd = memfd_create(name, MFD_CLOEXEC | MFD_ALLOW_SEALING);
	if (mem_fd == -1) {
		ERR("Creating memory fd copy %s failed: %m", name);
	} else {
		lseek(src_fd, 0, SEEK_SET);
		while (true) {
			errno = 0;
			ssize_t s = sendfile(mem_fd, src_fd, NULL, len);
			if (s == -1) {
				DBG("Copying %s file failed: %m", name);
				break;
			} else if ((len -= s) <= 0) {
				break;
			}
		}
		errno = 0;
		if (fcntl(mem_fd, F_ADD_SEALS, F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL) == -1) {
			WARN("Sealing memory fd for %s failed: %m", name);
			// continue
		}
	}
	return mem_fd;
}


static char * persistent_file(identity_t * base) {
	struct stat path_stat;
	if (stat(base->path, &path_stat) == -1) {
		WARN("Not able to stat %s: %m", base->path);
	} else if (S_ISREG(path_stat.st_mode)) { // TODO
		LOG("%s has mask %o", base->path, path_stat.st_mode);
		// Create a memory copy of the library
		errno = 0;
		int src_fd = open(base->path, O_RDONLY);
		if (src_fd == -1) {
			ERR("Unable to open %s: %m", base->path);
		} else {
			char fdname[PATH_MAX] = { '\0' };
			snprintf(fdname, PATH_MAX, "%s#%u", base->name, base->current->version + 1);
			int mem_fd = memfddup(fdname, src_fd, path_stat.st_size);
			close(src_fd);
			if (mem_fd != -1) {
				char * path;
				if (asprintf(&path, "/proc/self/fd/%d", mem_fd) == -1)
					ERR("Unable to allocate memory for asprintf");
				else
					return path;
			}
		}
	}

	char * path = realpath(base->path, NULL);
	if (path == NULL) {
		WARN("Unable to resolve path %s: %m", base->path);
		return strdup(base->path);
	} else {
		return path;
	}
}


void *thread_watch(void *arg) {
	(void) arg;
	char buf[4096] __attribute__ ((aligned(__alignof__(struct inotify_event))));
	sigset_t set;
	sigfillset(&set);
	int e = pthread_sigmask(SIG_BLOCK, &set, NULL);
	if (e != 0)
		WARN("Unable to block signals in watch thread: %s", strerror(e));
	while (true) {
		// Wait for events (blocking)
		ssize_t len = read(inotify_fd, buf, sizeof(buf));
		if (len == -1 && errno != EAGAIN) {
			ERR("Aborting since reading from inotify descriptor failed: %m");
			return 0;
		}

		e = pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL);
		if (e != 0)
			WARN("Unable to disable cancel in watch thread: %s", strerror(e));
		// Parse events
		const struct inotify_event * event;
		for (char *ptr = buf; ptr < buf + len; ptr += sizeof(struct inotify_event) + event->len) {
			event = (const struct inotify_event *) ptr;
			if (event->mask & IN_IGNORED)
				continue;
			else if (event->mask & (IN_MODIFY | IN_MOVE | IN_DELETE_SELF)) {
				// Find matching watch descriptor
				for (size_t i = 0; i < identities; i++)
					if (event->wd == identity[i].wd) {
						DBG("Modification event for %s", identity[i].name);
						inotify_rm_watch(inotify_fd, identity[i].wd);
						usleep(update_delay);

						uint32_t checksum = filechecksum(identity[i].path);
						if (checksum == identity[i].current->checksum) {
							DBG("Checksum %x has not changed to %s v%u - ignoring.", checksum, identity[i].name, identity[i].current->version);
						// Do the update
						} else {
							char * path = persistent_file(identity + i);
							lib_t * lib = dlload(path);
							if (lib != NULL) {
								lib->addr = ((struct link_map *)(lib->handle))->l_addr;  // hack
								lib->realpath = path;
								lib->base = identity + i;
								lib->checksum = checksum;
								lib->prev = identity[i].current;
								identity[i].current = lib;
								lib->version = lib->prev->version + 1;

								// load GOT
								elfread(lib);

								// Put in hash map
								ENTRY *r;
								hsearch_r((ENTRY) {
									.key = path,
									.data = lib
								}, ENTER, &r, &lib_hash);


								// relink (= actual update)
								for (size_t i = 0; i < identities; i++)
									for (lib_t * l = identity[i].current; l != NULL; l = l->prev)
										relink_got(l);

								LOG("Updated %s to version %u (located at %p)!", identity[i].name, lib->version, lib->addr);
							} else {
								WARN("Updating %s (%s) failed!", identity[i].path, path);
								free(path);
							}
						}
						// Install new watch
						if ((identity[i].wd = inotify_add_watch(inotify_fd, identity[i].path, inotify_flags)) == -1)
							WARN("Cannot reinstall watch %s for changes: %m", identity[i].path);

					}
			} else {
				DBG("Unhandled event: %d", event->mask);
			}
		}
		e = pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
		if (e != 0)
			WARN("Unable to enable cancel in watch thread: %s", strerror(e));
	}
	return NULL;
}


static void thread_watcher_install() {
	// Install inotify watch
	if ((inotify_fd = inotify_init1(IN_CLOEXEC)) == -1) {
		ERR("Unable to initialize inotify: %m - aborting");
		abort();
	}

	DBG("Install inotify watches for shared objects");
	for (size_t i = 0; i < identities; i++)
		if ((identity[i].wd = inotify_add_watch(inotify_fd, identity[i].path, inotify_flags)) == -1)
			WARN("Cannot watch %s for changes: %m", identity[i].path);

	int e = pthread_create(&thread_watcher, NULL, thread_watch, NULL);
	if (e != 0) {
		ERR("Creating thread failed: %s - aborting", strerror(e));
		abort();
	}
}


static void thread_watcher_remove() {
	int e = pthread_cancel(thread_watcher);
	if (e != 0) {
		WARN("Sending kill signal to watcher thread failed: %s", strerror(e));
	} else {
		struct timespec ts;
		errno = 0;
		if (clock_gettime(CLOCK_REALTIME, &ts) == -1) {
			WARN("Getting wall clock time failed: %m");
			e = pthread_join(thread_watcher, NULL);
		} else {
			ts.tv_sec += 10;  // wait no more then 10 seconds
			e = pthread_timedjoin_np(thread_watcher, NULL, &ts);
		}
		if (e != 0) {
			WARN("Joining watcher thread failed: %s", strerror(e));
			pthread_kill(thread_watcher, SIGKILL);
		}
	}

	DBG("Removing inotify watches for shared objects");
	for (size_t i = 0; i < identities; i++)
		if (identity[i].wd != -1 && inotify_rm_watch(inotify_fd, identity[i].wd) != 0)
			WARN("Unable to remove watch for %s: %m", identity[i].path);

	close(inotify_fd);
	inotify_fd = -1;
}


static void fork_prepare(void) {
	DBG("Stopping watcher thread before fork() in %lu", (long unsigned)gettid());
	thread_watcher_remove();

	DBG("Cloning shared memory before fork() in %lu", (long unsigned)gettid());
	if ((fork_sharedmem = calloc(identities, sizeof(sharedmem_t *))) == NULL) {
		ERR("Cannot allocate %zu shared memory pointer storages", identities);
		abort();
	}
	for (size_t i = 0; i < identities; i++) {
		if (identity[i].sharedmem != NULL) {
			if ((fork_sharedmem[i] = calloc(identity[i].sharedmemsz, sizeof(sharedmem_t))) == NULL) {
				ERR("Cannot allocate %zu shared memory storages", identity[i].sharedmemsz);
				abort();
			}
			sharedmem_t * shmem = fork_sharedmem[i];
			for (size_t j = 0; j < identity[i].sharedmemsz; j++) {
				shmem[j] = identity[i].sharedmem[j];
				if (shmem[j].fd < 0)
					continue;

				char fdname[PATH_MAX] = { '\0' };
				snprintf(fdname, PATH_MAX, "shmem#%s#%p", identity[i].name, (void*)(shmem[j].addr));
				if ((shmem[j].fd = memfddup(fdname, shmem[j].fd, shmem[j].size)) == -1) {
					ERR("Abort due to inability to clone memory %s", fdname);
					abort();
				}
			}
		}
	}
}


static void fork_parent(void) {
	DBG("Closing cloned shared memory after fork() in %lu", (long unsigned)gettid());
	for (size_t i = 0; i < identities; i++) {
		sharedmem_t * shmem = fork_sharedmem[i];
		for (size_t j = 0; j < identity[i].sharedmemsz; j++) {
			assert(shmem != NULL);
			close(shmem[j].fd);
		}
		free(shmem);
	}
	free(fork_sharedmem);
	fork_sharedmem = NULL;

	DBG("Starting watcher thread after fork() in %lu (parent)", (long unsigned)gettid());
	thread_watcher_install();
}


static void fork_child(void) {
	DBG("Setting up cloned shared memory after fork() in %lu (child)", (long unsigned)gettid());
	for (size_t i = 0; i < identities; i++) {
		sharedmem_t * shmem = fork_sharedmem[i];
		for (size_t j = 0; j < identity[i].sharedmemsz; j++)
			if (identity[i].sharedmem[j].fd != -1) {
				assert(shmem != identity[i].sharedmem);
				assert(shmem[j].fd != identity[i].sharedmem[j].fd);
				assert(shmem[j].addr == identity[i].sharedmem[j].addr);
				assert(shmem[j].size == identity[i].sharedmem[j].size);
				assert(shmem[j].flags == identity[i].sharedmem[j].flags);

				for (lib_t * l = identity[i].current; l != NULL; l = l->prev) {
					size_t offset = shmem->addr % shmem->align;
					uintptr_t mem_page_addr = shmem->addr + l->addr - offset;
					size_t mem_page_size = shmem->size + offset;
					errno = 0;
					if (munmap((void*)mem_page_addr, mem_page_size) != 0)
						WARN("Unable to unmap %p (%zu bytes): %m", (void*)(identity[i].sharedmem[j].addr), identity[i].sharedmem[j].size);
					errno = 0;
					if (mmap((void*)mem_page_addr, mem_page_size, shmem[j].flags, MAP_SHARED | MAP_FIXED, shmem[j].fd, 0) == MAP_FAILED) {
						ERR("Unable to create shared memory %d at %p (%zu bytes) in %s: %m", shmem[j].fd, (void*)(shmem[j].addr), shmem[j].size, identity[i].name);
						abort();
					} else {
						DBG("Recreated shared memory %d at %p (%zu bytes) in %s", shmem[j].fd, (void*)(shmem[j].addr), shmem[j].size, identity[i].name);
					}
				}
				close(identity[i].sharedmem[j].fd);
			}
		free(identity[i].sharedmem);
		identity[i].sharedmem = shmem;
	}
	free(fork_sharedmem);
	fork_sharedmem = NULL;

	DBG("Starting watcher thread after fork() in %lu (child)", (long unsigned)gettid());
	thread_watcher_install();
}


static bool enable() {
	// Logging
	logstart = time(NULL);
	const char * level = getenv("LIVE_LOGLEVEL");
	if (level != NULL && level[0] >= '0' && level[0] <= '9')
		loglevel = level[0] - '0';

	// Get defaults
	pagesize = sysconf(_SC_PAGE_SIZE);
	if (pagesize == -1)
		WARN("Unable to get page size: %m");

	// Load main program
	lib_t * main = dlload(NULL);
	if (main == NULL) {
		ERR("Unable to load main program");
		return false;
	}

	// get linklist
	struct link_map * link_map = NULL;
	if (dlinfo(main->handle, RTLD_DI_LINKMAP, &link_map) != 0) {
		ERR("Getting link map failed: %s", dlerror());
		free(main);
		return false;
	}

	// Allocat memory for library identities
	for (struct link_map * l = link_map; l != NULL; l = l->l_next)
		if (!ignore_lib(l->l_name))
			identities++;
	if ((identity = calloc(identities, sizeof(identity_t))) == NULL) {
		ERR("Cannot allocate %zu library identities", identities);
		free(main);
		return false;
	}
	hcreate_r(lib_hash_max_elements, &lib_hash);

	// Main program will iterate over link map to recursively load all other libs
	bool success = true;
	size_t i = 0;
	lib_t * cur;
	for (struct link_map * l = link_map; l != NULL; l = l->l_next) {
		if (l->l_name == NULL || strlen(l->l_name) == 0) {
			identity[i].current = main;
			char tmp[PATH_MAX + 1] = { '\0' };
			identity[i].path = strndup(readlink("/proc/self/exe", tmp, PATH_MAX) < 0 ? "/proc/self/exe" : tmp, PATH_MAX);
			DBG("Me is %s", identity[i].path);
		} else if (ignore_lib(l->l_name)) {
			DBG("Skipping shared library %s", l->l_name);
			continue;
		} else if ((cur = dlload(l->l_name)) != NULL) {
			identity[i].current = cur;
			identity[i].path = strndup(l->l_name, PATH_MAX);
		} else {
			WARN("Unable to load %s!", l->l_name);
			success = false;
			continue;
		}

		identity[i].current->realpath = identity[i].path;
		if ((identity[i].name = strrchr(identity[i].path, '/')) == NULL)
			identity[i].name = identity[i].path;
		else
			identity[i].name++;
		identity[i].current->checksum = filechecksum(identity[i].path);
		identity[i].current->addr = l->l_addr;
		identity[i].current->version = 0;
		identity[i].current->base = identity + i;

		// Put in hash map
		ENTRY *r;
		hsearch_r((ENTRY) {
			.key = identity[i].current->realpath,
			.data = identity[i].current
		}, ENTER, &r, &lib_hash);

		i++;
	}

	// Install fork handler
	if ((errno = pthread_atfork(fork_prepare, fork_parent, fork_child)) != 0) {
		WARN("Unable to install fork handler: %m");
		success = false;
	}

	// Read (relative) GOT address and size via ELF for each lib
	elf_version(EV_CURRENT);
	for (size_t i = 0; i < identities; i++)
		if (!elfread(identity[i].current))
			success = false;

	// install watcher thread
	thread_watcher_install();

	return success;
}


static bool disable() {
	DBG("Stopping watcher thread of %lu", (long unsigned)getpid());
	thread_watcher_remove();
	return true;
}


#ifdef USE_MAIN_WRAPPER

static int (*real_main)(int, char **, char **);

int main_wrapper(int argc, char **argv, char **envp) {
	enable();
	int r = real_main(argc, argv, envp);
	disable();
	return r;
}

int __libc_start_main(int (*main) (int, char **, char **), int argc, char ** argv, void (*init) (void), void (*fini) (void), void (*rtld_fini) (void), void (* stack_end)) {
	real_main = main;
	typeof(&__libc_start_main) real_libc_start_main = dlsym(RTLD_NEXT, "__libc_start_main");
	return real_libc_start_main(main_wrapper, argc, argv, init, fini, rtld_fini, stack_end);
}

#else

static __attribute__((constructor)) bool init() {
	return enable();
}

static __attribute__((destructor)) bool fini() {
	return disable;
}

#endif
