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
#include <stdbool.h>
#include <unistd.h>
#include <search.h>
#include <pthread.h>
#include <sys/mman.h>
#include <sys/inotify.h>
#include <sys/stat.h>
#include <stdarg.h>
#include <time.h>


#define ERR(FMT,...) logmsg(ERROR, __BASE_FILE__, __LINE__, FMT, __VA_ARGS__)
#define WARN(FMT,...) logmsg(WARNING, __BASE_FILE__, __LINE__, FMT, __VA_ARGS__)
#define LOG(FMT,...) logmsg(INFO, __BASE_FILE__, __LINE__, FMT, __VA_ARGS__)
#define DBG(FMT,...) logmsg(DEBUG, __BASE_FILE__, __LINE__, FMT, __VA_ARGS__)

#define COUNT(x) (sizeof(x)/sizeof(x[0]))
#define MAX_HASH_LIBS 1000

enum LogLevel {
	ERROR   =  0,
	WARNING =  1,
	INFO    =  2,
	DEBUG   =  3
};

struct Identity;
struct Lib;
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

typedef struct SharedMem {
	int fd;
	int flags;
	ElfW(Addr) addr;
	size_t size;
	size_t align;
} sharedmem_t;

typedef struct Identity {
	int wd;
	char * path;
	char * name;
	sharedmem_t * sharedmem;
	size_t sharedmemsz;
	lib_t * current;
} identity_t;

// Libraries to ignore for live updates
const char * ignore_libs[] = { "linux-vdso.so.1", "/libc.so.6", "/ld-linux-x86-64.so.2", "/libelf.so.1", "/libz.so.1", "/live.so" };

// Default page size
int pagesize = 0x1000;

// Delay between modification event and update in microseconds
// (this can be handy to prevent an update after file was removed but before the new version was installed)
const useconds_t update_delay = 20000;

struct hsearch_data lib_hash;

static size_t identities = 0;
identity_t * identity = NULL;

static int inotify_fd = -1;
static const int inotify_flags = IN_MODIFY | IN_DELETE_SELF | IN_MOVE_SELF | IN_DONT_FOLLOW;

static pthread_t thread_watcher;

static enum LogLevel loglevel;
static time_t logstart = 0;

static void logmsg(enum LogLevel level, const char * file, unsigned line, const char* format, ...) {
	if (level > DEBUG)
		level = DEBUG;
	if (level <= loglevel) {
		const char * intro[] = { "\e[41;30m ERROR \e[40;31m", "\e[43;30mWARNING\e[40;33m", "\e[47;30m INFO  \e[40;37m", "\e[7;1m DEBUG \e[0;40m" };
		fprintf(stderr, "%s %6lu %6lu %s:%-4u \e[49m ", intro[level], (long unsigned)(time(NULL) - logstart), (long unsigned)getpid(), file, line);
		va_list args;
		va_start(args, format);
		vfprintf(stderr, format, args);
		va_end(args);
		fputs("\e[0m\n", stderr);
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
		WARN("Unable to open %s: %s", path, strerror(errno));
	} else {
		char buf[4096];
		ssize_t len;
		while ((len = read(fd, buf, COUNT(buf))) > 0)
			for (size_t i = 0; i < len; i++) {
				crc ^= buf[i];
				for (size_t j = 0; j < 8; j++)
					crc = (crc >> 1) ^ (0xedb88320 & -(crc & 1));
			}
		close(fd);
		if (len == -1)
			WARN("Error reading %s for checksum: %s", path, strerror(errno));
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


static bool mapsharedmem(const lib_t * lib, sharedmem_t * s) {
	size_t offset = s->addr % s->align;
	uintptr_t mem_page_addr = s->addr + lib->addr - offset;
	size_t mem_page_size = s->size + offset;

	if (lib->version == 0) {
		char fdname[PATH_MAX];
		snprintf(fdname, PATH_MAX, "shmem#%s#%p", lib->base->name, (void*)(s->addr));

		if ((s->fd = memfd_create(fdname, MFD_CLOEXEC | MFD_ALLOW_SEALING)) == -1) {
			ERR("Creating memory fd for %p of %s v%u failed: %s", (void*)(s->addr), lib->base->name, lib->version, strerror(errno));
			close(s->fd);
			s->fd = -1;
			return false;
		}
		for (size_t written = 0; written < mem_page_size;) {
			ssize_t w = write(s->fd, (void*)(mem_page_addr + written), mem_page_size - written);
			if (w == -1) {
				ERR("Writing memory %zu bytes from %p for %p of %s v%u failed: %s", mem_page_size - written, (void*)(mem_page_addr + written), (void*)(s->addr), lib->base->name, lib->version, strerror(errno));
				close(s->fd);
				s->fd = -1;
				return false;
			} else {
				written += w;
			}
		}
		if (fcntl(s->fd, F_ADD_SEALS, F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL) == -1) {
			LOG("Sealing memory fd for %p of %s v%u failed: %s", (void*)(s->addr), lib->base->name, lib->version, strerror(errno));
			// continue
		}
		if (mmap((void*)mem_page_addr, mem_page_size, s->flags, MAP_SHARED | MAP_FIXED, s->fd, 0) == MAP_FAILED) {
			ERR("Unable to create shared memory %d at %p (%zu bytes) in %s v%u: %s", s->fd, (void*)(s->addr), s->size, lib->base->name, lib->version, strerror(errno));
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
					ERR("Unable to map shared memory %d at %p (%zu bytes) in %s v%u: %s", f->fd, (void*)(s->addr), s->size, lib->base->name, lib->version, strerror(errno));
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

static void elfread(lib_t * lib) {
	assert(lib != NULL);
	assert(lib->base != NULL);
	assert(lib->base->current != NULL);

	bool success = true;
	int fd = open(lib->realpath, O_RDONLY);
	if (fd == -1) {
		LOG("Opening %s failed: %s", lib->realpath, strerror(errno));
		return;
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
					if (!mapsharedmem(lib, shmem + i))
						success = false;
				}
				if (lib->version == 0 && shmem_num > 0) {
					if ((lib->base->sharedmem = malloc(sizeof(sharedmem_t) * shmem_num)) == NULL) {
						ERR("Unable to allocate memory for %zu shared memory entries", shmem_num);
						exit(EXIT_FAILURE);
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
		LOG("(Un)protecting %lx (%zu bytes) in %s v%u failed: %s", lib->addr + addr, len, lib->base->name, lib->version, strerror(errno));
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


static char * persistentfile(identity_t * base) {
	struct stat path_stat;
	if (stat(base->path, &path_stat) == -1) {
		WARN("Not able to stat %s: %s", base->path, strerror(errno));
	} else if (S_ISREG(path_stat.st_mode)) { // TODO
		LOG("%s has mask %o", base->path, path_stat.st_mode);
		// Create a memory copy of the library
		char fdname[PATH_MAX];
		snprintf(fdname, PATH_MAX, "%s#%u", base->name, base->current->version + 1);
		int mem_fd = memfd_create(fdname, MFD_CLOEXEC | MFD_ALLOW_SEALING);
		if (mem_fd == -1) {
			WARN("Creating memory fd for copy of %s v%u failed: %s",  base->name, base->current->version, strerror(errno));
		} else {
			int src_fd = open(base->path, O_RDONLY);
			if (src_fd == -1) {
				WARN("Unable to open %s: %s", base->path, strerror(errno));
			} else {
				ssize_t len = path_stat.st_size;
				while (true) {
					off_t off_mem_fd = 0;
					off_t off_src_fd = 0;
					ssize_t s  = copy_file_range(mem_fd, &off_mem_fd, src_fd, &off_src_fd, len, 0);
					if (s == -1) {
						DBG("Copying %s file range failed: %s ", base->path, strerror(errno));
						// TODO: Fall back to old fashion memcpy
						break;
					} else if ((len -= s) <= 0) {
						break;
					}
				}
				fcntl(mem_fd, F_ADD_SEALS, F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL);
				char * path;
				asprintf(&path, "/proc/self/fd/%d", mem_fd);
				return path;
			}
		}
	} else {
		char * path = realpath(base->path, NULL);
		if (path == NULL)
			WARN("Unable to resolve path %s: %s", base->path, strerror(errno));
		else
			return path;
	}
	DBG("Using default path %s", base->path);
	return strdup(base->path);
}


void *thread_watch(void *arg) {
	(void) arg;
	/* TODO: Endlosschleife mit inotify abwarten, dann bei Änderung lib neu laden aufrufen */
	char buf[4096] __attribute__ ((aligned(__alignof__(struct inotify_event))));
	while (true) {
		// Wait for events (blocking)
		ssize_t len = read(inotify_fd, buf, sizeof(buf));
		if (len == -1 && errno != EAGAIN) {
			ERR("Aborting since reading from inotify descriptor failed: %s", strerror(errno));
			return 0;
		}
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
						// 

						uint32_t checksum = filechecksum(identity[i].path);
						if (checksum == identity[i].current->checksum) {
							DBG("Checksum %x has not changed to %s v%u - ignoring.", checksum, identity[i].name, identity[i].current->version);
						// Do the update
						} else {
							char * path = persistentfile(identity + i);
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
							WARN("Cannot reinstall watch %s for changes: %s", identity[i].path, strerror(errno));

					}
			} else {
				DBG("Unhandled event: %d", event->mask);
			}
		}
	}
	return NULL;
}

static void thread_watcher_install() {
	int e = pthread_create(&thread_watcher, NULL, thread_watch, NULL);
	if (e != 0) {
		ERR("Creating thread failed: %s", strerror(e));
		exit(EXIT_FAILURE);
	}
	pthread_detach(thread_watcher);
}

static void fork_prepare(void) {
	// TODO: Duplicate all shared memory
}

static void fork_parent(void) {
	// TODO: Close duplicates
}

static void fork_child(void) {
	// TODO: Replace originals with duplicates
	// Start watcher thread
	thread_watcher_install();
}

static __attribute__((constructor)) bool init() {
	// Logging
	logstart = time(NULL);
	const char * level = getenv("LIVE_LOGLEVEL");
	if (level != NULL && level[0] >= '0' && level[0] <= '9')
		loglevel = level[0] - '0';

	// Get defaults
	pagesize = sysconf(_SC_PAGE_SIZE);
	if (pagesize == -1)
		WARN("Unable to get page size: %s", strerror(errno));

	// Install inotify watch
	if ((inotify_fd = inotify_init1(IN_CLOEXEC)) == -1) {
		ERR("Unable to initialize inotify: %s", strerror(errno));
		return false;
	}

	// Load main program
	lib_t * main = dlload(NULL);
	if (main == NULL) {
		ERR("Unable to load main program %s", "");
		return false;
	}

	// get linklist
	struct link_map * link_map = NULL;
	if (dlinfo(main->handle, RTLD_DI_LINKMAP, &link_map) != 0) {
		ERR("Getting link map failed: %s", dlerror());
		return false;
	}

	// Allocat memory for library identities
	for (struct link_map * l = link_map; l != NULL; l = l->l_next)
		if (!ignore_lib(l->l_name))
			identities++;
	if ((identity = calloc(identities, sizeof(identity_t))) == NULL) {
		ERR("Cannot allocate %zu library identities", identities);
		return false;
	}
	hcreate_r(MAX_HASH_LIBS, &lib_hash);

	// Main program will iterate over link map to recursively load all other libs
	size_t i = 0;
	lib_t * cur;
	for (struct link_map * l = link_map; l != NULL; l = l->l_next) {
		if (l->l_name == NULL || strlen(l->l_name) == 0) {
			identity[i].current = main;
			char tmp[PATH_MAX + 1];
			identity[i].path = strndup(readlink("/proc/self/exe", tmp, PATH_MAX) < 0 ? "/proc/self/exe" : tmp, PATH_MAX);
		} else if (ignore_lib(l->l_name)) {
			DBG("Skipping shared library %s", l->l_name);
			continue;
		} else if ((cur = dlload(l->l_name)) != NULL) {
			identity[i].current = cur;
			identity[i].path = strndup(l->l_name, PATH_MAX);
		} else {
			WARN("Unable to load %s!", l->l_name);
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
		if ((identity[i].wd = inotify_add_watch(inotify_fd, identity[i].path, inotify_flags)) == -1)
			WARN("Cannot watch %s for changes: %s", identity[i].path, strerror(errno));

		// Put in hash map
		ENTRY *r;
		hsearch_r((ENTRY) {
			.key = identity[i].current->realpath,
			.data = identity[i].current
		}, ENTER, &r, &lib_hash);

		i++;
	}

	// TODO: int 
	if ((errno = pthread_atfork(fork_prepare, fork_parent, fork_child)) != 0)
		WARN("Unable to install fork handler: %s", strerror(errno));

	// Read (relative) GOT address and size via ELF for each lib
	elf_version(EV_CURRENT);
	for (size_t i = 0; i < identities; i++)
		elfread(identity[i].current);

	// install watcher thread
	thread_watcher_install();
}

static __attribute__((destructor)) bool fini() {
	LOG("Cleanup %s", "Foo");
	return true;
}
