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

#define LOG(FMT,...) fprintf(stderr, "\e[33m[live.so] " FMT "\e[0m", __VA_ARGS__)
#define ERR(FMT,...) fprintf(stderr, "\e[31m[live.so] " FMT "\e[0m", __VA_ARGS__)
#define COUNT(x) (sizeof(x)/sizeof(x[0]))
#define MAX_HASH_LIBS 1000

struct Identity;
struct Lib;
typedef struct Lib {
	char * path;
	unsigned version;
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
	char * name;
	sharedmem_t * sharedmem;
	size_t sharedmemsz;
	lib_t * current;
} identity_t;

struct hsearch_data lib_hash;

static size_t identities = 0;
identity_t * identity = NULL;

const char * ignore_libs[] = { "linux-vdso.so.1", "/libc.so.6", "/ld-linux-x86-64.so.2", "/libelf.so.1", "/libz.so.1", "/live.so" };

int pagesize = 0x1000;
static pthread_t thread_watcher;

static bool ignore_lib(const char * path) {
	const char * name = strrchr(path, '/');
	if (name == NULL)
		name = path;
	for (size_t i = 0; i < COUNT(ignore_libs); i++)
		if (strcmp(name, ignore_libs[i]) == 0)
			return true;
	return false;
}

static lib_t * dlload(const char * path) {
	lib_t * lib = calloc(1, sizeof(lib_t));
	if (lib != NULL) {
		dlerror();
		if ((lib->handle = dlopen(path, RTLD_LAZY | RTLD_LOCAL)) == NULL) {
			LOG("Loading %s failed: %s\n", path == NULL ? "program" : path, dlerror());
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
		snprintf(fdname, PATH_MAX, "%s#%p", lib->base->name, (void*)(s->addr));

		if ((s->fd = memfd_create(fdname, MFD_CLOEXEC | MFD_ALLOW_SEALING)) == -1) {
			ERR("Creating memory fd for %p of %s v%u failed: %s\n", (void*)(s->addr), lib->base->name, lib->version, strerror(errno));
			close(s->fd);
			s->fd = -1;
			return false;
		}
		for (size_t written = 0; written < mem_page_size;) {
			ssize_t w = write(s->fd, (void*)(mem_page_addr + written), mem_page_size - written);
			if (w == -1) {
				ERR("Writing memory %zu bytes from %p for %p of %s v%u failed: %s\n", mem_page_size - written, (void*)(mem_page_addr + written), (void*)(s->addr), lib->base->name, lib->version, strerror(errno));
				close(s->fd);
				s->fd = -1;
				return false;
			} else {
				written += w;
			}
		}
		if (fcntl(s->fd, F_ADD_SEALS, F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL) == -1) {
			LOG("Sealing memory fd for %p of %s v%u failed: %s\n", (void*)(s->addr), lib->base->name, lib->version, strerror(errno));
			// continue
		}
		if (mmap((void*)mem_page_addr, mem_page_size, s->flags, MAP_SHARED | MAP_FIXED, s->fd, 0) == MAP_FAILED) {
			ERR("Unable to create shared memory %d at %p (%zu bytes) in %s v%u: %s\n", s->fd, (void*)(s->addr), s->size, lib->base->name, lib->version, strerror(errno));
			close(s->fd);
			s->fd = -1;
			return false;
		} else {
			LOG("Created shared memory %d at %p (%zu bytes) in %s v%u\n", s->fd, (void*)(s->addr), s->size, lib->base->name, lib->version);
			return true;
		}
	} else {
		assert(lib->base->sharedmemsz == 0 || lib->base->sharedmem != NULL);
		for (size_t j = 0; j < lib->base->sharedmemsz; j++) {
			sharedmem_t * f = lib->base->sharedmem + j;
			if (s->addr == f->addr && s->size == f->size) {
				if (f->fd < 0) {
					ERR("Not a valid shared memory for %p (%zu bytes) in %s v%u\n", (void*)(s->addr), s->size, lib->base->name, lib->version);
					return false;
				} else if (mmap((void*)mem_page_addr, mem_page_size, s->flags, MAP_SHARED | MAP_FIXED, f->fd, 0) == MAP_FAILED) {
					ERR("Unable to map shared memory %d at %p (%zu bytes) in %s v%u: %s\n", f->fd, (void*)(s->addr), s->size, lib->base->name, lib->version, strerror(errno));
					return false;
				} else {
					LOG("Mapped shared memory %d at %p (%zu bytes) in %s v%u\n", f->fd, (void*)(s->addr), s->size, lib->base->name, lib->version);
					return true;
				}
			}
		}
		ERR("No shared memory exists for %p (%zu bytes) in %s v%u\n", (void*)(s->addr), s->size, lib->base->name, lib->version);
		return false;
	}
}

static void elfread(lib_t * lib) {
	assert(lib != NULL);
	assert(lib->base != NULL);
	assert(lib->base->current != NULL);

	bool success = true;
	int fd = open(lib->path, O_RDONLY);
	if (fd == -1) {
		LOG("Opening %s for %s v%u failed: %s\n", lib->path, lib->base->name, lib->version, strerror(errno));
		return;
	}
	Elf * elf = elf_begin (fd, ELF_C_READ, NULL);
	if (elf == NULL) {
		LOG("Cannot read ELF data of %s for %s v%u: %s\n", lib->path, lib->base->name, lib->version, elf_errmsg(0));
	} else {
		GElf_Ehdr ehdr_mem;
		GElf_Ehdr *ehdr = gelf_getehdr(elf, &ehdr_mem);
		if (ehdr == NULL) {
			LOG("Cannot read ELF object file header of %s for %s v%u: %s\n", lib->path, lib->base->name, lib->version, elf_errmsg(0));
			success = false;
		} else if (ehdr->e_type != ET_EXEC && ehdr->e_type != ET_DYN) {
			LOG("Unsupported ELF type in %s for %s v%u\n",  lib->path, lib->base->name, lib->version);
			success = false;
		} else {
			GElf_Phdr phdr_mem;
			size_t phdr_num;
			if (elf_getphdrnum(elf, &phdr_num) == -1) {
				LOG("Cannot read ELF object program header number of %s for %s v%u: %s\n", lib->path, lib->base->name, lib->version, elf_errmsg(0));
				success = false;
			} else {
				sharedmem_t shmem[phdr_num];
				size_t shmem_num = 0;
				size_t addr_delta = ehdr->e_type == ET_EXEC ? lib->addr : 0;
				for (size_t p = 0; p < phdr_num; p++) {
					GElf_Phdr * phdr = gelf_getphdr(elf, p, &phdr_mem);
					if (phdr == NULL) {
						LOG("Cannot read ELF program header #%zu of %s for %s v%u: %s\n", p, lib->path,  lib->base->name, lib->version, elf_errmsg(0));
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
						ERR("Unable to allocate memory for %zu shared memory entries\n", shmem_num);
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
					LOG("Cannot read ELF section header of %s for %s v%u: %s\n", lib->path,lib->base->name, lib->version, elf_errmsg(0));
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
						LOG("Non-continous global offset tables in %s for %s v%u: %s\n", lib->path, lib->base->name, lib->version, section_name);
					}
				}
				
			}
		}
		if (elf_end(elf) != 0)
			LOG("Failed closing ELF data of %s for %s v%u: %s\n", lib->path, lib->base->name, lib->version, elf_errmsg(0));
	}
	if (close(fd) != 0)
		LOG("Closing %s for %s v%u failed: %s\n", lib->path, lib->base->name, lib->version, strerror(errno));

	// For RELRO, ensure GOT is writable
	// TODO: Check old permissons (e.g. if PROT_EXEC)
	uintptr_t addr = lib->addr + lib->got & (~(pagesize-1));
	size_t len = lib->addr + lib->got + lib->gotsz - addr;
	if (mprotect((void*)addr, len, PROT_READ | PROT_WRITE) != 0)
		LOG("(Un)protecting %lx (%zu) in %s v%u failed: %s\n", lib->addr + addr, len, lib->base->name, lib->version, strerror(errno));
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
				lib_t * target_old = (lib_t *) (r->data);
				identity_t * target_base = target_old->base;
				lib_t * target_new = target_base->current;
				// Check if update is necessary
				if (target_old == target_new)
					continue;
				// Update
				uintptr_t ptr = (uintptr_t)dlsym(target_new->handle, info.dli_sname);
				if (ptr == 0) {
					LOG("Symbol %s not found in %s (%s v%u)\n", info.dli_sname, target_new->path, target_base->name, target_new->version);
				} else if (ptr != *entry) {
					// Update!
					LOG("Symbol %s from %s update v%u -> v%u in %s (%s v%u): %lx -> %lx\n", info.dli_sname, target_base->name, target_old->version, target_new->version, lib->path, lib->base->name, lib->version, *entry, ptr);
					*entry = ptr;
				}
			} else if (!ignore_lib(info.dli_fname)) {
				LOG("No lib %s found\n", info.dli_fname);
			}
		}
	}
}

static lib_t * load_update(identity_t * base, const char * path) {
	assert(path != NULL);
	lib_t * lib = dlload(path);

	if (lib != NULL) {
		lib->addr = ((struct link_map *)(lib->handle))->l_addr;  // hack
		lib->base = base;
		lib->prev = base->current;
		base->current = lib;
		lib->version = lib->prev->version + 1;
		lib->path = strdup(path);

		// add to hash map
		ENTRY *r;
		hsearch_r((ENTRY) {
			.key = lib->path,
			.data = lib
		}, ENTER, &r, &lib_hash);

		// load GOT
		elfread(lib);

		// relink (= actual update)
		for (size_t i = 0; i < identities; i++)
			for (lib_t * l = identity[i].current; l != NULL; l = l->prev)
				relink_got(l);
	}
	return lib;
}

void *thread_watch(void *arg) {
	(void) arg;
	/* TODO: Endlosschleife mit inotify abwarten, dann bei Änderung lib neu laden aufrufen */
	
	// Lookup symbol in our lib list
	char * libname = "./libhw.so";
	ENTRY *r;
	hsearch_r((ENTRY) { .key =  libname }, FIND, &r, &lib_hash);
	if (r == NULL)
		LOG("%s not found!\n", libname);
	lib_t * lib = (lib_t *) (r->data);
	// Demohack: Testweise je 5 sekunden warten, dann die anderen sprachen der libhw symlinken & neu laden
	const char * alternative[] = {"./libhw-de.so", "./libhw-no.so", "./libhw-es.so" };
	for (size_t i = 0; i < COUNT(alternative); i++) {
		sleep(5);
		load_update(lib->base, alternative[i]);
	}

	return NULL;
}

static void thread_watcher_install() {
	int e = pthread_create(&thread_watcher, NULL, thread_watch, NULL);
	if (e != 0) {
		ERR("Creating thread failed: %s\n", strerror(e));
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
	pagesize = sysconf(_SC_PAGE_SIZE);
	if (pagesize == -1)
		ERR("Unable to get page size: %s\n", strerror(errno));

	// Load main program
	lib_t * main = dlload(NULL);
	if (main == NULL)
		return false;

	// get linklist
	struct link_map * link_map = NULL;
	if (dlinfo(main->handle, RTLD_DI_LINKMAP, &link_map) != 0) {
		ERR("Getting link map failed: %s\n", dlerror());
		return false;
	}

	// Allocat memory for library identities
	for (struct link_map * l = link_map; l != NULL; l = l->l_next)
		if (!ignore_lib(l->l_name))
			identities++;
	if ((identity = calloc(identities, sizeof(identity_t))) == NULL) {
		ERR("Cannot allocate %zu library identities\n", identities);
		return false;
	}
	hcreate_r(identities, &lib_hash);

	// Main program will iterate over link map to recursively load all other libs
	size_t i = 0;
	lib_t * cur;
	for (struct link_map * l = link_map; l != NULL; l = l->l_next) {
		if (l->l_name == NULL || strlen(l->l_name) == 0) {
			identity[i].current = main;
			if ((main->path = malloc(PATH_MAX + 1)) == NULL) {
				ERR("Cannot allocate %d bytes for program path\n", PATH_MAX + 1);
				return false;
			} else if (readlink("/proc/self/exe", main->path, PATH_MAX) < 0) {
				LOG("Cannot resolve program path of %s\n", "/proc/self/exe");
				return false;
			}
		} else if (ignore_lib(l->l_name)) {
			LOG("Skipping %s\n", l->l_name);
			continue;
		} else if ((cur = dlload(l->l_name)) != NULL) {
			identity[i].current = cur;
			cur->path = strndup(l->l_name, PATH_MAX);
		} else {
			ERR("Unable to load %s!", l->l_name);
			continue;
		}

		if ((identity[i].name = strrchr(identity[i].current->path, '/')) == NULL)
			identity[i].name = identity[i].current->path;
		else
			identity[i].name++;
		identity[i].current->addr = l->l_addr;
		identity[i].current->version = 0;
		identity[i].current->base = identity + i;

		// Put in hash map
		ENTRY *r;
		hsearch_r((ENTRY) {
			.key = identity[i].current->path,
			.data = identity[i].current
		}, ENTER, &r, &lib_hash);

		i++;
	}

	// TODO: Install inotify watch

	// TODO: int 
	if ((errno = pthread_atfork(fork_prepare, fork_parent, fork_child)) != 0) {
		ERR("Unable to install fork handler: %s\n", strerror(errno));
		return false;
	}

	// Read (relative) GOT address and size via ELF for each lib
	elf_version(EV_CURRENT);
	for (size_t i = 0; i < identities; i++)
		elfread(identity[i].current);

	// install watcher thread
	thread_watcher_install();

}

