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


#define LOG(FMT,...) fprintf(stderr, "\e[33m[live.so] " FMT "\e[0m", __VA_ARGS__)
#define COUNT(x) (sizeof(x)/sizeof(x[0]))
#define MAX_LIBS 100

struct Lib;
typedef struct Lib {
	char path[PATH_MAX+1];
	void * handle;
	ElfW(Addr) addr;
	uintptr_t got;
	size_t gotsz;
	struct Lib * update;
} lib_t;

struct hsearch_data lib_hash;

static size_t libs = 1;
static lib_t lib[MAX_LIBS] = {};

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


static bool dlload(const char * path, lib_t * lib) {
	dlerror();
	lib->handle = dlopen(path, RTLD_LAZY | RTLD_LOCAL);
	if (lib->handle == NULL) {
		LOG("Loading %s (%s) failed: %s\n", lib->path, path, dlerror());
		return false;
	}

	lib->got = 0;
	lib->gotsz = 0;
	lib->update = NULL;
	return true;
}

static void elfread(lib_t * lib) {
	bool success = true;
	int fd = open(lib->path, O_RDONLY);
	if (fd == -1) {
		LOG("Opening %s failed: %s\n", lib->path, strerror(errno));
		return;
	}
	Elf * elf = elf_begin (fd, ELF_C_READ, NULL);
	if (elf == NULL) {
		LOG("Cannot read ELF data of %s: %s\n", lib->path, elf_errmsg(0));
	} else {
		GElf_Ehdr ehdr_mem;
		GElf_Ehdr *ehdr = gelf_getehdr (elf, &ehdr_mem);
		if (ehdr == NULL) {
			LOG("Cannot read ELF object file header of %s: %s\n", lib->path, elf_errmsg(0));
			success = false;
		} else {
			// TODO - falls update:
			// Program header table durchgehen und memory alias für data erstellen
			// GOT auf 0 setzen

			Elf_Scn * scn = NULL;
			while ((scn = elf_nextscn(elf, scn)) != NULL) {
				GElf_Shdr shdr_mem;
				GElf_Shdr * shdr = gelf_getshdr(scn, &shdr_mem);
				if (shdr == NULL) {
					LOG("Cannot read ELF section header of %s: %s\n", lib->path, elf_errmsg(0));
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
						LOG("Non-continous global offset tables in %s: %s\n", lib->path, section_name);
					}
				}
				
			}
		}
		if (elf_end(elf) != 0)
			LOG("Failed closing ELF data of %s: %s\n", lib->path, elf_errmsg(0));
	}
	if (close(fd) != 0)
		LOG("Closing %s failed: %s\n", lib->path, strerror(errno));

	// For RELRO, ensure GOT is writable
	// TODO: Check old permissons (e.g. if PROT_EXEC)
	uintptr_t addr = lib->addr + lib->got & (~(pagesize-1));
	size_t len = lib->addr + lib->got + lib->gotsz - addr;
	if (mprotect((void*)addr, len, PROT_READ | PROT_WRITE) != 0)
		LOG("(Un)protecting %lx (%zu) in %s failed: %s\n", lib->addr + addr, len, lib->path, strerror(errno));
}


static void relink_got(lib_t * lib) {
	// TODO: Bei RELRO: ggf GOT via mprotect schreibbar machen

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
				lib_t * target = (lib_t *) (r->data);
				// Get latest version
				while (target->update != NULL)
					target = target->update;
				// Update
				uintptr_t ptr = (uintptr_t)dlsym(target->handle, info.dli_sname);
				if (ptr == 0) {
					LOG("Symbol %s not found in %s\n", info.dli_sname, target->path);
				} else if (ptr != *entry) {
					// Update!
					LOG("Updating %s (%s) from %lx to %lx \n", info.dli_sname, target->path, *entry, ptr);
					*entry = ptr;
				}
				
			}
		}
	}
}

static lib_t * load_update(const char * new_path, lib_t * old) {
	lib_t * l = lib + libs;
	if (dlload(new_path, l)) {
		// Set address and name
		l->addr = ((struct link_map *)(l->handle))->l_addr;  // hack
		strncpy(l->path, new_path, PATH_MAX);
		// mark update
		old->update = l;

		// load GOT
		elfread(l);

		// add to hash map
		ENTRY *r;
		hsearch_r((ENTRY) {
			.key = l->path,
			.data = l
		}, ENTER, &r, &lib_hash);

		// increment lib counter
		libs++;
		assert(libs < MAX_LIBS);

		// relink (= actual update)
		for (size_t i = 0; i < libs; i++)
			relink_got(lib + i);
			
		return l;
	}
	return NULL;
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
	lib_t * old_lib = (lib_t *) (r->data);
	// Demohack: Testweise je 5 sekunden warten, dann die anderen sprachen der libhw symlinken & neu laden
	const char * alternative[] = {"./libhw-de.so", "./libhw-no.so", "./libhw-es.so" };
	for (size_t i = 0; i < COUNT(alternative); i++) {
		sleep(5);
		lib_t * new_lib = load_update(alternative[i], old_lib);
		if (new_lib != NULL)
			old_lib = new_lib;
	}

	return NULL;
}


static __attribute__((constructor)) bool init() {
	// Load main program
	if (!dlload(NULL, lib + 0))
		return false;

	// get linklist
	struct link_map * link_map = NULL;
	if (dlinfo(lib[0].handle, RTLD_DI_LINKMAP, &link_map) != 0) {
		LOG("Getting link map failed: %s\n", dlerror());
		return false;
	}

	// Main program will iterate over link map to recursively load all other libs
	for (struct link_map * l = link_map; l != NULL; l = l->l_next) {
		if (l->l_name == NULL || strlen(l->l_name) == 0) {
			if (readlink("/proc/self/exe", lib[0].path, PATH_MAX) < 0) {
				LOG("Cannot resolve program path of %s\n", "/proc/self/exe");
				return false;
			}
			lib[0].addr = l->l_addr;
		} else if (ignore_lib(l->l_name)) {
			LOG("Skipping %s\n", l->l_name);
		} else if (dlload(l->l_name, lib + libs)) {
			strncpy(lib[libs].path, l->l_name, PATH_MAX);
			lib[libs].addr = l->l_addr;
			libs++;
			assert(libs < MAX_LIBS);
		}
	}

	// Put in hash map
	hcreate_r(MAX_LIBS, &lib_hash);
	for (size_t l = 0; l < libs; l++) {
		ENTRY *r;
		hsearch_r((ENTRY) {
			.key = lib[l].path,
			.data = lib + l
		}, ENTER, &r, &lib_hash);
	}

	// TODO: Install inotify watch

	pagesize = sysconf(_SC_PAGE_SIZE);
	if (pagesize == -1)
		LOG("Unable to get page size: %s\n", strerror(errno));

	// Read (relative) GOT address and size via ELF for each lib
	elf_version(EV_CURRENT);
	for (size_t l = 0; l < libs; l++)
		elfread(lib + l);

	// install watcher thread
	int e = pthread_create(&thread_watcher, NULL, thread_watch, NULL);
	if (e != 0) {
		LOG("Creating thread failed: %s\n", strerror(e));
		exit(EXIT_FAILURE);
	}
	pthread_detach(thread_watcher);
}

