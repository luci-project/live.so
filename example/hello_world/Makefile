CC = gcc
CFLAGS = -O2 -g -fPIC -Wextra
# Uncomment to enable full relro
#CFLAGS += -Wl,-z,relro,-z,now
LDFLAGS = -L. -lhw -Wl,-rpath=.

LIVESO = ../../live.so
LIVE_LOGLEVEL ?= 2

DEMO = run
LIBS = $(patsubst hello_world.%.c,libhw-%.so,$(wildcard hello_world.*.c))
LIBSYMLINK = libhw.so

all: $(LIVESO) $(DEMO) $(LIBS)

test: all
	@echo "\e[1mTest run\e[0m"
	@PARENT=$$PPID ; for LIB in $(LIBS) ; do \
		sleep 5 ; \
		kill -0 $$PARENT 2>/dev/null || exit 0 ; \
		echo "\e[2mChanging symlink $(LIBSYMLINK) to $$LIB\e[0m" ; \
		ln -f -s $$LIB $(LIBSYMLINK) ; \
	done &
	LIVE_LOGLEVEL=$(LIVE_LOGLEVEL) LD_PRELOAD=$(abspath $(LIVESO)) ./$(DEMO)


$(LIVESO):
	$(MAKE) -C $(dir $(LIVESO)) $(notdir $(LIVESO))

libhw-%.so: hello_world.%.c
	$(CC) $(CFLAGS) -shared -o $@ $<

$(LIBSYMLINK): libhw-en.so
	ln -f -s $< $@

$(DEMO): run.c libhw.so
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

.PHONY: all test
