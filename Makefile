CC = gcc
CFLAGS = -O2 -g -fPIC -Wextra -Wpedantic
LDFLAGS = -L. -lhw -Wl,-rpath=.

DEMO = run
LIBS = $(patsubst hello_world.%.c,libhw-%.so,$(wildcard hello_world.*.c))
LIBSYMLINK = libhw.so

all: live.so $(DEMO) $(LIBS)

test: all
	@echo "\e[1mTest run\e[0m"
	@PARENT=$$PPID ; for LIB in $(LIBS) ; do \
		sleep 5 ; \
		kill -0 $$PARENT 2>/dev/null || exit 0 ; \
		echo "\e[2mChanging symlink $(LIBSYMLINK) to $$LIB\e[0m" ; \
		ln -f -s $$LIB $(LIBSYMLINK) ; \
	done &
	LD_PRELOAD=live.so ./$(DEMO)


live.so: live.c
	$(CC) $(CFLAGS) -shared -o $@ $< -ldl -lpthread -lelf 

libhw-%.so: hello_world.%.c
	$(CC) $(CFLAGS) -shared -o $@ $<

$(LIBSYMLINK): libhw-en.so
	ln -f -s $< $@

$(DEMO): run.c libhw.so
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

.PHONY: all test
