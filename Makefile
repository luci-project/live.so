CC = gcc
CFLAGS = -O1 -fPIC
LDFLAGS = -L. -lhw -Wl,-rpath=.

DEMO = run
LIBS = $(patsubst hello_world.%.c,libhw-%.so,$(wildcard hello_world.*.c))

all: live.so $(DEMO) $(LIBS)

test: all
	LD_PRELOAD=live.so ./$(DEMO)

live.so: live.c
	$(CC) $(CFLAGS) -shared -o $@ $< -ldl -lpthread -lelf 

libhw-%.so: hello_world.%.c
	$(CC) $(CFLAGS) -shared -o $@ $<

libhw.so: libhw-en.so
	ln -f -s $< $@

$(DEMO): run.c libhw.so
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

.PHONY: all test
