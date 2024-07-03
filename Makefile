CC = gcc
CFLAGS = -O2 -fPIC -Wextra
LDFLAGS = -ldl -lpthread -lelf

all: live.so live_main_wrapper.so

live.so: live.c
	$(CC) $(CFLAGS) -shared -o $@ $< $(LDFLAGS)

live_main_wrapper.so: live.c
	$(CC) $(CFLAGS) -shared -DUSE_MAIN_WRAPPER=1 -o $@ $< $(LDFLAGS)
