CC = gcc
CFLAGS = -O2 -fPIC -Wextra -Wpedantic

live.so: live.c
	$(CC) $(CFLAGS) -shared -o $@ $< -ldl -lpthread -lelf
