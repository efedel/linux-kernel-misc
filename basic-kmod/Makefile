LINUX_INCLUDE = /usr/src/linux-2.4/include

CC = gcc
CFLAGS = -Wall -O2 -DMODULE -D__KERNEL__ -I$(LINUX_INCLUDE) \
	-I/lib/modules/2.4.9-e.3/build/include
OBJS = kernel.o redir.o entry.o log.o

.S.o:
	$(CC) -D__ASSEMBLY__ -traditional -c $< -o $*.o
.c.o:
	$(CC) $(CFLAGS) -c $< -o $@

test-kmod.o: $(OBJS)
	ld -r -o $@ $(OBJS)

all: test-kmod.o

clean:
	rm -rf $(OBJS)

unload:
	rmmod test-kmod.o

load:
	insmod test-kmod.o
