CC = gcc
CFLAGS = -Wall -O2 -DMODULE -D__KERNEL__ -I/lib/modules/2.4.9-e.3/build/include
OBJS = kernel.o redir.o entry.o log.o

.S.o:
	$(CC) -D__ASSEMBLY__ -traditional -c $< -o $*.o

trushield-linux.o: $(OBJS)
	ld -r -o $@ $(OBJS)

all: trushield-linux.o

clean:
	rm -rf *.o

unload:
	rmmod trushield-linux

load:
	insmod trushield-linux.o
