NS=../../net_skeleton.c
FLAGS = ../../net_skeleton.c -I../..
CFLAGS=-W -Wall -pthread $(CFLAGS_EXTRA)
PROGS = device_side cloud_side

all: $(PROGS)

device_side: Makefile device_side.c $(NS)
	$(CC) device_side.c $(FLAGS) -o $@ $(CFLAGS)

cloud_side: Makefile cloud_side.c $(NS)
	$(CC) cloud_side.c $(FLAGS) -o $@ $(CFLAGS)

device_side.exe: Makefile device_side.c $(NS)
	cl device_side.c $(FLAGS) /MD /Fe$@

clean:
	rm -rf *.gc* *.dSYM *.exe *.obj *.o a.out $(PROGS)
