#STDDEP	 = include/*.h
EXTRADEP = Makefile

MYCFLAGS  ?= -g3 -ggdb -O0 $(CFLAGS) $(DEFINES)
MYLDFLAGS ?= -Wl,--relax,--gc-sections $(LDFLAGS)



MYOBJECTS = build/demo.o

all: release/demo

release/demo: $(MYOBJECTS) $(STDDEP) $(EXTRADEP)
	$(CROSS_COMPILE)$(CC) $(MYOBJECTS) -o release/demo $(MYCFLAGS) -Wl,-Map,release/main.map $(MYLDFLAGS)

build/demo.o: build/demo.S $(STDDEP) $(EXTRADEP)
	$(CROSS_COMPILE)$(CC) build/demo.S -c -o build/demo.o $(MYCFLAGS)

build/demo.S: source/demo.c $(STDDEP) $(EXTRADEP)
	$(CROSS_COMPILE)$(CC) -dM -E  /usr/include/syscall.h -o /dev/stdout | sed 's/\t/\ \ /g' | grep "#define[\ ]*SYS_" | awk '{print $$2}' | while read line; do echo "{.str=\"$${line}\", .nr=$${line}},"; done > ./build/plattform.syscalls
	$(CROSS_COMPILE)$(CC) source/demo.c -S -o build/demo.S -I. $(MYCFLAGS)


allold: fakestat.so.0.0.1 test

test: test.o
	gcc -O3 test.o -o test

fakestat.so.0.0.1: fakestat.o
	rm -rf libfakestat.so.0
	rm -rf libfakestat.so
	gcc -shared -Wl,-soname,libfakestat.so.0 -o libfakestat.so.0.0.1 fakestat.o -ldl $(LDFLAGS)
	ln libfakestat.so.0.0.1 libfakestat.so.0
	ln libfakestat.so.0 libfakestat.so

test.o: test.c
	gcc -O3 -c test.c -o test.o

fakestat.o: fakestat.c
	gcc -O3 -fPIC -c fakestat.c -o fakestat.o

clean:
	$(RM) build/*
	$(RM) release/*

deepclean: clean
