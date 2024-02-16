STDDEP	 = include/*.h
EXTRADEP = Makefile

LN ?= ln -s
MYCFLAGS  ?= -g3 -ggdb -O0 $(CFLAGS) $(DEFINES)
MYLDFLAGS ?= -Wl,--relax,--gc-sections $(LDFLAGS)



MYOBJECTS = build/syssec.o
MYVERSION = 0.0.1
all: release/demo release/libsyssec.so

release/demo: build/demo.o $(MYOBJECTS) $(STDDEP) $(EXTRADEP)
	$(CROSS_COMPILE)$(CC) build/demo.o $(MYOBJECTS) -o release/demo $(MYCFLAGS) -Wl,-Map,release/main.map $(MYLDFLAGS)

build/demo.o: build/demo.S $(STDDEP) $(EXTRADEP)
	$(CROSS_COMPILE)$(CC) build/demo.S -c -o build/demo.o $(MYCFLAGS)

build/demo.S: source/demo.c build/plattform.syscalls $(STDDEP) $(EXTRADEP)
	$(CROSS_COMPILE)$(CC) source/demo.c -S -o build/demo.S -I. -Iinclude $(MYCFLAGS)

release/libsyssec.so: $(MYOBJECTS) $(STDDEP) $(EXTRADEP)
	$(RM) release/libsyssec.so.0
	$(RM) release/libsyssec.so
	$(CROSS_COMPILE)$(CC) -shared -Wl,-soname,libsyssec.so.0 -o release/libsyssec.so.$(MYVERSION) $(MYOBJECTS) -ldl $(LDFLAGS)
	$(LN) libsyssec.so.$(MYVERSION) release/libsyssec.so.0
	$(LN) libsyssec.so.0 release/libsyssec.so

build/syssec.o: build/syssec.S $(STDDEP) $(EXTRADEP)
	$(CROSS_COMPILE)$(CC) build/syssec.S -c -o build/syssec.o $(MYCFLAGS)

build/syssec.S: source/syssec.c build/plattform.syscalls $(STDDEP) $(EXTRADEP)
	$(CROSS_COMPILE)$(CC) source/syssec.c -S -o build/syssec.S -Iinclude -fPIC $(MYCFLAGS)

build/plattform.syscalls:
	$(CROSS_COMPILE)$(CC) -dM -E  /usr/include/syscall.h -o /dev/stdout | sed 's/\t/\ \ /g' | grep "#define[\ ]*SYS_" | awk '{print $$2}' | while read line; do echo "{.str=\"$${line}\", .nr=$${line}},"; done > ./build/plattform.syscalls

clean:
	$(RM) build/*
	$(RM) release/*

deepclean: clean
