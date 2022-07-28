# If your application is in a file named myapp.cpp or myapp.c
# this is the line you will need to build the binary.
PJBASE=/home/user/Downloads/pjproject-2.12
 
include $(PJBASE)/build.mak
 
CC      = $(PJ_CC)
LDFLAGS = $(PJ_LDFLAGS)
LDLIBS  = $(PJ_LDLIBS)
CFLAGS  = $(PJ_CFLAGS)
CPPFLAGS= ${CFLAGS}

all: simple_pjsip

simple_pjsip: simple_pjsip.o
	$(CC) simple_pjsip.o -o simple_pjsip $(LDFLAGS) $(LDLIBS)

simple_pjsip.o: simple_pjsip.c
	$(CC) -c -g $(CFLAGS) simple_pjsip.c

clean:
	rm -f simple_pjsip *.o *.so *.a
